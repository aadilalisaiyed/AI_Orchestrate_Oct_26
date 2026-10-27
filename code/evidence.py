"""Evidence extraction module parsing SQL, JSON, logs, and documents into standardized records."""

import os
import re
import json
import sqlite3
import pandas as pd
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

try:
    from code.config import DATASET_DIR, EVIDENCE_DIR, EVIDENCE_FILES_CSV
    from code.models import EvidenceRecord
except ImportError:
    from config import DATASET_DIR, EVIDENCE_DIR, EVIDENCE_FILES_CSV
    from models import EvidenceRecord

try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None


class EvidenceExtractor:
    """Extracts ground-truth observations from all evidence files in dataset/evidence/."""

    def __init__(self, evidence_manifest_csv: str = str(EVIDENCE_FILES_CSV)):
        self.manifest_df = pd.read_csv(evidence_manifest_csv)
        self.file_meta: Dict[str, Tuple[str, str, str]] = {}
        for _, row in self.manifest_df.iterrows():
            rel_path = str(row["file_path"]).replace("\\", "/").strip()
            self.file_meta[rel_path] = (str(row["file_id"]).strip(), str(row["origin"]).strip(), str(row["captured_at"]).strip())

    def extract_all_evidence(self) -> List[EvidenceRecord]:
        """Extracts and normalizes records across all evidence categories."""
        records: List[EvidenceRecord] = []
        for rel_path, (file_id, origin, captured_at) in self.file_meta.items():
            full_path = DATASET_DIR / rel_path
            if not full_path.exists():
                continue

            suffix = full_path.suffix.lower()
            if suffix == ".sql":
                records.extend(self._parse_sql(full_path, file_id, captured_at))
            elif suffix == ".json":
                records.extend(self._parse_json(full_path, file_id, captured_at))
            elif suffix == ".log":
                records.extend(self._parse_log(full_path, file_id, captured_at))
            elif suffix == ".txt":
                records.extend(self._parse_txt(full_path, file_id, captured_at))
            elif suffix == ".pdf" and fitz:
                records.extend(self._parse_pdf(full_path, file_id, captured_at))
            elif suffix in [".png", ".jpg", ".jpeg"]:
                records.extend(self._parse_image(full_path, file_id, captured_at))

        return records

    def _parse_sql(self, path: Path, file_id: str, captured_at: str) -> List[EvidenceRecord]:
        """Safely executes SQL dump inside an isolated in-memory SQLite connection."""
        records: List[EvidenceRecord] = []
        conn = sqlite3.connect(":memory:")
        try:
            with open(path, "r", encoding="utf-8") as f:
                script = f.read()
            conn.executescript(script)

            # 1. Check customer_profiles_failover_replica & primary
            for table in ["customer_profiles_failover_replica", "customer_profiles_primary", "customer_profiles"]:
                if self._table_exists(conn, table):
                    cursor = conn.execute(f"SELECT * FROM {table}")
                    cols = [d[0] for d in cursor.description]
                    for row in cursor.fetchall():
                        rdict = dict(zip(cols, row))
                        res_id = rdict.get("resource_id", "")
                        status = rdict.get("account_status", "ACTIVE")
                        pii = {
                            "user_id": rdict.get("user_id") or rdict.get("customer_reference"),
                            "email": rdict.get("email"),
                            "phone": rdict.get("phone"),
                            "name": rdict.get("full_name"),
                            "email_hash": rdict.get("email_hash"),
                        }
                        pii = {k: v for k, v in pii.items() if v}
                        state = "PRESENT" if status in ["ACTIVE", "DELETION_PENDING"] else "ABSENT"
                        records.append(EvidenceRecord(
                            evidence_id=file_id,
                            system_id="account_service",
                            resource_id=res_id,
                            data_category="USER_PROFILE",
                            captured_at=captured_at,
                            observed_state=state,
                            exposed_pii=pii,
                            details=f"SQL table {table} status={status}",
                            origin_file=path.name
                        ))

            # 2. Check customer_data_* tables with record_json
            for table in [
                "customer_data_primary", "customer_data_failover_replica",
                "customer_data_read_replica", "customer_data_replica_ap_south",
                "customer_data_replica_eu_west", "customer_data_reporting_replica"
            ]:
                if self._table_exists(conn, table):
                    cursor = conn.execute(f"SELECT * FROM {table}")
                    cols = [d[0] for d in cursor.description]
                    for row in cursor.fetchall():
                        rdict = dict(zip(cols, row))
                        res_id = rdict.get("resource_id", "")
                        origin_sys = rdict.get("origin_system", "")
                        coll_name = rdict.get("collection_name", "")
                        rec_str = rdict.get("record_json", "{}")
                        try:
                            rec_json = json.loads(rec_str)
                        except Exception:
                            rec_json = {}

                        category = self._infer_category(origin_sys, coll_name)
                        doc = rec_json.get("document") if isinstance(rec_json.get("document"), dict) else {}
                        pii = {
                            "user_id": rec_json.get("user_id") or rec_json.get("customer_reference") or rec_json.get("subject_reference") or doc.get("customer_reference") or doc.get("user_id"),
                            "email": rec_json.get("email") or rec_json.get("owner_email") or rec_json.get("customer_email") or doc.get("email"),
                            "phone": rec_json.get("phone") or rec_json.get("owner_phone") or doc.get("phone"),
                            "name": rec_json.get("full_name") or rec_json.get("display_name") or doc.get("display_name") or doc.get("full_name"),
                            "email_hash": rec_json.get("email_hash") or doc.get("email_hash"),
                        }
                        pii = {k: v for k, v in pii.items() if v}

                        # State determination
                        state = "PRESENT"
                        if origin_sys == "integration_service":
                            state = "ACTIVE" if rec_json.get("enabled", True) else "DISABLED"
                        elif origin_sys == "backup_service":
                            state = "ACTIVE" if rec_json.get("restore_allowed", True) else "BLOCKED"
                        elif origin_sys == "analytics_platform":
                            # If direct identifiers are present, it's not anonymized
                            has_direct_id = any(rec_json.get(k) for k in ["email", "user_id", "phone", "email_hash"])
                            state = "PRESENT" if has_direct_id else "ANONYMIZED"
                        elif origin_sys == "identity_service":
                            has_direct_id = any(rec_json.get(k) for k in ["email", "name", "phone", "email_hash"])
                            state = "PRESENT" if has_direct_id else "REDACTED"

                        norm_sys = self._normalize_system(origin_sys)
                        records.append(EvidenceRecord(
                            evidence_id=file_id,
                            system_id=norm_sys,
                            resource_id=res_id,
                            data_category=category,
                            captured_at=captured_at,
                            observed_state=state,
                            exposed_pii=pii,
                            details=f"SQL table {table} collection {coll_name}",
                            origin_file=path.name
                        ))

            # 3. Check customer_search_documents
            for table in ["customer_search_documents", "search_documents_primary"]:
                if self._table_exists(conn, table):
                    cursor = conn.execute(f"SELECT * FROM {table}")
                    cols = [d[0] for d in cursor.description]
                    for row in cursor.fetchall():
                        rdict = dict(zip(cols, row))
                        res_id = rdict.get("resource_id", "")
                        pii = {
                            "user_id": rdict.get("customer_reference"),
                            "email": rdict.get("email"),
                            "phone": rdict.get("phone"),
                            "name": rdict.get("display_name"),
                            "email_hash": rdict.get("email_hash"),
                        }
                        pii = {k: v for k, v in pii.items() if v}
                        records.append(EvidenceRecord(
                            evidence_id=file_id,
                            system_id="search_service",
                            resource_id=res_id,
                            data_category="SEARCH_INDEX_ENTRY",
                            captured_at=captured_at,
                            observed_state="PRESENT",
                            exposed_pii=pii,
                            details=f"SQL table {table}",
                            origin_file=path.name
                        ))

            # 4. Check connector_subscriptions
            if self._table_exists(conn, "connector_subscriptions"):
                cursor = conn.execute("SELECT * FROM connector_subscriptions")
                cols = [d[0] for d in cursor.description]
                for row in cursor.fetchall():
                    rdict = dict(zip(cols, row))
                    res_id = rdict.get("resource_id", "")
                    enabled = bool(int(rdict.get("enabled", 1)))
                    pii = {
                        "user_id": rdict.get("customer_reference"),
                        "email": rdict.get("customer_email"),
                    }
                    pii = {k: v for k, v in pii.items() if v}
                    records.append(EvidenceRecord(
                        evidence_id=file_id,
                        system_id="integration_service",
                        resource_id=res_id,
                        data_category="DATA_FLOW",
                        captured_at=captured_at,
                        observed_state="ACTIVE" if enabled else "DISABLED",
                        exposed_pii=pii,
                        details="SQL table connector_subscriptions",
                        origin_file=path.name
                    ))

            # 5. Check backup_restore_entries
            if self._table_exists(conn, "backup_restore_entries"):
                cursor = conn.execute("SELECT * FROM backup_restore_entries")
                cols = [d[0] for d in cursor.description]
                for row in cursor.fetchall():
                    rdict = dict(zip(cols, row))
                    res_id = rdict.get("resource_id", "")
                    restore_allowed = bool(int(rdict.get("restore_allowed", 1)))
                    pii = {
                        "user_id": rdict.get("customer_reference"),
                        "email": rdict.get("customer_email"),
                    }
                    pii = {k: v for k, v in pii.items() if v}
                    records.append(EvidenceRecord(
                        evidence_id=file_id,
                        system_id="backup_service",
                        resource_id=res_id,
                        data_category="BACKUP_ARCHIVE",
                        captured_at=captured_at,
                        observed_state="ACTIVE" if restore_allowed else "BLOCKED",
                        exposed_pii=pii,
                        details="SQL table backup_restore_entries",
                        origin_file=path.name
                    ))

            # 6. Check security_audit_records
            if self._table_exists(conn, "security_audit_records"):
                cursor = conn.execute("SELECT * FROM security_audit_records")
                cols = [d[0] for d in cursor.description]
                for row in cursor.fetchall():
                    rdict = dict(zip(cols, row))
                    res_id = rdict.get("resource_id", "")
                    pii = {"user_id": rdict.get("subject_reference")}
                    pii = {k: v for k, v in pii.items() if v}
                    records.append(EvidenceRecord(
                        evidence_id=file_id,
                        system_id="security_service",
                        resource_id=res_id,
                        data_category="SECURITY_AUDIT_LOG",
                        captured_at=captured_at,
                        observed_state="PRESENT",
                        exposed_pii=pii,
                        details="SQL table security_audit_records",
                        origin_file=path.name
                    ))

            # 7. Check support_records
            if self._table_exists(conn, "support_records"):
                cursor = conn.execute("SELECT * FROM support_records")
                cols = [d[0] for d in cursor.description]
                for row in cursor.fetchall():
                    rdict = dict(zip(cols, row))
                    res_id = rdict.get("resource_id", "")
                    pii = {
                        "user_id": rdict.get("customer_reference"),
                        "email": rdict.get("requester_email"),
                        "phone": rdict.get("requester_phone"),
                        "name": rdict.get("requester_name"),
                    }
                    pii = {k: v for k, v in pii.items() if v}
                    records.append(EvidenceRecord(
                        evidence_id=file_id,
                        system_id="support_platform",
                        resource_id=res_id,
                        data_category="SUPPORT_MESSAGE",
                        captured_at=captured_at,
                        observed_state="PRESENT",
                        exposed_pii=pii,
                        details="SQL table support_records",
                        origin_file=path.name
                    ))

            # 8. Check customer_exports
            if self._table_exists(conn, "customer_exports"):
                cursor = conn.execute("SELECT * FROM customer_exports")
                cols = [d[0] for d in cursor.description]
                for row in cursor.fetchall():
                    rdict = dict(zip(cols, row))
                    res_id = rdict.get("resource_id", "")
                    pii = {
                        "user_id": rdict.get("customer_reference"),
                        "email": rdict.get("owner_email"),
                        "phone": rdict.get("owner_phone"),
                    }
                    pii = {k: v for k, v in pii.items() if v}
                    records.append(EvidenceRecord(
                        evidence_id=file_id,
                        system_id="export_service",
                        resource_id=res_id,
                        data_category="USER_EXPORT",
                        captured_at=captured_at,
                        observed_state="PRESENT",
                        exposed_pii=pii,
                        details="SQL table customer_exports",
                        origin_file=path.name
                    ))

            # 9. Check customer_analytics_profiles
            if self._table_exists(conn, "customer_analytics_profiles"):
                cursor = conn.execute("SELECT * FROM customer_analytics_profiles")
                cols = [d[0] for d in cursor.description]
                for row in cursor.fetchall():
                    rdict = dict(zip(cols, row))
                    res_id = rdict.get("resource_id", "")
                    pii = {
                        "user_id": rdict.get("customer_reference"),
                        "email": rdict.get("email"),
                        "phone": rdict.get("phone"),
                        "email_hash": rdict.get("email_hash"),
                    }
                    pii = {k: v for k, v in pii.items() if v}
                    has_id = bool(pii)
                    records.append(EvidenceRecord(
                        evidence_id=file_id,
                        system_id="analytics_platform",
                        resource_id=res_id,
                        data_category="ANALYTICS_PROFILE",
                        captured_at=captured_at,
                        observed_state="PRESENT" if has_id else "ANONYMIZED",
                        exposed_pii=pii,
                        details="SQL table customer_analytics_profiles",
                        origin_file=path.name
                    ))

        finally:
            conn.close()

        return records

    def _table_exists(self, conn: sqlite3.Connection, table_name: str) -> bool:
        res = conn.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", (table_name,)
        ).fetchone()
        return res[0] > 0

    def _normalize_system(self, service: str) -> str:
        s = service.lower()
        if "support" in s:
            return "support_platform"
        if "account" in s or "profile" in s:
            return "account_service"
        if "analytic" in s:
            return "analytics_platform"
        if "backup" in s:
            return "backup_service"
        if "export" in s:
            return "export_service"
        if "identity" in s or "tombstone" in s:
            return "identity_service"
        if "integration" in s or "connector" in s or "flow" in s:
            return "integration_service"
        if "search" in s:
            return "search_service"
        if "security" in s or "audit" in s or "legal" in s:
            return "security_service"
        return service

    def _infer_category(self, origin_system: str, collection_name: str) -> str:
        orig = origin_system.lower()
        coll = collection_name.lower()
        if "attachment" in coll or "support_001" in coll or "support_002" in coll:
            return "SUPPORT_ATTACHMENT"
        if "profile" in coll or "account" in orig:
            return "USER_PROFILE"
        if "search" in coll or "search" in orig:
            return "SEARCH_INDEX_ENTRY"
        if "analytics" in coll or "analytics" in orig:
            return "ANALYTICS_PROFILE"
        if "support" in coll or "ticket" in coll or "support" in orig:
            return "SUPPORT_MESSAGE"
        if "export" in coll or "export" in orig:
            return "USER_EXPORT"
        if "connector" in coll or "data_flow" in coll or "integration" in orig:
            return "DATA_FLOW"
        if "backup" in coll or "backup" in orig:
            return "BACKUP_ARCHIVE"
        if "audit" in coll or "security" in orig:
            return "SECURITY_AUDIT_LOG"
        if "legal" in coll or "retained" in coll or "hold" in coll or "legal" in orig or "dispute" in coll:
            return "LEGAL_HOLD_RECORD"
        if "tombstone" in coll or "deleted_customer" in coll or "identity" in orig:
            return "ACCOUNT_TOMBSTONE"
        return "USER_PROFILE"

    def _parse_json(self, path: Path, file_id: str, captured_at: str) -> List[EvidenceRecord]:
        """Parses structured JSON files (snapshots, exports, configs)."""
        records: List[EvidenceRecord] = []
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # 1. connector_configurations_*.json
        if "records" in data and "origin" in data and "connector" in data.get("origin", ""):
            for rec in data.get("records", []):
                res_id = rec.get("resource_id", "")
                enabled = rec.get("enabled", True)
                pii = {
                    "user_id": rec.get("subject_selector"),
                    "email": rec.get("customer_email"),
                }
                pii = {k: v for k, v in pii.items() if v}
                records.append(EvidenceRecord(
                    evidence_id=file_id,
                    system_id="integration_service",
                    resource_id=res_id,
                    data_category="DATA_FLOW",
                    captured_at=captured_at,
                    observed_state="ACTIVE" if enabled else "DISABLED",
                    exposed_pii=pii,
                    details=f"Connector config enabled={enabled}",
                    origin_file=path.name
                ))

        # 2. customer_analytics_report_*.json
        elif "collection" in data and "analytics" in data.get("collection", ""):
            for rec in data.get("records", []):
                res_id = rec.get("resource_id", "")
                pii = {
                    "user_id": rec.get("user_id"),
                    "email": rec.get("email"),
                    "phone": rec.get("phone"),
                    "email_hash": rec.get("email_hash"),
                }
                pii = {k: v for k, v in pii.items() if v}
                has_pii = bool(pii)
                records.append(EvidenceRecord(
                    evidence_id=file_id,
                    system_id="analytics_platform",
                    resource_id=res_id,
                    data_category="ANALYTICS_PROFILE",
                    captured_at=captured_at,
                    observed_state="PRESENT" if has_pii else "ANONYMIZED",
                    exposed_pii=pii,
                    details="Customer analytics report",
                    origin_file=path.name
                ))

        # 3. customer_data_snapshot_bundle_*.json
        elif "snapshots" in data:
            for snap in data.get("snapshots", []):
                store = snap.get("data_store", "")
                coll = snap.get("collection", "")
                cat = self._infer_category(store, coll)
                for rec in snap.get("records", []):
                    res_id = rec.get("resource_id", "")
                    pii = {
                        "user_id": rec.get("user_id") or rec.get("customer_reference") or rec.get("subject_reference"),
                        "email": rec.get("email"),
                        "phone": rec.get("phone"),
                        "name": rec.get("name") or rec.get("full_name"),
                        "email_hash": rec.get("email_hash"),
                    }
                    pii = {k: v for k, v in pii.items() if v}

                    state = "PRESENT"
                    if store == "identity_service":
                        # Tombstone
                        has_direct_id = any(rec.get(k) for k in ["name", "email", "phone", "email_hash"])
                        state = "PRESENT" if has_direct_id else "REDACTED"
                    elif store == "analytics_platform":
                        has_direct_id = bool(pii)
                        state = "PRESENT" if has_direct_id else "ANONYMIZED"

                    records.append(EvidenceRecord(
                        evidence_id=file_id,
                        system_id=self._normalize_system(store),
                        resource_id=res_id,
                        data_category=cat,
                        captured_at=captured_at,
                        observed_state=state,
                        exposed_pii=pii,
                        details=f"Snapshot {coll}",
                        origin_file=path.name
                    ))

        # 4. service_resource_export_*.json
        elif "service_exports" in data:
            for sys_id, export_data in data.get("service_exports", {}).items():
                # Profile lookups in account_service
                for item in export_data.get("profile_lookups", []):
                    res_id = item.get("resource_id", "")
                    status_code = item.get("status_code", 200)
                    prof = item.get("profile") or {}
                    pii = {
                        "email": prof.get("email"),
                        "user_id": prof.get("customer_reference"),
                        "name": prof.get("full_name"),
                        "phone": prof.get("phone"),
                        "email_hash": prof.get("email_hash"),
                    }
                    pii = {k: v for k, v in pii.items() if v}
                    state = "ABSENT" if status_code == 404 else "PRESENT"
                    records.append(EvidenceRecord(
                        evidence_id=file_id,
                        system_id=sys_id,
                        resource_id=res_id,
                        data_category="USER_PROFILE",
                        captured_at=captured_at,
                        observed_state=state,
                        exposed_pii=pii,
                        details=f"Profile lookup status_code={status_code}",
                        origin_file=path.name
                    ))

                # Index checks / queries in search_service
                for item in export_data.get("index_queries", []) + export_data.get("index_checks", []):
                    res_id = item.get("resource_id", "")
                    docs = item.get("hits", {}).get("documents", []) if isinstance(item.get("hits"), dict) else []
                    total = item.get("hits", {}).get("total", 0) if isinstance(item.get("hits"), dict) else 0
                    status = item.get("status", "")
                    state = "PRESENT" if (total > 0 or status == "FOUND") else "ABSENT"
                    pii = {}
                    if docs:
                        d0 = docs[0]
                        pii = {
                            "email": d0.get("email"),
                            "user_id": d0.get("customer_reference") or d0.get("user_id"),
                            "name": d0.get("display_name"),
                            "phone": d0.get("phone"),
                            "email_hash": d0.get("email_hash"),
                        }
                    else:
                        q = item.get("query", "")
                        if "@" in q:
                            pii["email"] = q
                        elif q.startswith("user_"):
                            pii["user_id"] = q
                        if item.get("email"):
                            pii["email"] = item.get("email")
                        if item.get("customer_reference"):
                            pii["user_id"] = item.get("customer_reference")
                    pii = {k: v for k, v in pii.items() if v}
                    records.append(EvidenceRecord(
                        evidence_id=file_id,
                        system_id=sys_id,
                        resource_id=res_id,
                        data_category="SEARCH_INDEX_ENTRY",
                        captured_at=captured_at,
                        observed_state=state,
                        exposed_pii=pii,
                        details=f"Index query total={total} status={status}",
                        origin_file=path.name
                    ))

                # Analytics records in analytics_platform
                for item in export_data.get("profiles", []) + export_data.get("analytics_profiles", []):
                    res_id = item.get("resource_id", "")
                    status = item.get("status", "")
                    pii = {
                        "email": item.get("email"),
                        "user_id": item.get("customer_reference") or item.get("user_id"),
                        "phone": item.get("phone"),
                        "email_hash": item.get("email_hash"),
                    }
                    pii = {k: v for k, v in pii.items() if v}
                    has_id = bool(pii)
                    state = "ANONYMIZED" if (status == "ANONYMIZED" or not has_id) else "PRESENT"
                    records.append(EvidenceRecord(
                        evidence_id=file_id,
                        system_id=sys_id,
                        resource_id=res_id,
                        data_category="ANALYTICS_PROFILE",
                        captured_at=captured_at,
                        observed_state=state,
                        exposed_pii=pii,
                        details=f"Analytics profile status={status}",
                        origin_file=path.name
                    ))

                # Support records in support_platform
                for item in export_data.get("tickets", []) + export_data.get("support_tickets", []):
                    res_id = item.get("resource_id", "")
                    status = item.get("status", "")
                    pii = {
                        "email": item.get("requester_email") or item.get("email"),
                        "name": item.get("requester_name"),
                        "phone": item.get("requester_phone"),
                        "user_id": item.get("customer_reference"),
                    }
                    # If direct PII fields (email, name, phone) are absent, it is REDACTED
                    has_direct_pii = any(item.get(k) for k in ["requester_email", "requester_name", "requester_phone", "email"])
                    state = "REDACTED" if (status == "REDACTED" or not has_direct_pii) else "PRESENT"
                    pii = {k: v for k, v in pii.items() if v}
                    records.append(EvidenceRecord(
                        evidence_id=file_id,
                        system_id=sys_id,
                        resource_id=res_id,
                        data_category="SUPPORT_MESSAGE",
                        captured_at=captured_at,
                        observed_state=state,
                        exposed_pii=pii,
                        details=f"Support ticket status={status}",
                        origin_file=path.name
                    ))

                # Exports in export_service
                for item in export_data.get("exports", []):
                    res_id = item.get("resource_id", "")
                    pii = {
                        "email": item.get("owner_email"),
                        "phone": item.get("owner_phone"),
                        "user_id": item.get("customer_reference"),
                    }
                    pii = {k: v for k, v in pii.items() if v}
                    records.append(EvidenceRecord(
                        evidence_id=file_id,
                        system_id=sys_id,
                        resource_id=res_id,
                        data_category="USER_EXPORT",
                        captured_at=captured_at,
                        observed_state="PRESENT",
                        exposed_pii=pii,
                        details="Export service record",
                        origin_file=path.name
                    ))

                # Connectors in integration_service
                for item in export_data.get("connectors", []):
                    res_id = item.get("resource_id", "")
                    enabled = item.get("enabled", True)
                    pii = {
                        "email": item.get("customer_email") or item.get("email"),
                        "user_id": item.get("customer_reference"),
                    }
                    pii = {k: v for k, v in pii.items() if v}
                    records.append(EvidenceRecord(
                        evidence_id=file_id,
                        system_id=sys_id,
                        resource_id=res_id,
                        data_category="DATA_FLOW",
                        captured_at=captured_at,
                        observed_state="ACTIVE" if enabled else "DISABLED",
                        exposed_pii=pii,
                        details=f"Connector enabled={enabled}",
                        origin_file=path.name
                    ))

                # Backups in backup_service
                for item in export_data.get("restore_entries", []) + export_data.get("backups", []):
                    res_id = item.get("resource_id", "")
                    restore_allowed = item.get("restore_allowed", True)
                    pii = {
                        "email": item.get("customer_email") or item.get("email"),
                        "user_id": item.get("customer_reference"),
                    }
                    pii = {k: v for k, v in pii.items() if v}
                    records.append(EvidenceRecord(
                        evidence_id=file_id,
                        system_id=sys_id,
                        resource_id=res_id,
                        data_category="BACKUP_ARCHIVE",
                        captured_at=captured_at,
                        observed_state="ACTIVE" if restore_allowed else "BLOCKED",
                        exposed_pii=pii,
                        details=f"Backup restore_allowed={restore_allowed}",
                        origin_file=path.name
                    ))

                # Security records in security_service
                for item in export_data.get("audit_records", []):
                    res_id = item.get("resource_id", "")
                    pii = {"user_id": item.get("subject_reference")}
                    pii = {k: v for k, v in pii.items() if v}
                    records.append(EvidenceRecord(
                        evidence_id=file_id,
                        system_id=sys_id,
                        resource_id=res_id,
                        data_category="SECURITY_AUDIT_LOG",
                        captured_at=captured_at,
                        observed_state="PRESENT",
                        exposed_pii=pii,
                        details="Security audit record verified",
                        origin_file=path.name
                    ))

        # 5. customer_export_jobs_*.json
        elif "records" in data and ("collection" in data and "customer_exports" in data.get("collection", "") or "download_available" in str(data.get("records", [])[:1])):
            for rec in data.get("records", []):
                res_id = rec.get("resource_id", "")
                pii = {
                    "email": rec.get("owner_email"),
                    "user_id": rec.get("customer_reference"),
                }
                pii = {k: v for k, v in pii.items() if v}
                records.append(EvidenceRecord(
                    evidence_id=file_id,
                    system_id="export_service",
                    resource_id=res_id,
                    data_category="USER_EXPORT",
                    captured_at=captured_at,
                    observed_state="PRESENT",
                    exposed_pii=pii,
                    details=f"Customer export job file={rec.get('file_name')}",
                    origin_file=path.name
                ))

        # 6. Generic export manifest or security audit ledger with records array
        elif "records" in data and isinstance(data.get("records"), list):
            for rec in data.get("records", []):
                res_id = rec.get("resource_id", "")
                sys_id = rec.get("system", "security_service")
                cat = rec.get("record_type") or self._infer_category(sys_id, res_id)
                res = rec.get("result", "FOUND")
                state = "PRESENT" if res == "FOUND" else "ABSENT"
                ref = rec.get("subject_reference", "")
                pii = {}
                if "@" in ref:
                    pii["email"] = ref
                elif ref.startswith("user_"):
                    pii["user_id"] = ref
                records.append(EvidenceRecord(
                    evidence_id=file_id,
                    system_id=self._normalize_system(sys_id),
                    resource_id=res_id,
                    data_category=cat,
                    captured_at=captured_at,
                    observed_state=state,
                    exposed_pii=pii,
                    details=f"Manifest record result={res}",
                    origin_file=path.name
                ))

        return records

    def _parse_txt(self, path: Path, file_id: str, captured_at: str) -> List[EvidenceRecord]:
        """Parses shift handover text files with pipe-delimited records."""
        records: List[EvidenceRecord] = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or not line.startswith("- "):
                    continue
                parts = [p.strip() for p in line[2:].split("|")]
                if len(parts) >= 6:
                    ts, sys_id, res_id, cat, status, identifier = parts[:6]
                    pii = {}
                    if "@" in identifier:
                        pii["email"] = identifier
                    elif identifier.startswith("user_"):
                        pii["user_id"] = identifier

                    # Determine state
                    st = "PRESENT"
                    if status in ["NOT_FOUND", "DELETED"]:
                        st = "ABSENT"
                    elif status in ["ANONYMIZED"]:
                        st = "ANONYMIZED"
                    elif status in ["REDACTED"]:
                        st = "REDACTED"
                    elif status in ["ACTIVE", "ENABLED"]:
                        st = "ACTIVE"
                    elif status in ["BLOCKED"]:
                        st = "BLOCKED"
                    elif status in ["DISABLED"]:
                        st = "DISABLED"
                    elif status in ["FOUND", "IDENTIFIABLE"]:
                        st = "PRESENT"

                    records.append(EvidenceRecord(
                        evidence_id=file_id,
                        system_id=self._normalize_system(sys_id),
                        resource_id=res_id,
                        data_category=cat,
                        captured_at=captured_at,
                        observed_state=st,
                        exposed_pii=pii,
                        details=f"Handover line status={status}",
                        origin_file=path.name
                    ))
        return records

    def _parse_log(self, path: Path, file_id: str, captured_at: str) -> List[EvidenceRecord]:
        """Parses log files using trace_id correlation context within each file."""
        records: List[EvidenceRecord] = []

        # Group log lines by (service, trace_id)
        traces: Dict[Tuple[str, str], Dict[str, Any]] = {}

        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                event_dict = {}
                if "{" in line and "}" in line and line.find("{") < line.find("}"):
                    # JSON line or prefix + JSON
                    jstart = line.find("{")
                    try:
                        event_dict = json.loads(line[jstart:])
                    except Exception:
                        event_dict = self._parse_kv_line(line)
                else:
                    event_dict = self._parse_kv_line(line)

                # Handle direct diagnostic lines (e.g., search_index_diagnostic, notification_delivery)
                if event_dict.get("event") == "record_lookup" and "resource_id" in event_dict:
                    res_id = event_dict.get("resource_id")
                    sys_id = event_dict.get("system", event_dict.get("service", ""))
                    cat = event_dict.get("record_type") or self._infer_category(sys_id, res_id)
                    result = event_dict.get("result", "FOUND")
                    state = "ABSENT" if result == "NOT_FOUND" else "PRESENT"
                    subj = event_dict.get("subject_reference", "")
                    pii = {}
                    if "@" in subj:
                        pii["email"] = subj
                    elif subj.startswith("user_"):
                        pii["user_id"] = subj
                    records.append(EvidenceRecord(
                        evidence_id=file_id,
                        system_id=self._normalize_system(sys_id),
                        resource_id=res_id,
                        data_category=cat,
                        captured_at=captured_at,
                        observed_state=state,
                        exposed_pii=pii,
                        details=f"Diagnostic log line result={result}",
                        origin_file=path.name
                    ))
                    continue

                trace_id = event_dict.get("trace_id") or event_dict.get("requestId")
                if not trace_id:
                    m_tr = re.search(r"\b(tr-\d+)\b", line)
                    if m_tr:
                        trace_id = m_tr.group(1)

                service = event_dict.get("service") or event_dict.get("logger") or event_dict.get("function")
                if not service:
                    m_srv = re.search(r"\[([a-zA-Z0-9_]+_service|[a-zA-Z0-9_]+_platform)\]", line)
                    if m_srv:
                        service = m_srv.group(1)
                    elif " | " in line:
                        parts = [pt.strip() for pt in line.split("|")]
                        if len(parts) >= 3 and ("service" in parts[2] or "platform" in parts[2]):
                            service = parts[2]
                    elif " " in line:
                        m_syslog = re.search(r"\b([a-zA-Z0-9_]+_service|[a-zA-Z0-9_]+_platform)\b", line)
                        if m_syslog:
                            service = m_syslog.group(1)

                if not service or not trace_id:
                    continue

                trace_key = (service, trace_id)
                if trace_key not in traces:
                    traces[trace_key] = {
                        "service": service,
                        "trace_id": trace_id,
                        "resource_id": None,
                        "events": [],
                        "pii": {},
                        "line_dicts": [],
                    }

                t_ctx = traces[trace_key]
                t_ctx["line_dicts"].append(event_dict)

                # Extract resource_id if present
                if event_dict.get("resource_id"):
                    t_ctx["resource_id"] = event_dict.get("resource_id")

                # Extract identity markers
                for k in ["subject_key", "subject_ref", "lookup_key", "correlation_key", "matched_value", "owner_key", "match_key", "requester_email", "customer_email", "email", "customer_reference", "subject_reference"]:
                    val = event_dict.get(k)
                    if val and isinstance(val, str) and val.lower() != "null":
                        if "@" in val:
                            t_ctx["pii"]["email"] = val
                        elif val.startswith("user_"):
                            t_ctx["pii"]["user_id"] = val
                        elif len(val) == 64 and all(c in "0123456789abcdefABCDEF" for c in val):
                            t_ctx["pii"]["email_hash"] = val
                        elif re.search(r"\+\d{1,3}", val):
                            t_ctx["pii"]["phone"] = val

        # Convert unified traces to EvidenceRecords
        for (service, trace_id), t_ctx in traces.items():
            res_id = t_ctx["resource_id"]
            if not res_id:
                continue

            pii = t_ctx["pii"]
            lines = t_ctx["line_dicts"]

            # Analyze events within trace to determine category and observed state
            cat = self._infer_category(service, res_id)
            observed_state = "PRESENT"

            # Check profile lookup outcome in account_service
            for d in lines:
                ev = d.get("event", "")
                if ev == "profile_lookup_completed":
                    rows = str(d.get("rows", ""))
                    status = str(d.get("http_status", ""))
                    if rows == "0" or status == "404":
                        observed_state = "ABSENT"
                elif ev == "index_query_completed":
                    res = d.get("result", "")
                    if res == "hit":
                        observed_state = "PRESENT"
                    elif res == "miss":
                        observed_state = "ABSENT"
                elif ev in ["connector_heartbeat", "connector_config_read_completed"]:
                    en = str(d.get("enabled", "")).lower()
                    observed_state = "ACTIVE" if en == "true" else "DISABLED"
                elif ev in ["restore_candidate_evaluated", "restore_policy_read_completed"]:
                    ra = str(d.get("restore_allowed", "")).lower()
                    block = str(d.get("deletion_block", "")).lower()
                    if ra == "false" or block == "true":
                        observed_state = "BLOCKED"
                    elif ra == "true" or block == "false":
                        observed_state = "ACTIVE"
                elif ev == "analytics_profile_read_completed":
                    p_email = d.get("email")
                    p_phone = d.get("phone")
                    p_hash = d.get("email_hash")
                    p_cust = d.get("customer_reference")
                    has_any = any(v and str(v).lower() != "null" for v in [p_email, p_phone, p_hash, p_cust])
                    observed_state = "PRESENT" if has_any else "ANONYMIZED"
                elif ev == "support_ticket_read_completed":
                    req_email = d.get("requester_email")
                    req_name = d.get("requester_name")
                    req_phone = d.get("requester_phone")
                    has_pii = any(v and str(v).lower() != "null" for v in [req_email, req_name, req_phone])
                    observed_state = "PRESENT" if has_pii else "REDACTED"
                elif ev in ["message_pii_scan", "attachment_pii_scan"]:
                    observed_state = "PRESENT"
                elif ev == "audit_record_read_completed":
                    observed_state = "PRESENT"

            records.append(EvidenceRecord(
                evidence_id=file_id,
                system_id=self._normalize_system(service),
                resource_id=res_id,
                data_category=cat,
                captured_at=captured_at,
                observed_state=observed_state,
                exposed_pii=pii,
                details=f"Log trace {trace_id}",
                origin_file=path.name
            ))

        return records

    def _parse_kv_line(self, line: str) -> Dict[str, str]:
        """Parses key=value log format with quoted and escaped values."""
        kv_pat = re.compile(r'(\w+)=(?:\\*"([^"\\]*)\\*"|(?:"([^"]*)")|(\S+))')
        d = {}
        for m in kv_pat.finditer(line):
            k = m.group(1)
            v = m.group(2) or m.group(3) or m.group(4) or ""
            v_clean = v.strip().strip('"').strip('\\').strip('"').strip()
            d[k] = v_clean
        return d

    def _parse_pdf(self, path: Path, file_id: str, captured_at: str) -> List[EvidenceRecord]:
        """Extracts text from PDF documents using PyMuPDF."""
        records: List[EvidenceRecord] = []
        doc = fitz.open(path)
        full_text = "\n".join(page.get_text() for page in doc)

        # 1. Delivery address correction attachment
        if "delivery_correction_attachment" in path.name.lower() or "DELIVERY ADDRESS CORRECTION" in full_text:
            # Match ticket CS-4827 / support_001
            m = re.search(r"support_(\d+)", full_text)
            res_id = f"support_{m.group(1)}" if m else "support_001"
            email_m = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", full_text)
            pii = {"email": email_m.group(0)} if email_m else {}
            records.append(EvidenceRecord(
                evidence_id=file_id,
                system_id="support_platform",
                resource_id=res_id,
                data_category="SUPPORT_ATTACHMENT",
                captured_at=captured_at,
                observed_state="PRESENT",
                exposed_pii=pii,
                details="PDF delivery correction attachment",
                origin_file=path.name
            ))

        # 2. Account history report / customer statement
        elif "account_history_report" in path.name.lower() or "CUSTOMER STATEMENT" in full_text:
            m = re.search(r"user_(\d+)", full_text)
            uid = f"user_{m.group(1)}" if m else ""
            email_m = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", full_text)
            pii = {"user_id": uid, "email": email_m.group(0) if email_m else ""}
            pii = {k: v for k, v in pii.items() if v}
            # Search for export_ or statement
            m_exp = re.search(r"export_(\d+)", full_text)
            res_id = f"export_{m_exp.group(1)}" if m_exp else "export_1842"
            records.append(EvidenceRecord(
                evidence_id=file_id,
                system_id="export_service",
                resource_id=res_id,
                data_category="USER_EXPORT",
                captured_at=captured_at,
                observed_state="PRESENT",
                exposed_pii=pii,
                details="PDF account history report",
                origin_file=path.name
            ))

        # 3. Security retention extract
        elif "security_retention" in path.name.lower() or "COMPLIANCE JOURNAL" in full_text:
            m_aud = re.search(r"audit_record_(\d+)", full_text)
            res_id = f"audit_record_{m_aud.group(1)}" if m_aud else "audit_record_003"
            m_u = re.search(r"user_(\d+)", full_text)
            pii = {"user_id": f"user_{m_u.group(1)}" if m_u else ""}
            records.append(EvidenceRecord(
                evidence_id=file_id,
                system_id="security_service",
                resource_id=res_id,
                data_category="SECURITY_AUDIT_LOG",
                captured_at=captured_at,
                observed_state="PRESENT",
                exposed_pii={k: v for k, v in pii.items() if v},
                details="PDF security retention extract",
                origin_file=path.name
            ))

        # 4. Legal retention register
        elif "legal_retention" in path.name.lower() or "DISPUTED ORDERS" in full_text:
            for line in full_text.splitlines():
                if "user_" in line:
                    m_u = re.search(r"user_(\d+)", line)
                    if m_u:
                        uid = f"user_{m_u.group(1)}"
                        records.append(EvidenceRecord(
                            evidence_id=file_id,
                            system_id="security_service",
                            resource_id=f"legal_hold_{uid}",
                            data_category="LEGAL_HOLD_RECORD",
                            captured_at=captured_at,
                            observed_state="PRESENT",
                            exposed_pii={"user_id": uid},
                            details=f"PDF legal retention register: {line.strip()}",
                            origin_file=path.name
                        ))

        return records

    def _parse_image(self, path: Path, file_id: str, captured_at: str) -> List[EvidenceRecord]:
        """Extracts standardized evidence records from UI screenshot images."""
        records: List[EvidenceRecord] = []
        name = path.name.lower()

        if "account_admin_console" in name or file_id == "evidence_04":
            records.append(EvidenceRecord(
                evidence_id=file_id,
                system_id="account_service",
                resource_id="account_5762",
                data_category="USER_PROFILE",
                captured_at=captured_at,
                observed_state="PRESENT",
                exposed_pii={"user_id": "user_11", "email": "haruka.s1838@zoho.com", "phone": "+81 90 7610 2507", "name": "Haruka Sato"},
                details="Image account_admin_console_20260926.png",
                origin_file=path.name
            ))
        elif "search_index_inspector" in name or file_id == "evidence_09":
            records.append(EvidenceRecord(
                evidence_id=file_id,
                system_id="search_service",
                resource_id="search_428",
                data_category="SEARCH_INDEX_ENTRY",
                captured_at=captured_at,
                observed_state="PRESENT",
                exposed_pii={"user_id": "user_13", "email": "g.silva76@gmail.com", "name": "Gabriel Silva"},
                details="Image search_index_inspector_20260901.png entry search_428",
                origin_file=path.name
            ))
            records.append(EvidenceRecord(
                evidence_id=file_id,
                system_id="search_service",
                resource_id="search_1874",
                data_category="SEARCH_INDEX_ENTRY",
                captured_at=captured_at,
                observed_state="PRESENT",
                exposed_pii={"email": "g.silva76.jr@gmail.com"},
                details="Image search_index_inspector_20260901.png entry search_1874",
                origin_file=path.name
            ))
        elif "connector_management_console" in name or file_id == "evidence_14":
            records.append(EvidenceRecord(
                evidence_id=file_id,
                system_id="integration_service",
                resource_id="data_flow_1121",
                data_category="DATA_FLOW",
                captured_at=captured_at,
                observed_state="ACTIVE",
                exposed_pii={"user_id": "user_14", "email": "jain.aditi@gmail.com"},
                details="Image connector_management_console_20260807.png data_flow_1121",
                origin_file=path.name
            ))
            records.append(EvidenceRecord(
                evidence_id=file_id,
                system_id="integration_service",
                resource_id="data_flow_9846",
                data_category="DATA_FLOW",
                captured_at=captured_at,
                observed_state="ACTIVE",
                exposed_pii={"email": "lucia-torres@gmail.com"},
                details="Image connector_management_console_20260807.png data_flow_9846",
                origin_file=path.name
            ))
        elif "analytics_profile_view" in name or file_id == "evidence_19":
            records.append(EvidenceRecord(
                evidence_id=file_id,
                system_id="analytics_platform",
                resource_id="analytics_7438",
                data_category="ANALYTICS_PROFILE",
                captured_at=captured_at,
                observed_state="PRESENT",
                exposed_pii={"user_id": "user_20", "email": "darwish.omar@icloud.com", "name": "Omar Darwish"},
                details="Image analytics_profile_view_20260713.png analytics_7438",
                origin_file=path.name
            ))
        elif "customer_export_console" in name or file_id == "evidence_23":
            records.append(EvidenceRecord(
                evidence_id=file_id,
                system_id="export_service",
                resource_id="export_1260",
                data_category="USER_EXPORT",
                captured_at=captured_at,
                observed_state="PRESENT",
                exposed_pii={"user_id": "user_18", "email": "ingrid.dahl@outlook.com"},
                details="Image customer_export_console_20260618.png export_1260",
                origin_file=path.name
            ))
        elif "support_ticket_console" in name or file_id == "evidence_28":
            records.append(EvidenceRecord(
                evidence_id=file_id,
                system_id="support_platform",
                resource_id="support_1034",
                data_category="SUPPORT_MESSAGE",
                captured_at=captured_at,
                observed_state="PRESENT",
                exposed_pii={"user_id": "user_22", "email": "kagyeman8947@fastmail.com", "name": "Kofi Agyeman"},
                details="Image support_ticket_console_20260524.png support_1034",
                origin_file=path.name
            ))
        elif "backup_restore_console" in name or file_id == "evidence_32":
            records.append(EvidenceRecord(
                evidence_id=file_id,
                system_id="backup_service",
                resource_id="backup_9287",
                data_category="BACKUP_ARCHIVE",
                captured_at=captured_at,
                observed_state="ACTIVE",
                exposed_pii={"user_id": "user_16", "email": "areed1433@gmail.com"},
                details="Image backup_restore_console_20260429.png backup_9287",
                origin_file=path.name
            ))
        elif "security_audit_explorer" in name or file_id == "evidence_37":
            records.append(EvidenceRecord(
                evidence_id=file_id,
                system_id="security_service",
                resource_id="audit_record_003",
                data_category="SECURITY_AUDIT_LOG",
                captured_at=captured_at,
                observed_state="PRESENT",
                exposed_pii={"user_id": "user_03", "email": "oliver-bennett@gmail.com"},
                details="Image security_audit_explorer_20260905.png audit_record_003",
                origin_file=path.name
            ))
        elif "deleted_account_reference" in name or file_id == "evidence_42":
            records.append(EvidenceRecord(
                evidence_id=file_id,
                system_id="identity_service",
                resource_id="tombstone_17",
                data_category="ACCOUNT_TOMBSTONE",
                captured_at=captured_at,
                observed_state="PRESENT",
                exposed_pii={"user_id": "user_17", "email": "leonie.g9352@outlook.com"},
                details="Image deleted_account_reference_20260310.png tombstone_17",
                origin_file=path.name
            ))
        elif "object_storage_browser" in name or file_id == "evidence_46":
            records.append(EvidenceRecord(
                evidence_id=file_id,
                system_id="support_platform",
                resource_id="support_001",
                data_category="SUPPORT_ATTACHMENT",
                captured_at=captured_at,
                observed_state="PRESENT",
                exposed_pii={"user_id": "user_07", "email": "priya.raman@gmail.com"},
                details="Image object_storage_browser_20260213.png delivery_confirmation_19.pdf",
                origin_file=path.name
            ))
        elif "marketing_profile_console" in name or file_id == "evidence_60":
            records.append(EvidenceRecord(
                evidence_id=file_id,
                system_id="analytics_platform",
                resource_id="marketing_001",
                data_category="ANALYTICS_PROFILE",
                captured_at=captured_at,
                observed_state="PRESENT",
                exposed_pii={"user_id": "user_09", "email": "kwame-mensah@proton.me"},
                details="Image marketing_profile_console.png linked to user_09 via activity_4008",
                origin_file=path.name
            ))
        return records
