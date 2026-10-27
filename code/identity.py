"""Identity resolution module reconstructing user identity across current and historical snapshots."""

import pandas as pd
from typing import Dict, Optional

try:
    from code.config import USER_IDENTITIES_CSV, USER_AUDIT_LOG_CSV
    from code.models import IdentityCluster
except ImportError:
    from config import USER_IDENTITIES_CSV, USER_AUDIT_LOG_CSV
    from models import IdentityCluster


class IdentityResolver:
    """Resolves a user's full identity cluster from current snapshots and audit logs."""

    def __init__(self, identities_csv: str = str(USER_IDENTITIES_CSV), audit_log_csv: str = str(USER_AUDIT_LOG_CSV)):
        self.identities_df = pd.read_csv(identities_csv)
        self.audit_log_df = pd.read_csv(audit_log_csv)
        self._build_indexes()

    def _build_indexes(self):
        """Constructs bidirectional lookup maps for all current and historical identifiers."""
        self.email_to_userid: Dict[str, str] = {}
        self.clusters_by_userid: Dict[str, IdentityCluster] = {}

        # 1. Index current identities
        for _, row in self.identities_df.iterrows():
            uid = str(row["user_id"]).strip()
            name = str(row["name"]).strip() if pd.notna(row["name"]) else ""
            email = str(row["email"]).strip() if pd.notna(row["email"]) else ""
            phone = str(row["phone"]).strip() if pd.notna(row["phone"]) else ""
            ehash = str(row["email_hash"]).strip() if pd.notna(row["email_hash"]) else ""

            cluster = IdentityCluster(user_id=uid)
            if name:
                cluster.names.add(name)
            if email:
                cluster.emails.add(email)
                self.email_to_userid[email.lower()] = uid
            if phone:
                cluster.phones.add(phone)
            if ehash:
                cluster.email_hashes.add(ehash)

            self.clusters_by_userid[uid] = cluster

        # 2. Enrich clusters from user_audit_log
        for _, row in self.audit_log_df.iterrows():
            uid = str(row["user_id"]).strip()
            field_name = str(row["field_name"]).strip()
            old_val = str(row["old_value"]).strip() if pd.notna(row["old_value"]) else ""
            new_val = str(row["new_value"]).strip() if pd.notna(row["new_value"]) else ""

            if uid not in self.clusters_by_userid:
                self.clusters_by_userid[uid] = IdentityCluster(user_id=uid)
            cluster = self.clusters_by_userid[uid]

            if field_name == "email":
                if old_val:
                    cluster.emails.add(old_val)
                    self.email_to_userid[old_val.lower()] = uid
                if new_val:
                    cluster.emails.add(new_val)
                    self.email_to_userid[new_val.lower()] = uid
            elif field_name == "email_hash":
                if old_val:
                    cluster.email_hashes.add(old_val)
                if new_val:
                    cluster.email_hashes.add(new_val)
            elif field_name == "phone":
                if old_val:
                    cluster.phones.add(old_val)
                if new_val:
                    cluster.phones.add(new_val)

    def resolve_identity(self, email: str) -> Optional[IdentityCluster]:
        """Resolves request email to its complete IdentityCluster."""
        norm_email = email.strip().lower()
        uid = self.email_to_userid.get(norm_email)
        if uid and uid in self.clusters_by_userid:
            return self.clusters_by_userid[uid]

        # Fallback: check if the string itself is a user_id
        if norm_email in {k.lower(): k for k in self.clusters_by_userid}:
            actual_uid = {k.lower(): k for k in self.clusters_by_userid}[norm_email]
            return self.clusters_by_userid[actual_uid]

        return None
