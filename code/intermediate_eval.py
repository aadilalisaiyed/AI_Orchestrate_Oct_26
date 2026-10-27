"""Intermediate validation runner executing core modules over the 32 sample requests."""

import sys
import os
from pathlib import Path
import pandas as pd
from typing import Dict, List, Any

# Ensure local code directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from config import SAMPLE_DELETION_REQUESTS_CSV, SAMPLE_OUTPUT_CSV
from classifier import RequestClassifier
from identity import IdentityResolver
from evidence import EvidenceExtractor
from matcher import EvidenceMatcher
from rules import RuleEngine
from models import DeletionRequest


def run_intermediate_audit():
    print("Initializing components...")
    resolver = IdentityResolver()
    extractor = EvidenceExtractor()
    rule_engine = RuleEngine()

    print("Extracting all evidence files...")
    all_evidence = extractor.extract_all_evidence()
    print(f"Total evidence records extracted across corpus: {len(all_evidence)}")

    samples_df = pd.read_csv(SAMPLE_DELETION_REQUESTS_CSV)
    print(f"Loaded {len(samples_df)} sample deletion requests.\n")

    results = []

    for _, row in samples_df.iterrows():
        req = DeletionRequest(
            case_id=str(row["case_id"]).strip(),
            email=str(row["email"]).strip(),
            requested_at=str(row["requested_at"]).strip(),
            reported_status=str(row["reported_status"]).strip(),
            reported_at=str(row["reported_at"]).strip(),
            audit_at=str(row["audit_at"]).strip(),
            request_text=str(row["request_text"]).strip()
        )

        # 1. Intent classification
        is_authorized, intent_reason = RequestClassifier.classify_intent(req.request_text)

        # 2. Identity resolution
        cluster = resolver.resolve_identity(req.email)

        # 3. Evidence matching and cutoff filtering
        matched_valid = []
        excluded_cutoff = []
        applicable_rules = []
        ambiguities = []

        if cluster:
            matched_valid, excluded_cutoff = EvidenceMatcher.match_evidence_for_user(
                cluster=cluster,
                audit_at=req.audit_at,
                all_records=all_evidence
            )
            applicable_rules = rule_engine.get_applicable_rules(matched_valid)
            findings, verified = rule_engine.evaluate_compliance(matched_valid)
        else:
            ambiguities.append(f"Identity could not be resolved for email: {req.email}")

        if not is_authorized:
            ambiguities.append(f"Intent classified as non-deletion: {intent_reason}")

        results.append({
            "case_id": req.case_id,
            "email": req.email,
            "audit_at": req.audit_at,
            "is_authorized": is_authorized,
            "intent_reason": intent_reason,
            "user_id": cluster.user_id if cluster else "UNRESOLVED",
            "cluster_aliases": {
                "emails": list(cluster.emails) if cluster else [],
                "phones": list(cluster.phones) if cluster else [],
                "names": list(cluster.names) if cluster else [],
            },
            "matched_evidence_count": len(matched_valid),
            "matched_records": [
                {
                    "evidence_id": r.evidence_id,
                    "system_id": r.system_id,
                    "resource_id": r.resource_id,
                    "category": r.data_category,
                    "state": r.observed_state,
                    "origin": r.origin_file
                }
                for r in matched_valid
            ],
            "excluded_by_audit_at_count": len(excluded_cutoff),
            "excluded_records": [
                {
                    "evidence_id": r.evidence_id,
                    "system_id": r.system_id,
                    "resource_id": r.resource_id,
                    "captured_at": r.captured_at,
                    "audit_at": req.audit_at,
                    "origin": r.origin_file
                }
                for r in excluded_cutoff
            ],
            "applicable_rules": [f"{r.rule_id} ({r.data_category} -> {r.required_action})" for r in applicable_rules],
            "ambiguities": ambiguities
        })

    return results


if __name__ == "__main__":
    report = run_intermediate_audit()
    print("=" * 80)
    print("INTERMEDIATE AUDIT SUMMARY (32 SAMPLE CASES)")
    print("=" * 80)
    for r in report:
        print(f"\nCase: {r['case_id']} | Email: {r['email']} | User ID: {r['user_id']} | AuditAt: {r['audit_at']}")
        print(f"  Intent: {'Authorized' if r['is_authorized'] else 'NOT_APPLICABLE'} ({r['intent_reason']})")
        print(f"  Matched Records ({r['matched_evidence_count']}):")
        for m in r['matched_records']:
            print(f"    - [{m['evidence_id']}] {m['system_id']}:{m['resource_id']} ({m['category']}) -> {m['state']} ({m['origin']})")
        if r['excluded_by_audit_at_count'] > 0:
            print(f"  Excluded by audit_at ({r['excluded_by_audit_at_count']}):")
            for ex in r['excluded_records']:
                print(f"    - [{ex['evidence_id']}] {ex['system_id']}:{ex['resource_id']} captured_at={ex['captured_at']} > audit_at={ex['audit_at']}")
        print(f"  Applicable Rules: {', '.join(r['applicable_rules']) if r['applicable_rules'] else 'None'}")
        if r['ambiguities']:
            print(f"  Ambiguities/Flags: {', '.join(r['ambiguities'])}")
