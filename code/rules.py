"""Deletion rule evaluation module applying deletion_rules.csv to evidence observations."""

import pandas as pd
from typing import List, Dict, Optional, Tuple

try:
    from code.config import DELETION_RULES_CSV
    from code.models import RuleDefinition, EvidenceRecord, PolicyFinding, VerifiedResource
except ImportError:
    from config import DELETION_RULES_CSV
    from models import RuleDefinition, EvidenceRecord, PolicyFinding, VerifiedResource


class RuleEngine:
    """Evaluates evidence records against the 15 deletion policy rules."""

    def __init__(self, rules_csv: str = str(DELETION_RULES_CSV)):
        self.rules_df = pd.read_csv(rules_csv)
        self.rules_by_category: Dict[str, RuleDefinition] = {}
        for _, row in self.rules_df.iterrows():
            r = RuleDefinition(
                rule_id=str(row["rule_id"]).strip(),
                data_category=str(row["data_category"]).strip(),
                condition=str(row["condition"]).strip(),
                required_action=str(row["required_action"]).strip()
            )
            self.rules_by_category[r.data_category] = r

    def get_applicable_rules(self, records: List[EvidenceRecord]) -> List[RuleDefinition]:
        """Returns the set of deletion rules applicable to the given evidence records."""
        matched_rules = set()
        for r in records:
            cat = r.data_category
            if cat in self.rules_by_category:
                matched_rules.add(self.rules_by_category[cat].rule_id)
            elif cat == "DATA_FLOW":
                pass  # Resurrection risk, not standard deletion rule
        return [r for r in self.rules_by_category.values() if r.rule_id in matched_rules]

    def evaluate_compliance(
        self, records: List[EvidenceRecord]
    ) -> Tuple[List[PolicyFinding], List[VerifiedResource]]:
        """Evaluates records and partitions them into policy findings vs verified compliant resources."""
        findings: List[PolicyFinding] = []
        verified: List[VerifiedResource] = []

        # Deduplicate records by (system_id, resource_id) to avoid multiple conflicting observations
        seen_resources = set()

        for rec in records:
            key = (rec.system_id, rec.resource_id)
            if key in seen_resources:
                continue
            seen_resources.add(key)

            cat = rec.data_category
            state = rec.observed_state

            # 1. Active data flow resurrection risk
            if cat == "DATA_FLOW":
                if state == "ACTIVE":
                    findings.append(PolicyFinding(
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation="REPORT_ACTIVE_DATA_FLOW",
                        state="ACTIVE",
                        evidence_id=rec.evidence_id,
                        data_category=cat,
                        details=rec.details
                    ))
                elif state == "DISABLED":
                    verified.append(VerifiedResource(
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation="VERIFY_DATA_FLOW_DISABLED",
                        state="DISABLED",
                        evidence_id=rec.evidence_id,
                        data_category=cat,
                        details=rec.details
                    ))
                continue

            # 2. Backup archive restore risk vs blocked
            if cat == "BACKUP_ARCHIVE":
                if state == "ACTIVE":
                    findings.append(PolicyFinding(
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation="REPORT_RESTORE_RISK",
                        state="ACTIVE",
                        evidence_id=rec.evidence_id,
                        data_category=cat,
                        rule_id="rule_14",
                        details=rec.details
                    ))
                elif state == "BLOCKED":
                    verified.append(VerifiedResource(
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation="VERIFY_RESTORE_BLOCKED",
                        state="BLOCKED",
                        evidence_id=rec.evidence_id,
                        data_category=cat,
                        details=rec.details
                    ))
                continue

            # 3. Standard rule categories
            rule = self.rules_by_category.get(cat)
            req_action = rule.required_action if rule else "DELETE"

            if req_action == "DELETE":
                if state == "PRESENT":
                    findings.append(PolicyFinding(
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation="REPORT_REMAINING_RECORD",
                        state="PRESENT",
                        evidence_id=rec.evidence_id,
                        data_category=cat,
                        rule_id=rule.rule_id if rule else None,
                        details=rec.details
                    ))
                elif state == "ABSENT":
                    verified.append(VerifiedResource(
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation="VERIFY_RECORD_ABSENT",
                        state="ABSENT",
                        evidence_id=rec.evidence_id,
                        data_category=cat,
                        details=rec.details
                    ))

            elif req_action == "REDACT":
                if state == "PRESENT":
                    # Direct PII is still exposed
                    findings.append(PolicyFinding(
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation="REPORT_EXPOSED_PII",
                        state="PRESENT",
                        evidence_id=rec.evidence_id,
                        data_category=cat,
                        rule_id=rule.rule_id if rule else None,
                        details=rec.details
                    ))
                elif state == "REDACTED":
                    verified.append(VerifiedResource(
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation="VERIFY_RECORD_REDACTED",
                        state="REDACTED",
                        evidence_id=rec.evidence_id,
                        data_category=cat,
                        details=rec.details
                    ))

            elif req_action == "ANONYMIZE":
                if state == "PRESENT":
                    findings.append(PolicyFinding(
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation="REPORT_EXPOSED_PII",
                        state="PRESENT",
                        evidence_id=rec.evidence_id,
                        data_category=cat,
                        rule_id=rule.rule_id if rule else None,
                        details=rec.details
                    ))
                elif state == "ANONYMIZED":
                    verified.append(VerifiedResource(
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation="VERIFY_RECORD_ANONYMIZED",
                        state="ANONYMIZED",
                        evidence_id=rec.evidence_id,
                        data_category=cat,
                        details=rec.details
                    ))

            elif req_action == "RETAIN":
                if state == "PRESENT":
                    verified.append(VerifiedResource(
                        system_id=rec.system_id,
                        resource_id=rec.resource_id,
                        operation="VERIFY_RECORD_PRESENT",
                        state="PRESENT",
                        evidence_id=rec.evidence_id,
                        data_category=cat,
                        details=rec.details
                    ))

        return findings, verified
