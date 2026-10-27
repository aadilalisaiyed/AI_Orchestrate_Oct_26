"""Evidence matching module correlating identity clusters with evidence records subject to audit_at."""

from typing import List, Dict, Tuple, Optional

try:
    from code.models import IdentityCluster, EvidenceRecord
except ImportError:
    from models import IdentityCluster, EvidenceRecord


class EvidenceMatcher:
    """Matches evidence records to a user identity cluster while enforcing temporal cutoff."""

    @staticmethod
    def match_evidence_for_user(
        cluster: IdentityCluster,
        audit_at: str,
        all_records: List[EvidenceRecord]
    ) -> Tuple[List[EvidenceRecord], List[EvidenceRecord]]:
        """Filters evidence records for a given user.
        
        Returns:
            matched_valid: Records matching user identity AND captured_at <= audit_at.
            excluded_by_cutoff: Records matching user identity BUT captured_at > audit_at.
        """
        matched_valid: List[EvidenceRecord] = []
        excluded_by_cutoff: List[EvidenceRecord] = []

        for rec in all_records:
            # Check if record matches user identity
            matches_user = False
            for val in rec.exposed_pii.values():
                if cluster.matches_identifier(str(val)):
                    matches_user = True
                    break

            if not matches_user:
                continue

            # Check temporal cutoff
            if rec.captured_at <= audit_at:
                matched_valid.append(rec)
            else:
                excluded_by_cutoff.append(rec)

        return matched_valid, excluded_by_cutoff

    @staticmethod
    def resolve_best_evidence_id(records: List[EvidenceRecord]) -> Optional[str]:
        """For COMPLETE cases, selects the primary comprehensive snapshot/export bundle.
        
        Prioritizes unified service exports or snapshot bundles so multi-system checks
        consistently cite the proving document.
        """
        if not records:
            return None

        # Count occurrences of each evidence_id
        counts: Dict[str, int] = {}
        bundle_priority = {}
        for r in records:
            ev_id = r.evidence_id
            counts[ev_id] = counts.get(ev_id, 0) + 1
            # Priority weight for snapshot bundles
            orig = r.origin_file.lower()
            if "service_resource_export" in orig:
                bundle_priority[ev_id] = 100
            elif "customer_data_snapshot_bundle" in orig:
                bundle_priority[ev_id] = 90
            elif "customer_accounts_failover_replica" in orig:
                bundle_priority[ev_id] = 80
            elif "customer_account_handover" in orig:
                bundle_priority[ev_id] = 70
            elif "service_events" in orig:
                bundle_priority[ev_id] = 60
            else:
                bundle_priority[ev_id] = bundle_priority.get(ev_id, 10)

        # Sort by (bundle_priority, count) descending
        best_id = sorted(counts.keys(), key=lambda eid: (bundle_priority.get(eid, 0), counts[eid]), reverse=True)[0]
        return best_id
