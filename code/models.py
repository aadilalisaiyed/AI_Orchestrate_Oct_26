"""Core data models and type definitions for deletion audit agent."""

from dataclasses import dataclass, field
from typing import Set, Dict, Any, Optional, List


@dataclass
class DeletionRequest:
    case_id: str
    email: str
    requested_at: str
    reported_status: str
    reported_at: str
    audit_at: str
    request_text: str


@dataclass
class IdentityCluster:
    user_id: str
    names: Set[str] = field(default_factory=set)
    emails: Set[str] = field(default_factory=set)
    phones: Set[str] = field(default_factory=set)
    email_hashes: Set[str] = field(default_factory=set)

    def matches_identifier(self, identifier: Optional[str]) -> bool:
        """Check if any identifier matches this cluster (case-insensitive for strings)."""
        if not identifier:
            return False
        norm = identifier.strip().lower()
        
        # Exact email match
        if norm in {e.lower() for e in self.emails}:
            return True
            
        # Exact hash match
        if norm in {h.lower() for h in self.email_hashes}:
            return True
            
        # Exact user_id match
        if norm == self.user_id.lower():
            return True
            
        # Exact full name match
        if norm in {n.lower() for n in self.names}:
            return True

        # Phone matching: only if identifier looks like a phone (contains '+' or >= 7 digits)
        digits = "".join(filter(str.isdigit, identifier))
        if len(digits) >= 7 and ("+" in identifier or "-" in identifier or " " in identifier):
            cluster_phone_digits = {"".join(filter(str.isdigit, p)) for p in self.phones if p}
            if digits in cluster_phone_digits:
                return True
                
        return False


@dataclass
class EvidenceRecord:
    evidence_id: str          # file_id (e.g. evidence_01) or activity_id or audit_id
    system_id: str            # account_service, search_service, etc.
    resource_id: str          # account_005, search_001, etc.
    data_category: str        # USER_PROFILE, SEARCH_INDEX_ENTRY, etc.
    captured_at: str          # ISO-8601 UTC
    observed_state: str       # PRESENT, ABSENT, REDACTED, ANONYMIZED, ACTIVE, BLOCKED
    exposed_pii: Dict[str, Any] = field(default_factory=dict)
    details: str = ""
    origin_file: str = ""


@dataclass
class RuleDefinition:
    rule_id: str
    data_category: str
    condition: str
    required_action: str      # DELETE, REDACT, ANONYMIZE, RETAIN


@dataclass
class PolicyFinding:
    system_id: str
    resource_id: str
    operation: str            # REPORT_REMAINING_RECORD, REPORT_EXPOSED_PII, REPORT_ACTIVE_DATA_FLOW, REPORT_RESTORE_RISK
    state: str                # PRESENT or ACTIVE
    evidence_id: str
    data_category: str
    rule_id: Optional[str] = None
    details: str = ""


@dataclass
class VerifiedResource:
    system_id: str
    resource_id: str
    operation: str            # VERIFY_RECORD_ABSENT, VERIFY_RECORD_PRESENT, etc.
    state: str                # ABSENT, PRESENT, REDACTED, ANONYMIZED, DISABLED, BLOCKED
    evidence_id: str
    data_category: str
    details: str = ""
