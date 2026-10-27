import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pandas as pd
from code.identity import IdentityResolver
from code.evidence import EvidenceExtractor
from code.matcher import EvidenceMatcher

resolver = IdentityResolver()
extractor = EvidenceExtractor()
all_ev = extractor.extract_all_evidence()
reqs = pd.read_csv('dataset/deletion_requests.csv')

cids = ['case_35', 'case_39', 'case_50', 'case_52', 'case_55', 'case_61', 'case_63']
for cid in cids:
    row = reqs[reqs['case_id'] == cid].iloc[0]
    email = row['email']
    audit_at = row['audit_at']
    cluster = resolver.resolve_identity(email)
    print(f"\n--- {cid} | Email: {email} | Audit_at: {audit_at} ---")
    if cluster:
        print(f"Cluster: user_id={cluster.user_id}, emails={cluster.emails}, names={cluster.names}")
        matched, unmerged = EvidenceMatcher.match_evidence_for_user(cluster, audit_at, all_ev)
        print(f"Matched evidence before cutoff ({len(matched)}):")
        for m in matched:
            print(f"  {m.evidence_id} | {m.system_id} | {m.resource_id} | {m.observed_state} | {m.captured_at}")
        
        # Check evidence captured AFTER cutoff
        matched_all, _ = EvidenceMatcher.match_evidence_for_user(cluster, "9999-99-99", all_ev)
        after_cutoff = [m for m in matched_all if m.captured_at > audit_at]
        print(f"Matched evidence AFTER cutoff ({len(after_cutoff)}):")
        for m in after_cutoff:
            print(f"  {m.evidence_id} | {m.system_id} | {m.resource_id} | {m.observed_state} | {m.captured_at}")
    else:
        print("No cluster resolved!")
