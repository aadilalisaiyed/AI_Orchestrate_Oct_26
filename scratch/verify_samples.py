import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pandas as pd
import json

sample_df = pd.read_csv('dataset/sample_output.csv')
sample_cases = set(sample_df['case_id'])

# The sample output has case_01 to case_32
# The 518 cases are case_33 to case_550
# Let's run the planner directly on sample_deletion_requests.csv to verify 100% agreement
from code.planner import RemediationPlanner
from code.models import DeletionRequest

sample_reqs = pd.read_csv('dataset/sample_deletion_requests.csv')
planner = RemediationPlanner()

matched = 0
total = len(sample_df)

for _, s_row in sample_df.iterrows():
    cid = s_row['case_id']
    req_row = sample_reqs[sample_reqs['case_id'] == cid].iloc[0]
    req = DeletionRequest(
        case_id=req_row['case_id'],
        email=req_row['email'],
        requested_at=req_row['requested_at'],
        reported_status=req_row['reported_status'],
        reported_at=req_row['reported_at'],
        audit_at=req_row['audit_at'],
        request_text=req_row['request_text']
    )
    status, steps = planner.audit_case(req)
    
    s_status = s_row['deletion_status']
    s_steps = json.loads(s_row['steps_json'])
    
    if status != s_status:
        print(f"Status mismatch for {cid}: expected {s_status}, got {status}")
        continue
    if steps != s_steps:
        print(f"Steps mismatch for {cid}: expected {len(s_steps)} steps, got {len(steps)} steps")
        continue
        
    matched += 1

print(f"Sample validation: {matched}/{total} cases matched perfectly ({matched/total*100:.1f}%)")
