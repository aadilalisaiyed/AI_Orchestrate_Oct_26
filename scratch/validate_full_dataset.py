import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pandas as pd
import json

df = pd.read_csv('output.csv')
reqs_df = pd.read_csv('dataset/deletion_requests.csv')
ev_files_df = pd.read_csv('dataset/evidence_files.csv')

# Build manifest captured_at map
ev_meta = {}
for _, row in ev_files_df.iterrows():
    ev_meta[str(row['file_id']).strip()] = str(row['captured_at']).strip()

print("=== RUNNING FULL DATASET INTEGRITY & CONSTRAINT CHECKS ===")

# 1. Row count
assert len(df) == 518, f"Expected 518 rows, got {len(df)}"
print(f"[OK] Total rows: {len(df)}")

# 2. Columns
expected_cols = ['case_id', 'deletion_status', 'steps_json']
assert list(df.columns) == expected_cols, f"Columns mismatch: {list(df.columns)}"
print(f"[OK] Exact columns: {expected_cols}")

# 3. Case ID ordering & completeness
assert list(df['case_id']) == list(reqs_df['case_id']), "Case IDs do not match deletion_requests.csv exactly"
print(f"[OK] Case IDs match deletion_requests.csv in identical order (case_33 to case_550)")

# 4. Status values
valid_statuses = {'COMPLETE', 'INCOMPLETE', 'NOT_APPLICABLE'}
assert set(df['deletion_status']).issubset(valid_statuses), "Invalid status found"
status_counts = df['deletion_status'].value_counts().to_dict()
print(f"[OK] Status counts: {status_counts}")

# 5. Schema and constraint checks per case
req_audit_at = dict(zip(reqs_df['case_id'], reqs_df['audit_at']))
step_count_total = 0
phase_order_map = {'FINDING': 0, 'REMEDIATION': 1, 'VERIFICATION': 2}
expected_step_keys = ['evidence_id', 'operation', 'phase', 'resource_id', 'state', 'step_no', 'system_id']

for idx, row in df.iterrows():
    cid = row['case_id']
    status = row['deletion_status']
    audit_at = req_audit_at[cid]
    
    try:
        steps = json.loads(row['steps_json'])
    except Exception as e:
        raise AssertionError(f"Failed to parse steps_json for {cid}: {e}")
        
    step_count_total += len(steps)
    
    if status == 'NOT_APPLICABLE':
        assert steps == [], f"NOT_APPLICABLE case {cid} has non-empty steps: {steps}"
    else:
        assert len(steps) > 0, f"{status} case {cid} has empty steps"
        
        # Check sequential step numbering starting from 1
        for s_idx, step in enumerate(steps, 1):
            assert list(sorted(step.keys())) == expected_step_keys, f"Step keys mismatch in {cid} step {s_idx}: {list(step.keys())}"
            assert step['step_no'] == s_idx, f"Step numbering error in {cid}: expected {s_idx}, got {step['step_no']}"
            assert step['phase'] in phase_order_map, f"Invalid phase in {cid}: {step['phase']}"
            
            # Phase-specific evidence_id rules
            ev_id = step['evidence_id']
            if step['phase'] == 'FINDING':
                assert ev_id != "", f"FINDING step must have evidence_id in {cid}"
                assert ev_id in ev_meta, f"Unknown evidence_id {ev_id} cited in {cid}"
                assert ev_meta[ev_id] <= audit_at, f"Temporal cutoff violation in {cid}: evidence {ev_id} ({ev_meta[ev_id]}) > audit_at ({audit_at})"
            elif step['phase'] == 'REMEDIATION':
                assert ev_id == "", f"REMEDIATION step must have empty evidence_id in {cid}, got {ev_id}"
            elif step['phase'] == 'VERIFICATION':
                if status == 'INCOMPLETE':
                    assert ev_id == "", f"INCOMPLETE VERIFICATION must have empty evidence_id in {cid}, got {ev_id}"
                elif status == 'COMPLETE':
                    assert ev_id != "", f"COMPLETE VERIFICATION must have non-empty evidence_id in {cid}"
                    assert ev_id in ev_meta, f"Unknown evidence_id {ev_id} cited in {cid}"
                    assert ev_meta[ev_id] <= audit_at, f"Temporal cutoff violation in {cid}: evidence {ev_id} ({ev_meta[ev_id]}) > audit_at ({audit_at})"

        # Check phase ordering (FINDING -> REMEDIATION -> VERIFICATION)
        phases = [phase_order_map[s['phase']] for s in steps]
        assert phases == sorted(phases), f"Phases not sorted in canonical phase order for {cid}"

print(f"[OK] Total audit steps validated: {step_count_total}")
print("[ALL CHECKS PASSED PERFECTLY]")
