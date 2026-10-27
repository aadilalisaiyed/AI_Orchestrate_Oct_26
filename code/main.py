"""Main pipeline runner for the deletion audit agent.

Executes end-to-end audits for all 518 requests in dataset/deletion_requests.csv,
strictly validates the output schema and constraints, and produces the final root output.csv.
"""

import sys
import os
import json
import csv
from pathlib import Path
from typing import List, Dict, Any, Tuple
import pandas as pd

# Ensure code directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from config import DELETION_REQUESTS_CSV, REPO_ROOT, ROOT_OUTPUT_CSV
from models import DeletionRequest
from planner import RemediationPlanner


VALID_PHASES = {"FINDING", "REMEDIATION", "VERIFICATION"}
VALID_STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}

VALID_OPERATIONS = {
    "REPORT_REMAINING_RECORD",
    "REPORT_EXPOSED_PII",
    "REPORT_ACTIVE_DATA_FLOW",
    "REPORT_RESTORE_RISK",
    "DISABLE_DATA_FLOW",
    "BLOCK_RESTORE",
    "DELETE_RECORD",
    "REDACT_RECORD",
    "ANONYMIZE_RECORD",
    "VERIFY_RECORD_ABSENT",
    "VERIFY_RECORD_PRESENT",
    "VERIFY_RECORD_REDACTED",
    "VERIFY_RECORD_ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED",
    "VERIFY_RESTORE_BLOCKED",
}

VALID_STATES = {
    "PRESENT",
    "ABSENT",
    "REDACTED",
    "ANONYMIZED",
    "ACTIVE",
    "DISABLED",
    "BLOCKED",
}

VALID_SYSTEMS = {
    "account_service",
    "analytics_platform",
    "backup_service",
    "export_service",
    "identity_service",
    "integration_service",
    "search_service",
    "security_service",
    "support_platform",
}

REQUIRED_STEP_KEYS = {
    "step_no",
    "phase",
    "system_id",
    "resource_id",
    "operation",
    "state",
    "evidence_id",
}


def validate_audit_results(
    requests_df: pd.DataFrame, output_rows: List[Dict[str, Any]]
) -> None:
    """Performs strict schema and constraint validation on generated audit outputs."""
    print("Running strict schema and constraint validation...")

    # 1. Row count check
    if len(output_rows) != len(requests_df):
        raise ValueError(
            f"Row count mismatch: expected {len(requests_df)} rows, got {len(output_rows)}"
        )

    # 2. Header and column check
    req_case_ids = list(requests_df["case_id"])
    gen_case_ids = [r["case_id"] for r in output_rows]

    if req_case_ids != gen_case_ids:
        raise ValueError("Generated case_ids do not match request case_ids in order!")

    for idx, row in enumerate(output_rows):
        cid = row["case_id"]
        status = row["deletion_status"]
        steps_json = row["steps_json"]

        # 3. Status check
        if status not in VALID_STATUSES:
            raise ValueError(f"Invalid deletion_status '{status}' in case {cid}")

        # 4. JSON parse check
        try:
            steps = json.loads(steps_json)
        except Exception as e:
            raise ValueError(f"Invalid JSON in case {cid}: {e}")

        if not isinstance(steps, list):
            raise ValueError(f"steps_json must be a JSON array in case {cid}")

        # 5. NOT_APPLICABLE check
        if status == "NOT_APPLICABLE":
            if len(steps) != 0:
                raise ValueError(
                    f"NOT_APPLICABLE case {cid} must have empty steps_json, got {len(steps)} steps"
                )
            continue

        # 6. Step structure and sequential numbering check
        for s_idx, step in enumerate(steps, start=1):
            keys = set(step.keys())
            if keys != REQUIRED_STEP_KEYS:
                raise ValueError(
                    f"Invalid keys in case {cid} step {s_idx}: got {keys}, expected {REQUIRED_STEP_KEYS}"
                )

            if step["step_no"] != s_idx:
                raise ValueError(
                    f"Non-sequential step_no in case {cid}: got {step['step_no']}, expected {s_idx}"
                )

            phase = step["phase"]
            if phase not in VALID_PHASES:
                raise ValueError(f"Invalid phase '{phase}' in case {cid} step {s_idx}")

            sys_id = step["system_id"]
            if sys_id not in VALID_SYSTEMS:
                raise ValueError(f"Invalid system_id '{sys_id}' in case {cid} step {s_idx}")

            op = step["operation"]
            if op not in VALID_OPERATIONS:
                raise ValueError(f"Invalid operation '{op}' in case {cid} step {s_idx}")

            st = step["state"]
            if st not in VALID_STATES:
                raise ValueError(f"Invalid state '{st}' in case {cid} step {s_idx}")

            ev_id = step["evidence_id"]

            # COMPLETE case constraints
            if status == "COMPLETE":
                if phase != "VERIFICATION":
                    raise ValueError(
                        f"COMPLETE case {cid} step {s_idx} has non-VERIFICATION phase '{phase}'"
                    )
                if not ev_id or not isinstance(ev_id, str):
                    raise ValueError(
                        f"COMPLETE case {cid} step {s_idx} must have non-empty evidence_id"
                    )

            # INCOMPLETE case constraints
            elif status == "INCOMPLETE":
                if phase == "FINDING":
                    if not ev_id or not isinstance(ev_id, str):
                        raise ValueError(
                            f"INCOMPLETE case {cid} FINDING step {s_idx} must have non-empty evidence_id"
                        )
                elif phase in ["REMEDIATION", "VERIFICATION"]:
                    if ev_id != "":
                        raise ValueError(
                            f"INCOMPLETE case {cid} {phase} step {s_idx} must have empty evidence_id, got '{ev_id}'"
                        )

    print("All schema and constraint validations PASSED successfully!")


def run_pipeline() -> Path:
    """Executes the complete audit pipeline and writes output.csv to repo root."""
    print("=" * 60)
    print("STARTING DELETION AUDIT PIPELINE")
    print("=" * 60)

    # Ingest requests
    requests_path = DELETION_REQUESTS_CSV
    print(f"Loading deletion requests from {requests_path}...")
    reqs_df = pd.read_csv(requests_path)
    total_cases = len(reqs_df)
    print(f"Loaded {total_cases} requests to process.\n")

    # Initialize deterministic planner
    print("Initializing RemediationPlanner...")
    planner = RemediationPlanner()
    print("Planner initialized with all evidence, activity logs, and rules.\n")

    output_rows: List[Dict[str, Any]] = []
    status_counts = {"COMPLETE": 0, "INCOMPLETE": 0, "NOT_APPLICABLE": 0}
    total_steps_generated = 0

    print("Auditing requests...")
    for idx, row in reqs_df.iterrows():
        req = DeletionRequest(
            case_id=str(row["case_id"]).strip(),
            email=str(row["email"]).strip(),
            requested_at=str(row["requested_at"]).strip(),
            reported_status=str(row["reported_status"]).strip(),
            reported_at=str(row["reported_at"]).strip(),
            audit_at=str(row["audit_at"]).strip(),
            request_text=str(row["request_text"]).strip(),
        )

        status, steps = planner.audit_case(req)
        status_counts[status] = status_counts.get(status, 0) + 1
        total_steps_generated += len(steps)

        # Serialize steps deterministically with exact key order
        serialized_steps = json.dumps(steps, separators=(",", ":"))

        output_rows.append({
            "case_id": req.case_id,
            "deletion_status": status,
            "steps_json": serialized_steps,
        })

        if (idx + 1) % 50 == 0 or (idx + 1) == total_cases:
            print(f"  Processed {idx + 1}/{total_cases} cases...")

    # Run validation
    validate_audit_results(reqs_df, output_rows)

    # Write output.csv to repo root
    output_path = ROOT_OUTPUT_CSV
    print(f"\nWriting final output to {output_path}...")
    
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["case_id", "deletion_status", "steps_json"],
            quoting=csv.QUOTE_MINIMAL
        )
        writer.writeheader()
        writer.writerows(output_rows)

    print(f"Successfully wrote {len(output_rows)} rows to {output_path}.\n")

    print("=" * 60)
    print("PIPELINE EXECUTION SUMMARY")
    print("=" * 60)
    print(f"Total Requests Audited:    {total_cases}")
    print(f"COMPLETE Cases:            {status_counts['COMPLETE']}")
    print(f"INCOMPLETE Cases:          {status_counts['INCOMPLETE']}")
    print(f"NOT_APPLICABLE Cases:      {status_counts['NOT_APPLICABLE']}")
    print(f"Total Audit Steps:         {total_steps_generated}")
    print(f"Output File:               {output_path.resolve()}")
    print("=" * 60)

    return output_path


if __name__ == "__main__":
    run_pipeline()
