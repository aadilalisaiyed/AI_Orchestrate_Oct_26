"""Configuration and file paths for the deletion audit system."""

from pathlib import Path

# Base paths
CODE_DIR = Path(__file__).resolve().parent
REPO_ROOT = CODE_DIR.parent
DATASET_DIR = REPO_ROOT / "dataset"
EVIDENCE_DIR = DATASET_DIR / "evidence"

# Input CSV files
DELETION_REQUESTS_CSV = DATASET_DIR / "deletion_requests.csv"
SAMPLE_DELETION_REQUESTS_CSV = DATASET_DIR / "sample_deletion_requests.csv"
SAMPLE_OUTPUT_CSV = DATASET_DIR / "sample_output.csv"
USER_IDENTITIES_CSV = DATASET_DIR / "user_identities.csv"
USER_AUDIT_LOG_CSV = DATASET_DIR / "user_audit_log.csv"
SYSTEM_ACTIVITY_CSV = DATASET_DIR / "system_activity.csv"
DELETION_RULES_CSV = DATASET_DIR / "deletion_rules.csv"
EVIDENCE_FILES_CSV = DATASET_DIR / "evidence_files.csv"

# Target output files
ROOT_OUTPUT_CSV = REPO_ROOT / "output.csv"
EVALUATION_REPORT_MD = CODE_DIR / "evaluation" / "evaluation_report.md"
USAGE_REPORT_MD = CODE_DIR / "evaluation" / "usage_report.md"
