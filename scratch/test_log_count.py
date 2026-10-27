import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from code.evidence import EvidenceExtractor

ext = EvidenceExtractor()
records = ext.extract_all_evidence()
print(f"Total evidence records currently: {len(records)}")

log_records = [r for r in records if r.origin_file.endswith('.log')]
print(f"Current log records: {len(log_records)}")
