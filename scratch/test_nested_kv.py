import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from code.evidence import EvidenceExtractor

ext = EvidenceExtractor()
line = '2026-06-08T09:51:04Z requestId=tr-0305307 level=WARN function=support_platform message="instance=\\"support-5\\" pod=\\"support-6b03\\" region=\\"eu-central-1\\" resource_id=\\"support_2498\\" event=\\"message_pii_scan\\" matched_value=\\"aarav-singh@proton.me\\" detector=\\"direct_identifier\\""'
d = ext._parse_kv_line(line)
print("Outer d:", d)
if "message" in d:
    msg_d = ext._parse_kv_line(d["message"])
    print("Inner msg_d:", msg_d)
