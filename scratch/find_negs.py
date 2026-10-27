import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from code.classifier import RequestClassifier
import pandas as pd

reqs = pd.read_csv('dataset/deletion_requests.csv')
negs = [
    "don't delete", "do not delete", "without removing", "without deleting",
    "please do not delete", "not asking", "keep my account", "don't close",
    "do not close", "leave my account", "don't erase", "do not erase"
]
found = []
for _, row in reqs.iterrows():
    cid = row['case_id']
    txt = row['request_text']
    auth, reason = RequestClassifier.classify_intent(txt)
    lower = txt.lower()
    if any(n in lower for n in negs):
        found.append((cid, auth, txt))

print(f"Total found: {len(found)}")
for cid, auth, txt in found:
    print(f"{cid} | Auth={auth} | {txt}")
