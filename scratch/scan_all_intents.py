import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pandas as pd

reqs = pd.read_csv('dataset/deletion_requests.csv')
print("Total cases:", len(reqs))

for idx, row in reqs.iterrows():
    txt = row['request_text']
    cid = row['case_id']
    # Check if there are other potential non-deletion requests
    # e.g., question marks, rectification, access, opt-out, not asking, etc.
    lower = txt.lower()
    suspicious = False
    if any(k in lower for k in [
        "not asking", "don't delete", "do not delete", "do not close", "don't close",
        "without removing", "without deleting", "leave the account", "keep the account",
        "misspelled", "marketing lists only", "information request", "resetting the login",
        "invoices for my records", "continue using the service", "access my profile"
    ]):
        suspicious = True
    if suspicious:
        print(f"Row {idx} | {cid}: {txt}")
