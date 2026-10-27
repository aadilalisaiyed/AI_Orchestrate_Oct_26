import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pandas as pd
from code.classifier import RequestClassifier

reqs = pd.read_csv('dataset/deletion_requests.csv')
for _, row in reqs[reqs['case_id'] >= 'case_530'].iterrows():
    auth, reason = RequestClassifier.classify_intent(row['request_text'])
    print(f"{row['case_id']} | Auth={auth} | {row['request_text']}")
