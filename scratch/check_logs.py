import glob
from pathlib import Path

logs = glob.glob('dataset/evidence/logs/*.log')
for p in logs:
    with open(p, 'r', encoding='utf-8', errors='ignore') as f:
        lines = [f.readline().strip() for _ in range(5)]
        has_trace = any('trace_id' in l for l in lines if l)
        fname = Path(p).name
        print(f"{fname}: has_trace={has_trace}")
        if not has_trace:
            for l in lines[:2]:
                print(f"   sample: {l}")
