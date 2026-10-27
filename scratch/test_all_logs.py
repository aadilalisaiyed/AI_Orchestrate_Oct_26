import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import re
import json
import glob
from code.models import EvidenceRecord

def parse_kv_line(line: str):
    kv_pat = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')
    d = {}
    for m in kv_pat.finditer(line):
        k = m.group(1)
        v = m.group(2) if m.group(2) is not None else m.group(3)
        d[k] = v
    return d

def test_parse_all_logs():
    records = []
    logs = glob.glob('dataset/evidence/logs/*.log')
    for p in logs:
        path = Path(p)
        file_id = "test"
        captured_at = "2026-09-01T00:00:00Z"
        
        traces = {}
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                event_dict = {}
                if "{" in line and "}" in line and line.find("{") < line.find("}"):
                    jstart = line.find("{")
                    try:
                        event_dict = json.loads(line[jstart:])
                    except Exception:
                        event_dict = parse_kv_line(line)
                else:
                    event_dict = parse_kv_line(line)
                
                # Check direct diagnostic line
                if event_dict.get("event") == "record_lookup" and "resource_id" in event_dict:
                    res_id = event_dict.get("resource_id")
                    sys_id = event_dict.get("system", event_dict.get("service", ""))
                    cat = event_dict.get("record_type", "USER_PROFILE")
                    result = event_dict.get("result", "FOUND")
                    state = "ABSENT" if result == "NOT_FOUND" else "PRESENT"
                    subj = event_dict.get("subject_reference", "")
                    pii = {}
                    if "@" in subj: pii["email"] = subj
                    elif subj.startswith("user_"): pii["user_id"] = subj
                    records.append((path.name, res_id, sys_id, cat, state, pii))
                    continue
                
                # Extract trace_id and service from various formats
                trace_id = event_dict.get("trace_id") or event_dict.get("requestId")
                if not trace_id:
                    m_tr = re.search(r"\b(tr-\d+)\b", line)
                    if m_tr:
                        trace_id = m_tr.group(1)
                
                service = event_dict.get("service") or event_dict.get("logger") or event_dict.get("function")
                if not service:
                    m_srv = re.search(r"\[([a-zA-Z0-9_]+_service|[a-zA-Z0-9_]+_platform)\]", line)
                    if m_srv:
                        service = m_srv.group(1)
                    elif " | " in line:
                        parts = [pt.strip() for pt in line.split("|")]
                        if len(parts) >= 3 and ("service" in parts[2] or "platform" in parts[2]):
                            service = parts[2]
                    elif " " in line:
                        m_syslog = re.search(r"\b([a-zA-Z0-9_]+_service|[a-zA-Z0-9_]+_platform)\b", line)
                        if m_syslog:
                            service = m_syslog.group(1)
                
                if not service or not trace_id:
                    continue
                
                trace_key = (service, trace_id)
                if trace_key not in traces:
                    traces[trace_key] = {"service": service, "trace_id": trace_id, "resource_id": None, "pii": {}, "lines": []}
                t_ctx = traces[trace_key]
                t_ctx["lines"].append(event_dict)
                if event_dict.get("resource_id"):
                    t_ctx["resource_id"] = event_dict.get("resource_id")
                
                for k in ["subject_key", "subject_ref", "lookup_key", "correlation_key", "matched_value", "owner_key", "match_key", "requester_email", "customer_email", "email", "customer_reference", "subject_reference"]:
                    val = event_dict.get(k)
                    if val and isinstance(val, str) and val.lower() != "null":
                        if "@" in val: t_ctx["pii"]["email"] = val
                        elif val.startswith("user_"): t_ctx["pii"]["user_id"] = val
        
        for (service, trace_id), t_ctx in traces.items():
            if t_ctx["resource_id"]:
                records.append((path.name, t_ctx["resource_id"], service, "TRACE", "PRESENT", t_ctx["pii"]))
                
    print(f"Extracted total {len(records)} records from logs across all formats!")
    return records

test_parse_all_logs()
