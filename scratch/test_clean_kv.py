import re

def parse_kv_line(line: str):
    # Match both standard key="val" and escaped key=\"val\" or key=val
    kv_pat = re.compile(r'(\w+)=(?:\\*"([^"\\]*)\\*"|(?:"([^"]*)")|(\S+))')
    d = {}
    for m in kv_pat.finditer(line):
        k = m.group(1)
        v = m.group(2) or m.group(3) or m.group(4) or ""
        v_clean = v.strip().strip('"').strip('\\').strip('"').strip()
        d[k] = v_clean
    return d

sample = '2026-06-08T09:51:04Z requestId=tr-0305307 level=WARN function=support_platform message="instance=\\"support-5\\" pod=\\"support-6b03\\" region=\\"eu-central-1\\" resource_id=\\"support_2498\\" event=\\"message_pii_scan\\" matched_value=\\"aarav-singh@proton.me\\" detector=\\"direct_identifier\\""'
res = parse_kv_line(sample)
print("Parsed kv:", res)
