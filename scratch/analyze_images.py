import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pandas as pd

# The 11 images and their observed visual data:
# 1. evidence_04: account_admin_console_20260926.png -> user_11 / haruka.s1838@zoho.com / account_5762
# 2. evidence_09: search_index_inspector_20260901.png -> user_13 / g.silva76@gmail.com / search_428
# 3. evidence_14: connector_management_console_20260807.png -> user_14 / jain.aditi@gmail.com / data_flow_1121
# 4. evidence_19: analytics_profile_view_20260713.png -> user_20 / darwish.omar@icloud.com / analytics_7438
# 5. evidence_23: customer_export_console_20260618.png -> user_18 / ingrid.dahl@outlook.com / export_1260
# 6. evidence_28: support_ticket_console_20260524.png -> user_22 / kagyeman8947@fastmail.com / support_1034
# 7. evidence_32: backup_restore_console_20260429.png -> user_16 / areed1433@gmail.com / backup_9287
# 8. evidence_37: security_audit_explorer_20260905.png -> user_03 / audit_record_003 / (Oliver Bennett)
# 9. evidence_42: deleted_account_reference_20260310.png -> user_17 / leonie.g9352@outlook.com / tombstone_17
# 10. evidence_46: object_storage_browser_20260213.png -> delivery_confirmation_19.pdf (support_001) / user_07 (priya.raman@gmail.com)
# 11. evidence_60: marketing_profile_console.png -> marketing_001 / kwame-mensah@proton.me / user_09

reqs = pd.read_csv('dataset/deletion_requests.csv')

image_targets = {
    'evidence_04': ('haruka.s1838@zoho.com', 'user_11', 'account_service', 'account_5762', 'USER_PROFILE', 'PRESENT'),
    'evidence_09': ('g.silva76@gmail.com', 'user_13', 'search_service', 'search_428', 'SEARCH_INDEX_ENTRY', 'PRESENT'),
    'evidence_14': ('jain.aditi@gmail.com', 'user_14', 'integration_service', 'data_flow_1121', 'DATA_FLOW', 'ACTIVE'),
    'evidence_19': ('darwish.omar@icloud.com', 'user_20', 'analytics_platform', 'analytics_7438', 'ANALYTICS_PROFILE', 'PRESENT'),
    'evidence_23': ('ingrid.dahl@outlook.com', 'user_18', 'export_service', 'export_1260', 'USER_EXPORT', 'PRESENT'),
    'evidence_28': ('kagyeman8947@fastmail.com', 'user_22', 'support_platform', 'support_1034', 'SUPPORT_MESSAGE', 'PRESENT'),
    'evidence_32': ('areed1433@gmail.com', 'user_16', 'backup_service', 'backup_9287', 'BACKUP_ARCHIVE', 'ACTIVE'),
    'evidence_37': ('oliver-bennett@gmail.com', 'user_03', 'security_service', 'audit_record_003', 'SECURITY_AUDIT_LOG', 'PRESENT'),
    'evidence_42': ('leonie.g9352@outlook.com', 'user_17', 'identity_service', 'tombstone_17', 'ACCOUNT_TOMBSTONE', 'PRESENT'),
    'evidence_46': ('priya.raman@gmail.com', 'user_07', 'support_platform', 'support_001', 'SUPPORT_ATTACHMENT', 'PRESENT'),
    'evidence_60': ('kwame-mensah@proton.me', 'user_09', 'analytics_platform', 'marketing_001', 'ANALYTICS_PROFILE', 'PRESENT'),
}

for ev_id, (email, uid, sys_id, res_id, cat, state) in image_targets.items():
    matching_reqs = reqs[reqs['email'] == email]
    print(f"\n{ev_id} target={email} ({uid}): {len(matching_reqs)} matching requests:")
    for _, r in matching_reqs.iterrows():
        print(f"  {r['case_id']} | req={r['requested_at']} | rep={r['reported_at']} | audit={r['audit_at']}")
