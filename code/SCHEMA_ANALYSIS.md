# Schema & System Analysis: AI-Powered Deletion Audit Agent
**Challenge:** HackerRank Orchestrate (October 2026) — *Ghost Data Still Exists*  
**Date:** 2026-10-24  
**Status:** Pre-implementation Analysis Complete  

---

## 1. Overview and Core Objective

Northstar Shop needs an automated, verifiable deletion audit system. The primary goal is to determine whether personal data was genuinely deleted, redacted, or anonymized following user deletion requests, or if it still persists as "ghost data" in databases, replicas, support attachments, logs, exports, search indexes, or backup archives.

For every case in `dataset/deletion_requests.csv` (518 cases), the audit agent must:
1. Determine whether the person actually requested deletion (`COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`).
2. Reconstruct user identity across current and historical identifiers.
3. Establish the ground-truth system state at `audit_at` (treating workflow statuses and reported results as unverified claims).
4. Identify policy violations, exposed PII, active synchronization paths, and restore risks.
5. Generate an ordered sequence of findings, remediation steps, and post-remediation verification checks.

---

## 2. File Purpose and Column Definitions

All participant-facing data is located in `dataset/`.

### 2.1 `dataset/deletion_requests.csv` (Primary Evaluation Input)
Contains 518 evaluation requests to be audited. Each row represents a unique customer case.

| Column | Type | Description |
| :--- | :--- | :--- |
| `case_id` | String | Unique identifier for the audit case (e.g., `case_33` through `case_550`). |
| `email` | String | Email address submitted with the request (may be current or historical). |
| `requested_at` | ISO-8601 UTC | Timestamp when the user submitted the request. |
| `reported_status` | Enum (`COMPLETE`, `PARTIALLY_COMPLETE`, `NOT_STARTED`) | Self-reported status claimed by the existing deletion workflow (unverified claim). |
| `reported_at` | ISO-8601 UTC | Timestamp when the existing workflow claimed the reported status. |
| `audit_at` | ISO-8601 UTC | **Ground truth cutoff timestamp**. Evidence created after this timestamp must be ignored. |
| `request_text` | String | Natural language text of the user request (multilingual: English, French, Spanish, Japanese, Korean, Arabic, etc.). |

### 2.2 `dataset/sample_deletion_requests.csv` & `dataset/sample_output.csv`
- `sample_deletion_requests.csv`: 32 sample cases (`case_01` through `case_32`).
- `sample_output.csv`: Correct benchmark answers for the 32 sample cases, providing canonical examples for status decisions, operation selection, phase ordering, and serialization.

### 2.3 `dataset/user_identities.csv`
Contains current identity snapshots for 851 registered users.

| Column | Type | Description |
| :--- | :--- | :--- |
| `user_id` | String | Stable internal identifier (e.g., `user_01`). |
| `name` | String | Full name of the user. |
| `email` | String | Current primary email address. |
| `phone` | String | Current phone number (with country code). |
| `email_hash` | String | SHA-256 hash of the normalized email address. |
| `updated_at` | ISO-8601 UTC | Timestamp of the most recent profile snapshot update. |

### 2.4 `dataset/user_audit_log.csv`
Contains 307 historical identity change events. Critical for resolving users who submitted requests using old contact details or whose older records store historical identifiers.

| Column | Type | Description |
| :--- | :--- | :--- |
| `audit_id` | String | Unique identifier for the identity audit record (e.g., `audit_01`). May be cited as evidence. |
| `user_id` | String | References `user_identities.user_id`. |
| `event_time` | ISO-8601 UTC | Timestamp of the identifier change. |
| `field_name` | Enum (`email`, `email_hash`, `phone`) | The specific identity attribute changed. |
| `old_value` | String | Value prior to the change. |
| `new_value` | String | Value after the change. |

### 2.5 `dataset/system_activity.csv`
Contains 4,012 operational and workflow event logs across all platform services.

| Column | Type | Description |
| :--- | :--- | :--- |
| `activity_id` | String | Unique activity identifier (e.g., `activity_01`). May be cited as evidence. |
| `event_time` | ISO-8601 UTC | Timestamp when the event occurred. |
| `event_type` | Enum | `DELETE_RECORD`, `UPDATE_RECORD`, `SYNC_RECORD`, `INDEX_RECORD`, `SEND_EMAIL`, `REFRESH_CACHE`, `RETAIN_RECORD`, `ANONYMIZE_RECORD`, `REDACT_RECORD`, `CREATE_EXPORT`, `CHECK_DATA_FLOW`, `DISABLE_DATA_FLOW`, `BLOCK_RESTORE`, `CHECK_RESTORE_ACCESS`, `LINK_RESOURCE_IDENTITY`, `CLASSIFY_REQUEST`, `RESTORE_BACKUP`. |
| `source_system` | String | Originating service (e.g., `deletion_worker`, `account_service`, `profile_service`, `support_platform`, `security_service`, `export_service`, etc.). |
| `target_system` | String | Target service or store (e.g., `account_service`, `search_service`, `analytics_platform`, `email_delivery_service`, `cache_service`, `archive_service`, `backup_service`, etc.). |
| `resource_id` | String | Identifier of the affected resource (e.g., `account_1482`, `analytics_7277`, `search_9729`, `audit_record_7206`, `data_flow_9522`, `backup_4978`). |
| `reported_result` | Enum (`SUCCESS`, `FAILED`, `PARTIAL`) | Outcome claimed by the service. |
| `details` | String | Human-readable explanation and context of the event. |

### 2.6 `dataset/deletion_rules.csv`
Defines 15 business and compliance policy rules governing how different data categories must be treated:

| Rule ID | Data Category | Condition | Required Action |
| :--- | :--- | :--- | :--- |
| `rule_01` | `USER_PROFILE` | Always | `DELETE` |
| `rule_02` | `SECONDARY_IDENTIFIER` | Always | `DELETE` |
| `rule_03` | `SEARCH_INDEX_ENTRY` | Always | `DELETE` |
| `rule_04` | `CACHE_ENTRY` | Always | `DELETE` |
| `rule_05` | `SUPPORT_MESSAGE` | Conversation contains shared customer, agent, or order context that must be retained | `REDACT` |
| `rule_06` | `SUPPORT_ATTACHMENT` | Attachment belongs only to the deletion subject | `DELETE` |
| `rule_07` | `ANALYTICS_PROFILE` | Record is still attributable to a user | `ANONYMIZE` |
| `rule_08` | `PRODUCT_TELEMETRY` | Record is still attributable to a user | `ANONYMIZE` |
| `rule_09` | `USER_EXPORT` | Always | `DELETE` |
| `rule_10` | `MARKETING_PROFILE` | Always | `DELETE` |
| `rule_11` | `EMAIL_DELIVERY_LOG` | Log contains a user email address | `REDACT` |
| `rule_12` | `SECURITY_AUDIT_LOG` | Record is within the supplied retention period | `RETAIN` |
| `rule_13` | `LEGAL_HOLD_RECORD` | A supplied legal hold is active | `RETAIN` |
| `rule_14` | `BACKUP_ARCHIVE` | Restore access can be blocked | `RETAIN` |
| `rule_15` | `ACCOUNT_TOMBSTONE` | Account is deleted and only stable internal `user_id` is needed to preserve references to retained records | `REDACT` |

### 2.7 `dataset/evidence_files.csv`
Manifest of 94 physical evidence files available under `dataset/evidence/`.

| Column | Type | Description |
| :--- | :--- | :--- |
| `file_id` | String | Unique identifier (e.g., `evidence_01` to `evidence_94`). |
| `file_path` | String | Relative path under `dataset/` (e.g., `evidence/logs/...`, `evidence/databases/...`). |
| `origin` | String | Service or component that produced the capture (e.g., `central_observability_export`, `records_assurance_snapshot_bundle`, `customer_data_read_replica_capture`). |
| `captured_at` | ISO-8601 UTC | Timestamp of file capture. |

---

## 3. Relationships Between Files

```
 +------------------------+             +-----------------------+
 | deletion_requests.csv  |             |  user_audit_log.csv   |
 |------------------------|             |-----------------------|
 | case_id                |             | audit_id (Evidence)   |
 | email (current/old)    | <---------> | user_id               |
 | requested_at           |             | field_name            |
 | reported_status        |             | old_value / new_value |
 | audit_at (CUTOFF)      |             +-----------+-----------+
 | request_text           |                         |
 +-----------+------------+                         |
             |                                      |
             v (Resolves via email)                 v (Resolves user_id)
 +------------------------+             +-----------------------+
 |  user_identities.csv   |             |  deletion_rules.csv   |
 |------------------------|             |-----------------------|
 | user_id                |             | rule_id               |
 | name, email, phone     |             | data_category         |
 | email_hash             |             | condition             |
 +-----------+------------+             | required_action       |
             |                          +-----------+-----------+
             |                                      |
             +-----------------+--------------------+
                               |
                               v (Matches identifiers & rules)
 +--------------------------------------------------------------+
 |                  Ground Truth Evidence Sources               |
 |--------------------------------------------------------------|
 | 1. evidence_files.csv -> dataset/evidence/ (file_id)         |
 |    - databases/*.sql (Replicas, primary tables, drift)       |
 |    - records/*.json & *.txt (Snapshots, exports, configs)    |
 |    - logs/*.log (Real-time service scan & access traces)     |
 |    - documents/*.pdf (Customer statements, legal registers)  |
 |    - images/*.png (Console UI screenshots)                   |
 | 2. system_activity.csv (activity_id)                         |
 | 3. user_audit_log.csv (audit_id)                             |
 +--------------------------------------------------------------+
                               |
                               v (Outputs verified state at audit_at)
 +--------------------------------------------------------------+
 |                     output.csv (Root)                        |
 |--------------------------------------------------------------|
 | case_id, deletion_status, steps_json                         |
 +--------------------------------------------------------------+
```

### Identity Resolution Flow:
1. Lookup request `email` in `user_identities.csv` (current email).
2. If not found or to find historical aliases, lookup `email` in `user_audit_log.csv` (`old_value` or `new_value`).
3. Recover the canonical `user_id`, current name, current email, current phone, and `email_hash`.
4. Recover all historical names, emails, phones, and email hashes for that `user_id`.
5. Use this complete identity bundle to query evidence and system activity.

---

## 4. Evidence Structure and File Types

Under `dataset/evidence/`, there are 94 files across 5 functional directories:

1. **`databases/` (24 files, `.sql`):**
   - SQLite-compatible SQL transaction dumps.
   - Contains snapshots of `customer_profiles_primary`, `customer_profiles_failover_replica`, `customer_profiles_regional_replicas`, and `customer_data_read_replica`.
   - **Crucial for detecting replication drift:** A primary database might show the profile is deleted (or missing), while a failover or regional replica still contains the active record (e.g. `evidence_54`).
2. **`records/` (28 files `.json`, 1 file `.txt`):**
   - JSON structured data captures including `customer_analytics_reports` (`evidence_56`), `service_resource_export` (`evidence_92`), `connector_configurations`, and customer handover notes (`customer_account_handover_20261001.txt`).
   - Shows resource statuses, exposed PII, anonymization states (e.g. `user_id: null`, `email: null`), active connector data flows, and export archives.
3. **`logs/` (26 files, `.log`):**
   - Structured observability event streams containing line-by-line service traces (`service=search_service`, `service=support_platform`, `service=account_service`, `service=backup_service`, `service=security_service`).
   - Fields: timestamp, log level, pod, trace ID, `resource_id`, `event` (e.g., `index_query_completed`, `message_pii_scan`, `attachment_pii_scan`, `profile_lookup_completed`), `matched_value`, `correlation_key`, and `detector`.
4. **`images/` (11 files, `.png`):**
   - High-resolution (1800x1200, 1800x1100, etc.) administrative console screenshots (e.g., `account_admin_console_20260926.png`, `search_index_inspector_20260901.png`, `support_ticket_console_20260524.png`).
5. **`documents/` (4 files, `.pdf`):**
   - Multi-page operational and compliance documents (`account_history_report_20260718.pdf`, `delivery_correction_attachment.pdf`, `legal_retention_register_20260529.pdf`, `security_retention_extract.pdf`). Text is cleanly extractable via PyMuPDF (`fitz`).

---

## 5. Output Requirements & Step Schema

The final deliverable is written to `output.csv` at the repository root.

### 5.1 CSV Structure
```csv
case_id,deletion_status,steps_json
```
- Exactly 518 data rows + 1 header row.
- Sorted ascending by `case_id` (`case_33` through `case_550`).

### 5.2 Status Values & Rules
- `NOT_APPLICABLE`:
  - Assigned when `request_text` does not authorize account/data deletion (e.g., marketing unsubscribe, mobile number change, export request, copy of invoice).
  - `steps_json` must be strictly `[]`.
- `COMPLETE`:
  - Assigned when all required deletion, redaction, and anonymization actions have occurred prior to `audit_at`, no resurrection flows or restore risks remain, and all required retained records remain intact.
  - `steps_json` contains **only** `VERIFICATION` phase steps.
  - Every verification step in a `COMPLETE` case **must cite a valid `evidence_id`** (`file_id`, `activity_id`, or `audit_id`) proving that compliant state.
- `INCOMPLETE`:
  - Assigned when any ghost data, unredacted tombstone, unanonymized analytics, active data flow, or unblocked backup remains at `audit_at`.
  - `steps_json` contains three distinct phases:
    1. `FINDING`: Every remaining violation/risk, citing valid `evidence_id`.
    2. `REMEDIATION`: Proposed remediation actions (must set `evidence_id: ""`).
    3. `VERIFICATION`: Future verification checks that must pass after remediation (must set `evidence_id: ""`).

### 5.3 Step JSON Object Schema
```json
{
  "step_no": 1,
  "phase": "FINDING",
  "system_id": "account_service",
  "resource_id": "account_005",
  "operation": "REPORT_REMAINING_RECORD",
  "state": "PRESENT",
  "evidence_id": "evidence_54"
}
```

### 5.4 Allowed Operations and Allowed States by Phase
| Phase | Operation | Allowed State | Meaning |
| :--- | :--- | :--- | :--- |
| **`FINDING`** | `REPORT_REMAINING_RECORD` | `PRESENT` | Record that should have been deleted still exists. |
| | `REPORT_EXPOSED_PII` | `PRESENT` | Record may remain, but contains unredacted/unanonymized direct PII. |
| | `REPORT_ACTIVE_DATA_FLOW` | `ACTIVE` | An active process/connector can sync or recreate data. |
| | `REPORT_RESTORE_RISK` | `ACTIVE` | A backup/restore path can bring deleted data back. |
| **`REMEDIATION`** | `DISABLE_DATA_FLOW` | `DISABLED` | Halt the active synchronization flow. |
| | `BLOCK_RESTORE` | `BLOCKED` | Restrict backup restore access for this subject. |
| | `DELETE_RECORD` | `ABSENT` | Remove the record completely. |
| | `REDACT_RECORD` | `REDACTED` | Strip direct identifiers while retaining necessary context. |
| | `ANONYMIZE_RECORD` | `ANONYMIZED` | Irreversibly unlink record from the user identity. |
| **`VERIFICATION`** | `VERIFY_RECORD_ABSENT` | `ABSENT` | Confirm record no longer exists. |
| | `VERIFY_RECORD_PRESENT` | `PRESENT` | Confirm policy-required retained record still exists. |
| | `VERIFY_RECORD_REDACTED` | `REDACTED` | Confirm required identifying fields are removed. |
| | `VERIFY_RECORD_ANONYMIZED` | `ANONYMIZED` | Confirm record is unlinkable to subject. |
| | `VERIFY_DATA_FLOW_DISABLED` | `DISABLED` | Confirm data flow is inactive. |
| | `VERIFY_RESTORE_BLOCKED` | `BLOCKED` | Confirm affected backup cannot restore data. |

### 5.5 Step Ordering Rules (Strict)
1. **Phase Order:** `FINDING` -> `REMEDIATION` -> `VERIFICATION`.
2. **Operation Order:** Exactly the order presented in the table above:
   - Findings: `REPORT_REMAINING_RECORD` -> `REPORT_EXPOSED_PII` -> `REPORT_ACTIVE_DATA_FLOW` -> `REPORT_RESTORE_RISK`.
   - Remediation: `DISABLE_DATA_FLOW` -> `BLOCK_RESTORE` -> `DELETE_RECORD` -> `REDACT_RECORD` -> `ANONYMIZE_RECORD`.
   - Verification: `VERIFY_RECORD_ABSENT` -> `VERIFY_RECORD_PRESENT` -> `VERIFY_RECORD_REDACTED` -> `VERIFY_RECORD_ANONYMIZED` -> `VERIFY_DATA_FLOW_DISABLED` -> `VERIFY_RESTORE_BLOCKED`.
3. **System ID Order:** Within the same operation, ascending alphabetically by `system_id`.
4. **Resource ID Order:** Within the same system ID, ascending alphabetically by `resource_id`.
5. **Step Numbering:** `step_no` must be consecutive integers starting at `1`.

---

## 6. Important Edge Cases & Complex Interactions

1. **Replication Drift vs. Primary Success:**
   - In distributed databases, primary instances may complete deletion, but secondary/failover replicas lag or retain copies (e.g., `account_005` in failover replica). The audit must inspect replica dumps, not just primary tables or success logs.
2. **Account Tombstones vs. Retained Records:**
   - When policy permits retaining records (e.g. `rule_12` security audit logs, `rule_13` legal holds), an `ACCOUNT_TOMBSTONE` (`rule_15`) is maintained in `identity_service`.
   - The tombstone retains `user_id` to prevent broken foreign keys, but direct identifiers (`name`, `email`, `phone`, `email_hash`) must be stripped (`REDACT`). If PII remains in the tombstone, it is a policy violation (`REPORT_EXPOSED_PII`).
3. **Resurrection Hazards (Data Flows & Backups):**
   - Active connectors (`integration_service`) can re-populate deleted records into `search_service` or `analytics_platform`.
   - Backups in `backup_service` can restore deleted accounts during recovery.
   - Remediation ordering is critical: data flows must be disabled and restores blocked **before** records are remediated.
4. **Decoys and Shared Identifiers:**
   - Cases exist where users share names or have similar emails (e.g., sample case_28). The agent must not falsely attribute records belonging to other users.
   - Support conversations with shared customer/order context (`rule_05`) must be redacted, not deleted, to protect third-party order context.
5. **Multilingual Non-Deletion Requests:**
   - Requesters may write in English, Spanish, French, German, Japanese, Korean, or Portuguese. Requests for account updates, marketing opt-outs, or data downloads must be classified as `NOT_APPLICABLE`.
6. **Strict Timestamp Cutoff (`audit_at`):**
   - Events, log lines, or snapshots captured after `audit_at` cannot be used to determine the status at `audit_at`.

---

## 7. Uncertainties Requiring Investigation

1. **Image Interpretation Pipeline:**
   - 11 `.png` evidence files exist in `dataset/evidence/images/`.
   - While `fitz` is available for PDFs, OCR libraries (`pytesseract`, `easyocr`) are not pre-installed in the current Python environment.
   - We must investigate whether evidence in images is also mirrored in logs/records/SQL, or whether lightweight image processing / multimodal API calls should be used.
2. **Evidence ID Priority (File vs. Activity vs. Audit):**
   - In `sample_output.csv`, all cited evidence IDs are `evidence_XX` file IDs from `evidence_files.csv`.
   - We need to confirm whether `activity_id` and `audit_id` are only fallbacks when no file ID covers the finding/verification.
3. **Deterministic Retrieval Architecture:**
   - For 518 cases, performing end-to-end LLM calls across all evidence files would be slow and token-expensive.
   - Building a deterministic evidence indexing and query engine in Python will allow high accuracy, zero hallucination, rapid iteration, and minimal token cost.
