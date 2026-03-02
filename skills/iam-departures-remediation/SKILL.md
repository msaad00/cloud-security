---
name: iam-departures-remediation
description: Auto-remediate IAM users created by departed employees — daily reconciliation with change-driven S3 export and EventBridge-triggered Step Function cleanup
version: 0.1.0
metadata:
  openclaw:
    requires:
      bins:
        - aws
      env:
        - AWS_ACCOUNT_ID
        - IAM_REMEDIATION_BUCKET
    optional_env:
      - SNOWFLAKE_ACCOUNT
      - SNOWFLAKE_USER
      - SNOWFLAKE_PASSWORD
      - DATABRICKS_HOST
      - DATABRICKS_TOKEN
      - CLICKHOUSE_HOST
      - CLICKHOUSE_USER
      - CLICKHOUSE_PASSWORD
      - WORKDAY_API_URL
      - WORKDAY_CLIENT_ID
      - WORKDAY_CLIENT_SECRET
    emoji: "\U0001F6AA"
    homepage: https://github.com/msaad00/cloud-security
    source: https://github.com/msaad00/cloud-security
    license: Apache-2.0
    os:
      - darwin
      - linux
    file_reads: []
    file_writes:
      - "s3://${IAM_REMEDIATION_BUCKET}/departures/*.json"
    network_endpoints:
      - url: "https://*.snowflakecomputing.com"
        purpose: "Query employee termination data from Workday tables replicated into Snowflake"
        auth: true
      - url: "https://*.cloud.databricks.com"
        purpose: "Query employee termination data from Workday tables replicated into Databricks"
        auth: true
      - url: "https://*.clickhouse.cloud"
        purpose: "Query employee termination data from ClickHouse"
        auth: true
      - url: "https://iam.amazonaws.com"
        purpose: "List and disable IAM users in target AWS accounts"
        auth: true
      - url: "https://s3.amazonaws.com"
        purpose: "Export change-detected remediation manifests"
        auth: true
    telemetry: false
    persistence: true
    privilege_escalation: false
    always: false
    autonomous_invocation: restricted
---

# iam-departures-remediation — Automated IAM Cleanup for Departed Employees

Reconciles HR termination data against IAM users daily, exports change-detected manifests to S3, and triggers Step Function remediation pipelines via EventBridge.

- **Multi-source HR ingestion** — Workday direct, Snowflake, Databricks, ClickHouse (wherever your HR data lands)
- **Rehire-safe** — Employees who return are automatically excluded from remediation
- **Already-deleted detection** — Skips IAM users that were manually removed, no false positives
- **Change-driven export** — Only pushes to S3 when the remediation table actually changes (row-level diff)
- **EventBridge + Step Functions** — S3 PutObject triggers a 2-Lambda pipeline: validate → remediate

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Data Sources (Daily Refresh)                  │
│                                                                      │
│  ┌──────────┐  ┌───────────┐  ┌────────────┐  ┌──────────────────┐  │
│  │ Workday  │  │ Snowflake │  │ Databricks │  │ ClickHouse       │  │
│  │  (API)   │  │ (table)   │  │ (table)    │  │ (table)          │  │
│  └────┬─────┘  └─────┬─────┘  └─────┬──────┘  └───────┬──────────┘  │
│       │              │              │                  │              │
│       └──────────────┴──────┬───────┴──────────────────┘              │
│                             ▼                                        │
│              ┌──────────────────────────────┐                        │
│              │  Unified Departures Table     │                        │
│              │  (daily materialized view)    │                        │
│              │                              │                        │
│              │  email | account_id | iam_user│                        │
│              │  created_at | terminated_at  │                        │
│              │  is_rehire | iam_deleted     │                        │
│              └──────────────┬───────────────┘                        │
│                             │                                        │
│                    ┌────────▼────────┐                                │
│                    │  Change Detect  │                                │
│                    │  (row-level     │                                │
│                    │   hash diff)    │                                │
│                    └────────┬────────┘                                │
│                             │ only if changed                        │
│                             ▼                                        │
│              ┌──────────────────────────────┐                        │
│              │  S3 Export                    │                        │
│              │  s3://bucket/departures/     │                        │
│              │    YYYY-MM-DD.json           │                        │
│              └──────────────┬───────────────┘                        │
│                             │ PutObject event                        │
│                             ▼                                        │
│              ┌──────────────────────────────┐                        │
│              │  EventBridge Rule            │                        │
│              │  (ObjectCreated filter)      │                        │
│              └──────────────┬───────────────┘                        │
│                             │                                        │
│                             ▼                                        │
│              ┌──────────────────────────────┐                        │
│              │  Step Function               │                        │
│              │                              │                        │
│              │  ┌────────────────────────┐  │                        │
│              │  │ Lambda 1: Validate     │  │                        │
│              │  │ - Parse manifest       │  │                        │
│              │  │ - Confirm IAM exists   │  │                        │
│              │  │ - Check rehire status  │  │                        │
│              │  │ - Check deletion grace  │  │                        │
│              │  └──────────┬─────────────┘  │                        │
│              │             ▼                │                        │
│              │  ┌────────────────────────┐  │                        │
│              │  │ Lambda 2: Remediate    │  │                        │
│              │  │ - Disable IAM user     │  │                        │
│              │  │ - Revoke access keys   │  │                        │
│              │  │ - Remove from groups   │  │                        │
│              │  │ - Tag with ticket ref  │  │                        │
│              │  │ - Log to audit table   │  │                        │
│              │  └────────────────────────┘  │                        │
│              └──────────────────────────────┘                        │
└──────────────────────────────────────────────────────────────────────┘
```

## Unified Departures Table Schema

The skill builds a materialized table from whichever HR source is available. All sources are normalized to this schema:

| Column | Type | Description |
|--------|------|-------------|
| `email` | STRING | Employee email (primary key for matching) |
| `recipient_account_id` | STRING | AWS account ID where the IAM user was created |
| `iam_username` | STRING | The IAM user name in the target account |
| `iam_created_at` | TIMESTAMP | When the IAM user was provisioned |
| `terminated_at` | TIMESTAMP | Employee termination date from HR system |
| `termination_source` | STRING | Origin system: `workday`, `snowflake`, `databricks`, `clickhouse` |
| `is_rehire` | BOOLEAN | `true` if employee was rehired after termination (skip remediation) |
| `rehire_date` | TIMESTAMP | Date of rehire (NULL if not rehired) |
| `iam_deleted` | BOOLEAN | `true` if IAM user was already manually deleted |
| `iam_deleted_at` | TIMESTAMP | When the IAM user was deleted (NULL if still active) |
| `last_checked_at` | TIMESTAMP | Last time this row was reconciled |
| `remediation_status` | STRING | `pending`, `validated`, `remediated`, `skipped`, `error` |

### Source-Specific Queries

**Workday data in Snowflake:**
```sql
SELECT
    w.email_address         AS email,
    i.account_id            AS recipient_account_id,
    i.iam_username,
    i.created_at            AS iam_created_at,
    w.termination_date      AS terminated_at,
    'snowflake'             AS termination_source,
    CASE WHEN w.rehire_date IS NOT NULL AND w.rehire_date > w.termination_date
         THEN TRUE ELSE FALSE END AS is_rehire,
    w.rehire_date
FROM hr_db.workday.employees w
JOIN security_db.iam.users i ON LOWER(w.email_address) = LOWER(i.email)
WHERE w.termination_date IS NOT NULL
  AND w.termination_date <= CURRENT_DATE()
```

**Workday data in Databricks:**
```sql
SELECT
    w.email_address         AS email,
    i.account_id            AS recipient_account_id,
    i.iam_username,
    i.created_at            AS iam_created_at,
    w.termination_date      AS terminated_at,
    'databricks'            AS termination_source,
    CASE WHEN w.rehire_date IS NOT NULL AND w.rehire_date > w.termination_date
         THEN true ELSE false END AS is_rehire,
    w.rehire_date
FROM hr_catalog.workday.employees w
JOIN security_catalog.iam.users i ON LOWER(w.email_address) = LOWER(i.email)
WHERE w.termination_date IS NOT NULL
  AND w.termination_date <= current_date()
```

**Workday data in ClickHouse:**
```sql
SELECT
    w.email_address         AS email,
    i.account_id            AS recipient_account_id,
    i.iam_username,
    i.created_at            AS iam_created_at,
    w.termination_date      AS terminated_at,
    'clickhouse'            AS termination_source,
    if(w.rehire_date IS NOT NULL AND w.rehire_date > w.termination_date, 1, 0) AS is_rehire,
    w.rehire_date
FROM hr.workday_employees w
JOIN security.iam_users i ON lower(w.email_address) = lower(i.email)
WHERE w.termination_date IS NOT NULL
  AND w.termination_date <= today()
```

## Change Detection

The skill computes a SHA-256 hash of the full result set (sorted, deterministic). Export to S3 only triggers when the hash differs from the previous run.

```
current_hash  = SHA256(sorted rows as JSON)
previous_hash = read from s3://bucket/departures/.last_hash

if current_hash != previous_hash:
    export rows → s3://bucket/departures/YYYY-MM-DD.json
    write current_hash → s3://bucket/departures/.last_hash
else:
    log "No changes detected, skipping export"
```

This prevents unnecessary Step Function executions and avoids re-processing unchanged data.

## S3 Manifest Format

Each export writes a single JSON file:

```json
{
  "export_timestamp": "2026-03-01T00:00:00Z",
  "source": "snowflake",
  "row_count": 42,
  "hash": "a1b2c3d4...",
  "entries": [
    {
      "email": "jane.doe@company.com",
      "recipient_account_id": "123456789012",
      "iam_username": "jane.doe",
      "iam_created_at": "2024-06-15T09:00:00Z",
      "terminated_at": "2026-02-28T00:00:00Z",
      "termination_source": "snowflake",
      "is_rehire": false,
      "rehire_date": null,
      "iam_deleted": false,
      "iam_deleted_at": null,
      "remediation_status": "pending"
    }
  ]
}
```

## EventBridge + Step Function Pipeline

### EventBridge Rule

Triggers on `s3:ObjectCreated:*` for the departures prefix:

```json
{
  "source": ["aws.s3"],
  "detail-type": ["Object Created"],
  "detail": {
    "bucket": { "name": ["${IAM_REMEDIATION_BUCKET}"] },
    "object": { "key": [{ "prefix": "departures/" }] }
  }
}
```

### Lambda 1: Validate

Reads the S3 manifest and performs pre-remediation checks:

1. **Parse manifest** — load JSON, validate schema
2. **Filter rehires** — remove entries where `is_rehire = true`
3. **Filter already-deleted** — remove entries where `iam_deleted = true`
4. **Confirm IAM user exists** — call `iam:GetUser` for each entry, mark missing users as `skipped`
5. **Grace period check** — skip users terminated within the last N days (configurable, default 7) to allow for HR data corrections
6. **Cross-account assume** — use `sts:AssumeRole` into `recipient_account_id` for multi-account validation
7. **Output** — validated manifest (only actionable entries) passed to Lambda 2

### Lambda 2: Remediate

Executes remediation actions on validated entries:

1. **Disable login profile** — `iam:DeleteLoginProfile` (revoke console access)
2. **Deactivate access keys** — `iam:UpdateAccessKey` → Status=Inactive for all keys
3. **Remove from groups** — `iam:RemoveUserFromGroup` for all group memberships
4. **Detach policies** — `iam:DetachUserPolicy` for all attached managed policies, `iam:DeleteUserPolicy` for inline policies
5. **Tag IAM user** — add `remediation-ticket`, `remediated-at`, `terminated-at` tags for audit trail
6. **Write audit record** — log action to DynamoDB or the source data warehouse
7. **Do NOT delete the user** — disable only, preserve for audit (deletion is a separate manual approval)

## Rehire Handling

The skill handles rehires at multiple levels:

| Scenario | Behavior |
|----------|----------|
| Employee terminated, not rehired | Normal remediation flow |
| Employee terminated then rehired (rehire_date > terminated_at) | `is_rehire = true` → skipped at table level |
| Employee terminated, rehired, terminated again | Uses latest termination_date, `is_rehire = false` |
| IAM user already deleted by admin | `iam_deleted = true` → skipped, no action needed |
| IAM user recreated after deletion | New IAM created_at > old deleted_at → treated as new user, not remediated unless new termination |
| Termination reversed within grace period | Grace period (7d default) catches HR corrections before remediation |

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AWS_ACCOUNT_ID` | Yes | Management account ID for cross-account assume |
| `IAM_REMEDIATION_BUCKET` | Yes | S3 bucket for change-detected exports |
| `IAM_GRACE_PERIOD_DAYS` | No | Days after termination before remediation (default: 7) |
| `IAM_CROSS_ACCOUNT_ROLE` | No | Role name to assume in target accounts (default: `iam-remediation-role`) |

### Data Source Configuration (one required)

| Variable | Description |
|----------|-------------|
| `SNOWFLAKE_ACCOUNT` + `SNOWFLAKE_USER` + `SNOWFLAKE_PASSWORD` | Snowflake with Workday tables |
| `DATABRICKS_HOST` + `DATABRICKS_TOKEN` | Databricks with Workday tables |
| `CLICKHOUSE_HOST` + `CLICKHOUSE_USER` + `CLICKHOUSE_PASSWORD` | ClickHouse with Workday tables |
| `WORKDAY_API_URL` + `WORKDAY_CLIENT_ID` + `WORKDAY_CLIENT_SECRET` | Workday direct API |

## Example Workflow

### 1. Daily reconciliation (runs via cron/scheduler)
```
iam_departures_reconcile(source="snowflake")
```

### 2. Check current departures table
```
iam_departures_list(status="pending", limit=50)
```

### 3. Force export (bypass change detection)
```
iam_departures_export(force=true)
```

### 4. Check remediation audit trail
```
iam_departures_audit(email="jane.doe@company.com")
```

## Security Considerations

- **Least privilege** — Cross-account role should only have `iam:GetUser`, `iam:DeleteLoginProfile`, `iam:UpdateAccessKey`, `iam:ListAccessKeys`, `iam:RemoveUserFromGroup`, `iam:ListGroupsForUser`, `iam:DetachUserPolicy`, `iam:ListAttachedUserPolicies`, `iam:DeleteUserPolicy`, `iam:ListUserPolicies`, `iam:TagUser`
- **No user deletion** — Users are disabled, not deleted. Deletion requires separate manual approval.
- **Grace period** — Configurable delay prevents acting on HR data corrections
- **Audit trail** — Every action is logged with timestamp, actor, and ticket reference
- **Change detection** — Prevents re-processing unchanged data and duplicate remediations
- **Rehire safety** — Multiple layers of rehire detection prevent disabling returning employees

## Source & Verification

- **Source code**: https://github.com/msaad00/cloud-security (Apache-2.0)
- **No telemetry**: `telemetry: false` — zero tracking
- **Self-contained**: All logic runs in your AWS account, no external dependencies beyond HR data source
