# cloud-security

Production-ready cloud security automations — deployable Lambda code, CloudFormation infra, multi-cloud workers, and compliance-mapped skills for AI agents.

## Architecture

```
                         EXTERNAL HR DATA SOURCES
 ┌──────────────────────────────────────────────────────────────────────┐
 │                                                                      │
 │  ┌───────────┐  ┌────────────┐  ┌────────────┐  ┌──────────────┐   │
 │  │  Workday  │  │ Snowflake  │  │ Databricks │  │  ClickHouse  │   │
 │  │  (API)    │  │ (SQL/S.I.) │  │ (Unity)    │  │  (SQL)       │   │
 │  └─────┬─────┘  └─────┬──────┘  └─────┬──────┘  └──────┬───────┘   │
 │        └───────────────┴───────┬───────┴─────────────────┘           │
 └────────────────────────────────┼─────────────────────────────────────┘
                                  │
                                  ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                  AWS Organization — Security OU Account                │
 │                                                                        │
 │  ┌──────────────────────────────────────────┐                          │
 │  │  Reconciler (src/reconciler/)            │                          │
 │  │                                          │                          │
 │  │  sources.py → DepartureRecord[]          │                          │
 │  │  change_detect.py → SHA-256 row diff     │                          │
 │  │  export.py → S3 manifest (KMS encrypted) │                          │
 │  └─────────────────┬────────────────────────┘                          │
 │                    │                                                    │
 │                    ▼                                                    │
 │  ┌──────────────────────────┐     ┌─────────────────────────────┐     │
 │  │  S3 Departures Bucket    │────▶│  EventBridge Rule           │     │
 │  │  (KMS, versioned)        │     │  (S3 PutObject trigger)     │     │
 │  └──────────────────────────┘     └──────────────┬──────────────┘     │
 │                                                   │                    │
 │                                   ┌───────────────▼───────────────┐   │
 │                                   │        Step Function           │   │
 │                                   │                                │   │
 │   ┌───── VPC ─────────────────────────────────────────────────┐   │   │
 │   │                                                           │   │   │
 │   │  ┌─────────────────────┐    ┌──────────────────────────┐  │   │   │
 │   │  │ Parser Lambda       │    │ Worker Lambda             │  │   │   │
 │   │  │                     │───▶│                            │  │   │   │
 │   │  │ - Validate manifest │    │ - 13-step IAM cleanup     │  │   │   │
 │   │  │ - Grace period check│    │ - Cross-account STS       │  │   │   │
 │   │  │ - Rehire filtering  │    │ - Multi-cloud workers     │  │   │   │
 │   │  │ - IAM existence     │    │ - Audit to DDB + S3       │  │   │   │
 │   │  │                     │    │                            │  │   │   │
 │   │  │ Parser IAM Role     │    │ Worker IAM Role            │  │   │   │
 │   │  │ (read-only)         │    │ (write, cross-account)     │  │   │   │
 │   │  └─────────────────────┘    └────────────┬─────────────┘  │   │   │
 │   └──────────────────────────────────────────┼─────────────────┘   │   │
 │                                              │                      │   │
 │                 ┌────────────────────────────▼──────────────────┐    │
 │                 │  Target Accounts (via STS AssumeRole)         │    │
 │                 │                                                │    │
 │                 │  1. Revoke all credentials                    │    │
 │                 │  2. Strip all permissions                     │    │
 │                 │  3. Delete IAM user                           │    │
 │                 └──────────────────────────────────────────────┘    │
 │                                                                      │
 │   ┌──────────────────────────────────────────────────────────────┐   │
 │   │  Audit Trail                                                 │   │
 │   │  DynamoDB (per-user) + S3 (execution logs) → DW ingest-back │   │
 │   └──────────────────────────────────────────────────────────────┘   │
 └──────────────────────────────────────────────────────────────────────┘
```

## Skills

| Skill | Status | Description |
|-------|--------|-------------|
| [iam-departures-remediation](skills/iam-departures-remediation/) | Production | Auto-remediate IAM for departed employees — 4 HR sources, 5 cloud targets, 13-step cleanup |

## What's Inside

### iam-departures-remediation

Fully deployable automation that reconciles HR termination data against cloud IAM and safely removes departed-employee access.

**Pipeline**: HR source → Reconciler → S3 manifest → EventBridge → Step Function → Parser Lambda → Worker Lambda → Target Accounts

<details>
<summary><b>Components</b></summary>

| Component | Path | What It Does |
|-----------|------|-------------|
| **Reconciler** | `src/reconciler/` | Ingests from 4 HR sources, SHA-256 change detection, KMS-encrypted S3 export |
| **Parser Lambda** | `src/lambda_parser/` | Validates manifest, grace period checks, rehire filtering, IAM existence verification |
| **Worker Lambda** | `src/lambda_worker/` | 13-step IAM dependency cleanup + deletion, cross-account STS |
| **Multi-Cloud Workers** | `src/lambda_worker/clouds/` | Azure Entra, GCP IAM, Snowflake, Databricks SCIM |
| **CloudFormation** | `infra/cloudformation.yaml` | Full stack: roles, Lambdas, Step Function, S3, DynamoDB |
| **StackSets** | `infra/cross_account_stackset.yaml` | Org-wide cross-account remediation role |
| **IAM Policies** | `infra/iam_policies/` | Least-privilege policy documents per component |
| **Tests** | `tests/` | Unit tests covering parser, worker, reconciler, cross-cloud |

</details>

### Security Model

```
  ZERO TRUST                    LEAST PRIVILEGE              DEFENSE IN DEPTH
 ┌────────────────┐            ┌────────────────┐           ┌────────────────┐
 │ Cross-account  │            │ Parser: read   │           │ Deny policies  │
 │ scoped by      │            │ Worker: scoped │           │ on root,       │
 │ PrincipalOrgID │            │   write per    │           │ break-glass-*, │
 │                │            │   component    │           │ emergency-*    │
 │ STS AssumeRole │            │ SFN: invoke    │           │                │
 │ per account    │            │   only         │           │ KMS encryption │
 │                │            │ EB: start      │           │ everywhere     │
 │ VPC isolation  │            │   only         │           │                │
 └────────────────┘            └────────────────┘           │ Dual audit:    │
                                                            │ DDB + S3 + DW  │
                                                            └────────────────┘
```

| Principle | Implementation |
|-----------|---------------|
| **Least privilege** | Each component has its own IAM role with minimal permissions |
| **Defense in depth** | Deny policies protect root, break-glass, and emergency accounts |
| **Zero trust** | Cross-account access scoped by `aws:PrincipalOrgID` condition |
| **Encryption** | S3 (KMS), DynamoDB (encryption at rest), Lambda env vars (KMS) |
| **Audit trail** | Dual-write: DynamoDB per-user audit + S3 execution logs → warehouse ingest |
| **Rehire safety** | 8 rehire scenarios handled with grace period (default 7 days) |

### Compliance Framework Mapping

Every Lambda and reconciler module is tagged with official framework controls:

| Framework | Controls Covered | Where |
|-----------|-----------------|-------|
| **MITRE ATT&CK** | T1078.004, T1098.001, T1087.004, T1531, T1552 | Lambda docstrings |
| **NIST CSF 2.0** | PR.AC-1, PR.AC-4, DE.CM-3, RS.MI-2 | Lambda docstrings |
| **CIS Controls v8** | 5.3, 6.1, 6.2, 6.5 | Lambda docstrings |
| **SOC 2 TSC** | CC6.1, CC6.2, CC6.3 | Worker Lambda |

<details>
<summary><b>MITRE ATT&CK coverage detail</b></summary>

| Technique | ID | How This Skill Addresses It |
|-----------|-----|---------------------------|
| Valid Accounts: Cloud | T1078.004 | Daily reconciliation detects + remediates departed-employee IAM |
| Additional Cloud Credentials | T1098.001 | All access keys deactivated + deleted |
| Cloud Account Discovery | T1087.004 | Cross-account STS validates IAM existence |
| Account Access Removal | T1531 | Full 13-step dependency cleanup pipeline |
| Unsecured Credentials | T1552 | Proactive cleanup within grace period |

</details>

### Multi-Cloud Support

The Worker Lambda dispatches to cloud-specific handlers:

| Cloud | Handler | Cleanup Steps | API |
|-------|---------|--------------|-----|
| **AWS IAM** | `handler.py` | 13 steps (keys, groups, policies, MFA, certs, SSH, delete) | boto3 |
| **Azure Entra** | `clouds/azure_entra.py` | 6 steps (revoke sessions, disable, remove groups, delete) | msgraph-sdk |
| **GCP** | `clouds/gcp_iam.py` | SA: 4 steps + Workspace: 2 steps | google-cloud-iam |
| **Snowflake** | `clouds/snowflake_user.py` | 6 steps (disable, drop roles, revoke, drop user) | SQL DDL |
| **Databricks** | `clouds/databricks_scim.py` | 4 steps (deactivate, remove groups, revoke tokens, delete) | SCIM API |

### HR Data Sources

```
  ┌───────────────────────────────────────────────────┐
  │              HR Data Ingestion                     │
  │                                                    │
  │  Workday ──(RaaS API)──┐                          │
  │  Snowflake ──(SQL)──────┤                          │
  │  Databricks ──(Unity)───┼──▶ DepartureRecord[]    │
  │  ClickHouse ──(SQL)─────┘    (unified schema)     │
  │                                   │                │
  │                                   ▼                │
  │                          change_detect.py          │
  │                          (SHA-256 row diff)        │
  │                                   │                │
  │                          only changed → export     │
  └───────────────────────────────────────────────────┘
```

All sources normalize to a unified `DepartureRecord` schema. Change detection ensures only new/changed records trigger remediation.

## Quick Start

```bash
# Clone
git clone https://github.com/msaad00/cloud-security.git
cd cloud-security/skills/iam-departures-remediation

# Run tests
pip install boto3 moto pytest
pytest tests/ -v

# Deploy (CloudFormation)
aws cloudformation deploy \
  --template-file infra/cloudformation.yaml \
  --stack-name iam-departures-remediation \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    HRSourceType=snowflake \
    SnowflakeAccount=your_account \
    SnowflakeUser=your_user

# Validate with agent-bom (optional)
pip install agent-bom
agent-bom scan --aws --aws-cis-benchmark
```

## Integration with agent-bom

This repo contains the deployment code. [agent-bom](https://github.com/msaad00/agent-bom) provides the scanning and compliance validation layer:

| agent-bom Tool | Use Case |
|----------------|----------|
| `cis_benchmark` | Post-remediation IAM hygiene validation |
| `scan --aws` | Discover Lambda dependencies, check for CVEs |
| `blast_radius` | Map impact of orphaned IAM credentials |
| `compliance` | 10-framework compliance posture check |

## License

Apache 2.0
