# Security Policy

## Supported Versions

The `main` branch is the supported release line. Security fixes land there first.

## Reporting a Vulnerability

Please do not open public GitHub issues for suspected vulnerabilities.

Send reports through [GitHub private security reporting](https://github.com/msaad00/cloud-ai-security-skills/security/advisories/new)
or directly by email if a contact is listed on the maintainer profile. Include:

- affected skill and file path
- impact and attack scenario
- steps to reproduce
- proof-of-concept details if available
- whether secrets, credentials, or customer data were involved

## Response Expectations

- initial acknowledgment target: 48 hours
- remediation triage target: 7 business days
- coordinated disclosure after a fix or mitigation is available

## Secure Usage Requirements

- never commit credentials, tokens, or customer data
- source runtime secrets from AWS Secrets Manager, SSM Parameter Store, Vault, or workload identity
- prefer federation and short-lived credentials over static passwords or long-lived API tokens
- keep CSPM execution roles read-only unless the skill is explicitly remediation-oriented
- run CI checks before merging changes that affect IAM, cloud auth, or infrastructure templates
- keep S3 artifacts KMS-encrypted and scope cross-account trust by `aws:PrincipalOrgID`
