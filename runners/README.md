# Runners

Runners are the persistent edge components around the stateless skills.

They own:
- source subscriptions and queue triggers
- checkpointing and replay position
- dedupe tables or sink merge semantics
- retry / DLQ behavior
- sink writes and alert fan-out

They do **not** change the skill contract. The same `SKILL.md + src/ + tests/`
bundle should still run unchanged from the CLI, CI, MCP, or a persistent loop.

## Shipped reference runner

- [`aws-s3-sqs-detect`](aws-s3-sqs-detect/): S3 object create trigger → ingest
  Lambda → SQS detect queue → detect Lambda → DynamoDB dedupe → SNS publish

This is a reference template, not a multi-tenant managed service. Operators still
own packaging, deployment, sink wiring, IAM review, and environment-specific
controls.
