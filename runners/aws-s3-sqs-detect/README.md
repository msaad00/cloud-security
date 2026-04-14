# aws-s3-sqs-detect

Reference persistent runner template for continuous ingest → detect pipelines on
AWS. The template attaches to an existing source bucket and keeps the queue,
dedupe table, and alert path inside the stack.

## What it does

```
S3 object create
  -> ingest Lambda
  -> SQS queue
  -> detect Lambda
  -> DynamoDB dedupe
  -> SNS fan-out
```

The runner keeps state and side effects at the edges:
- S3 is the raw object source
- SQS provides durable decoupling
- DynamoDB stores replay-safe dedupe keys
- SNS distributes new findings downstream

The skills remain unchanged and stateless.

## When to use it

- You want a repo-owned example of a persistent execution path beyond IAM departures
- You need a minimal AWS pattern for continuous ingest → detect with replay safety
- You want to wire any compatible `ingest-*` and `detect-*` skill pair into a
  queue-driven loop

## What it does not do

- It is not a generic sink framework for every cloud or SIEM
- It does not package Lambda zip artifacts for you
- It does not hardcode a specific skill family, sink vendor, or storage format

## Required environment variables

### Ingest Lambda

- `INGEST_SKILL_CMD`
  Example: `python skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py --output-format native`
- `DETECT_QUEUE_URL`

### Detect Lambda

- `DETECT_SKILL_CMD`
  Example: `python skills/detection/detect-lateral-movement/src/detect.py --output-format native`
- `DEDUPE_TABLE`
- `SNS_TOPIC_ARN`

## Packaging model

The CloudFormation template expects:
- an existing source bucket name
- one zip for the ingest handler
- one zip for the detect handler

That keeps the template deployable without assuming SAM or an external build
system.

## Security model

- no shell invocation; skill commands are tokenized with `shlex.split`
- `subprocess.run(..., shell=False)` only
- DynamoDB conditional writes prevent duplicate publish on replay
- SNS only sees deduped findings
- operators should scope the Lambda roles to the specific source bucket, queue,
  topic, and table ARNs in their environment
