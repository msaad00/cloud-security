# Runner Contract

Runners are not skills. They are thin, side-effectful wrappers that drive the
same skill contract continuously.

Their job is:

`source event -> invoke skill command(s) -> dedupe / checkpoint -> publish or persist`

## What runners own

- queue or event subscription wiring
- checkpoint or dedupe state
- cloud-native packaging and deployment shape
- retry / DLQ / concurrency boundaries

## What runners do not own

- detection logic
- normalization logic
- skill-specific business rules
- alternate implementations of a shipped skill

If the skill logic changes, it changes in the skill, not in the runner.

## Required design rules

- skill commands are passed in as environment variables, not hardcoded in code
- tokenized command execution only; no shell passthrough
- skills remain unchanged and stateless
- retry and replay behavior lives in the runner edge, not in the skill
- dedupe and checkpoint state must be explicit

## Packaging model

The repo’s runner templates intentionally focus on event plumbing first. They
may provision the queues, topics, subscriptions, and dedupe state without
owning the final compute packaging layer for every cloud.

That is deliberate:

- AWS, GCP, and Azure package compute differently
- enterprise teams often already have an internal deployment opinion
- the runner template should stay portable and reviewable

## Concurrency and cost

Runners should document or enforce a concurrency ceiling where the platform
supports it.

Current shipped posture:

- AWS template: queue-driven geometry and retry boundaries
- GCP template: enforced `max_instance_count`
- Azure template: exported `recommendedMaxInstances` operator contract

## Current shipped runners

- `runners/aws-s3-sqs-detect`
- `runners/gcp-gcs-pubsub-detect`
- `runners/azure-blob-eventgrid-detect`

These are reference patterns, not a promise that every skill ships with a
dedicated long-lived runtime.
