# CI Workflow

The CI pipeline is split into independent lanes so failures point at the right kind of work without duplicating the entire repo in every job.

## Lanes

- `lint`
  - fast repo-wide Ruff gate
- `security-scan`
  - scoped Bandit for the currently enforced high-risk paths
- `safe-skill-bar`
  - policy lane for abuse resistance, write-path guardrails, wildcard IAM exceptions, secrets scan, and dependency audit against the repo's declared project dependencies
- `test-compliance`
  - benchmark skills grouped under one matrix
- `test-remediation`
  - write-capable workflows isolated from read-only checks
- `test-detection-engineering`
  - OCSF ingest, detect, and convert skills
- `test-ai-infra`
  - model serving, GPU, and environment-discovery skills
- `test-integration`
  - cross-skill contracts and pipe-level regression tests
- `validate-iac`
  - CloudFormation and Terraform validation
- `agent-bom`
  - advisory artifact and SARIF generation

## Simplification Rules

- Share Python setup and dependency install logic through a composite action.
- Keep required checks small and actionable.
- Keep advisory scans separate from merge-blocking gates.
- Install only the packages each lane needs.
- Prefer matrix lanes by skill family instead of one global `pytest skills/`.

## Next Tightenings

1. Pin all third-party GitHub Actions to immutable SHAs.
2. Move repeated skill-family package sets into dependency groups or lock-backed sync commands.
3. Add a reusable workflow for test lanes if matrix shapes keep growing.

## Dependency Policy

Dependency refreshes should land in grouped batches, not one-package PR spam:

- `deps: github-actions`
- `deps: python-dev-tools`
- `deps: cloud-sdks`

Use the dependency hygiene skill spec as the review contract for those batches.
