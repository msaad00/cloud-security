# OCSF Contract — Detection Engineering Category

This document pins the exact OCSF fields every skill in `detection-engineering/` must read and write. It is the **only** dependency shared across skills in this category. If you are writing a new ingestion or detection skill, your tests must verify that the output matches this contract.

## OCSF version

- Base schema: **OCSF 1.3** (current stable).
- MCP-specific fields: **custom profile extension** `cloud_security_mcp`, bolted onto `Application Activity` (class 6002). This lets us use OCSF 1.3 for everything else while still capturing MCP tool schema, tool arguments, and proxy session ID.
- When OCSF 1.4 ships with native AI/agent classes, we will swap the custom profile for the official one in a single follow-up PR and update the contract version below.

```
contract version: 1.3.0+mcp.2026.04
```

## Wire format

- All skills read and write **JSONL** (one OCSF event per line).
- UTF-8, no BOM, LF line endings.
- Skills read from `stdin` by default, write to `stdout`. A `--input` / `--output` flag is optional but must not change the default behaviour.
- Errors go to `stderr`. A malformed line is **skipped with a `stderr` warning**, never fatal — detection pipelines must not crash on one bad event.

## Required OCSF fields (every event)

Every event a skill emits MUST populate these fields at minimum. Fields marked `[req]` are required by OCSF itself; `[pin]` are pinned by this contract on top of the OCSF minimum.

| Field | Type | Notes |
|---|---|---|
| `activity_id` | int [req] | Class-specific activity enum |
| `category_uid` | int [req] | Matches the class's category |
| `category_name` | string [pin] | Human-readable category (for log grep) |
| `class_uid` | int [req] | The OCSF class number (e.g. 6002 for Application Activity) |
| `class_name` | string [pin] | Human-readable class (for log grep) |
| `type_uid` | int [req] | `class_uid * 100 + activity_id` |
| `severity_id` | int [req] | 0 Unknown, 1 Informational, 2 Low, 3 Medium, 4 High, 5 Critical, 6 Fatal |
| `status_id` | int [pin] | 0 Unknown, 1 Success, 2 Failure |
| `time` | int [req] | Unix epoch **milliseconds** (not seconds) |
| `metadata.version` | string [req] | `"1.3.0"` |
| `metadata.product.name` | string [pin] | `"cloud-security"` |
| `metadata.product.vendor_name` | string [pin] | `"msaad00/cloud-security"` |
| `metadata.product.feature.name` | string [pin] | Name of the emitting skill (e.g. `"detect-mcp-tool-drift"`) |

## OCSF class usage

### Ingest skills

| Source | OCSF class | `class_uid` | Why |
|---|---|---:|---|
| AWS CloudTrail | API Activity | 6003 | Control-plane API calls |
| GCP Audit | API Activity | 6003 | Same |
| Azure Activity | API Activity | 6003 | Same |
| Kubernetes audit | API Activity | 6003 | K8s API server is the control plane |
| MCP proxy | Application Activity | 6002 | MCP is an application protocol, not a cloud control plane |
| Model serving access logs | HTTP Activity | 4002 | Inference over HTTP |

### Detect skills

All detection skills produce **Security Finding** (class `2001`, `category_uid=2`). The input class varies.

## Required fields on a Security Finding (2001)

```jsonc
{
  "activity_id": 1,                 // 1 = Create (a new finding)
  "category_uid": 2,                // Findings
  "category_name": "Findings",
  "class_uid": 2001,
  "class_name": "Security Finding",
  "type_uid": 200101,               // 2001 * 100 + 1
  "severity_id": 4,                 // High — pinned by detection rule
  "status_id": 1,                   // 1 Success — the rule ran cleanly
  "time": 1743465600000,            // when the FINDING was created, not the underlying event

  "metadata": {
    "version": "1.3.0",
    "product": {
      "name": "cloud-security",
      "vendor_name": "msaad00/cloud-security",
      "feature": {"name": "detect-mcp-tool-drift"}
    },
    "labels": ["detection-engineering", "mcp", "supply-chain"]
  },

  "finding": {
    "uid": "det-mcp-drift-abc123",  // stable ID per (rule, session, tool)
    "title": "MCP tool schema drift detected mid-session",
    "desc": "Tool 'query_db' changed fingerprint after first call in session sess-abc"
  },

  "attacks": [
    {
      "version": "v14",
      "tactic":    {"name": "Initial Access",            "uid": "TA0001"},
      "technique": {"name": "Compromise Software Supply Chain", "uid": "T1195.001"}
    }
  ],

  "observables": [
    {"name": "session.uid",    "type": "Other",       "value": "sess-abc"},
    {"name": "tool.name",      "type": "Other",       "value": "query_db"},
    {"name": "tool.before",    "type": "Fingerprint", "value": "sha256:abc..."},
    {"name": "tool.after",     "type": "Fingerprint", "value": "sha256:def..."}
  ],

  "evidence": {
    "events_observed": 2,
    "before_event_time": 1743465000000,
    "after_event_time":  1743465600000,
    "raw_events": []                // pointer / rowid / S3 URI, not full bodies
  }
}
```

The point: **a downstream tool (ClickHouse, Splunk OCSF app, Grafana) can pivot on `attacks[].technique.uid` without ever reading the rule code**. That is the whole benefit of keeping MITRE inside OCSF instead of as a sidecar mapping.

## MITRE ATT&CK version pinning

- ATT&CK version: **v14** (pinned for the v1.3.0+mcp.2026.04 contract)
- Rationale: frozen once per contract version so detections are reproducible. To bump, cut a new contract version and update every detection skill's test fixtures.

## Custom MCP profile extension

For `Application Activity` events that originate from an MCP proxy, populate these extra fields under a nested `mcp` key (non-standard, gated by `metadata.profiles: ["cloud_security_mcp"]`):

```jsonc
{
  "metadata": {
    "profiles": ["cloud_security_mcp"],
    ...
  },
  "mcp": {
    "session_uid": "sess-abc",       // agent-bom proxy session ID
    "method":      "tools/list",     // MCP JSON-RPC method
    "direction":   "response",       // request | response
    "tool": {                        // present only for tools/list and tools/call
      "name":        "query_db",
      "description": "Query database using SQL",
      "input_schema_sha256": "sha256:abc123...",
      "fingerprint":         "sha256:full_tool_fingerprint..."
    }
  }
}
```

Fingerprint definition: `sha256(json.dumps({name, description, inputSchema, annotations}, sort_keys=True))`.

## Test contract

Every detection skill ships with:
1. An **input fixture**: frozen OCSF JSONL in `golden/<source>_sample.ocsf.jsonl`
2. An **expected-output fixture**: frozen OCSF Security Finding in `golden/<detection>_finding.ocsf.json`
3. A pytest test that pipes the input fixture through the detector and asserts deep-equality against the expected output (with a helper that scrubs volatile fields like timestamps)

If the skill adds a new attack scenario, add a new fixture pair, keep the old one. Never mutate an existing fixture.
