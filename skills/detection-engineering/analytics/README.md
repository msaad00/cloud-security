# Analytics stub — ClickHouse + Grafana on OCSF

This directory is intentionally **stub-only**. It pins the target analytics stack so contributors know what to build toward, but no code lives here yet — analytics is a follow-up PR once the ingest/detect pipeline has enough findings to visualise.

## Target stack

```
  OCSF JSONL                    ClickHouse                Grafana
 (stdout of                    (columnar OLAP,           (OCSF dashboard
  detect-* skills)  ──ingest──► OCSF schema      ◄─query─ pack)
```

1. **Storage: ClickHouse** with a native OCSF schema (one table per OCSF class, or a single wide table with `class_uid` as a partition key — decide based on ingest volume).
2. **Query: ClickHouse SQL** — flat SQL over `attacks[]`, `observables[]`, `metadata.product.feature.name` to pivot detections by technique, tool, agent, tenant.
3. **Dashboards: Grafana** with the ClickHouse datasource plugin — one dashboard per detection family (MCP, credential access, privilege escalation), plus a master "MITRE ATT&CK heatmap" view driven by `attacks[].technique.uid`.
4. **Alerting: Grafana Alerting** on rolling windows (e.g. "more than 5 MCP tool-drift findings in 1 hour from one session").

## Why not a SIEM?

The skills in `detection-engineering/` already produce OCSF. Every major SIEM (Splunk, Elastic, Sentinel, Chronicle) now ingests OCSF natively or via `convert/ocsf-to-sigma`. If you want to ship findings into an existing SIEM, that path already works — this analytics stack is for teams that don't have (or don't want) a SIEM and need visibility on AI-infra detections today.

## Why ClickHouse specifically?

- OCSF is nested JSON — ClickHouse has first-class JSON and tuple types.
- OCSF is high-cardinality (one row per event, millions per day per tenant) — ClickHouse's MergeTree handles this without sharding drama.
- ClickHouse is already in the agent-bom stack as the analytics backend, so operationally we only run one OLAP.

## OCSF-to-ClickHouse schema mapping (sketch — not implemented)

```sql
CREATE TABLE ocsf_security_finding (
    -- OCSF base
    time              DateTime64(3) CODEC(Delta, ZSTD),
    class_uid         UInt16,
    activity_id       UInt8,
    severity_id       UInt8,
    status_id         UInt8,

    -- metadata
    product_feature   LowCardinality(String),   -- which skill emitted the finding
    labels            Array(LowCardinality(String)),

    -- finding
    finding_uid       String,
    finding_title     String,
    finding_desc      String,

    -- attacks (MITRE) — Nested so we can unfold multiple techniques per finding
    attacks           Nested(
        tactic_uid     LowCardinality(String),
        tactic_name    String,
        technique_uid  LowCardinality(String),
        technique_name String
    ),

    -- observables — unfolded for pivot queries
    observables       Nested(
        name  String,
        type  LowCardinality(String),
        value String
    ),

    -- evidence — pointer only, raw events stay in S3/ADLS
    evidence_events_observed  UInt32,
    evidence_first_seen       DateTime64(3),
    evidence_last_seen        DateTime64(3),
    evidence_raw_uri          String,

    -- raw JSON as a fallback
    raw JSON
) ENGINE = MergeTree
PARTITION BY toYYYYMM(time)
ORDER BY (product_feature, time, finding_uid);
```

Follow-up PR will flesh this out with:
- Full DDL (one table per `class_uid` that we actually ingest)
- Ingestion scripts (OCSF JSONL → ClickHouse `clickhouse-client --query="INSERT…"` or Kafka)
- Grafana dashboard JSON exports
- Alerting rules
