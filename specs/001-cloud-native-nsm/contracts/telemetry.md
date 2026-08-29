# Trawl Telemetry Contract

This contract keeps operational signals useful without leaking packet evidence or
creating unbounded Prometheus/Loki cardinality.

## Safety rules

The following values must never appear in telemetry: packet payloads, capture
contents, bearer tokens, private keys, S3 credentials, presigned URLs, raw rejected
records, HTTP query strings, Authorization/Cookie headers, or analyzer command
output that has not passed a sanitizer.

The following high-cardinality values may appear in structured log fields, Loki
structured metadata, or bounded Kubernetes status fields, but never in Prometheus
labels or Loki indexed labels: IP/MAC address, port, Community ID, Zeek UID, rule
ID, CaptureJob UID/name, object key, pod name, request ID, and arbitrary error text.

## Loki observation streams

Every observation body validates against `observation.schema.json`.

### Indexed labels

| Label | Allowed values |
|---|---|
| `service_name` | `trawl-observation` |
| `cluster` | Installation-configured bounded cluster identifier |
| `source_kind` | `suricata`, `zeek`, `hubble` |
| `observation_type` | Contract enum (`signature`, `connection`, and so on) |

Do not promote tap name, target/node, namespace, verdict, severity, rule category,
or status code without a measured cardinality review. Dashboards begin with the
four labels above and filter the rest as structured metadata/JSON.

### Structured metadata

Alloy may promote: `tap_uid`, `tap_namespace`, `tap_name`, `target_node`,
`target_interface`, `community_id`, `zeek_uid`, `source_ip`, `source_port`,
`destination_ip`, `destination_port`, `protocol`, `severity`, `rule_id`,
`category`, `verdict`, and `drop_reason`.

The full JSON line remains authoritative. Loki must use TSDB index type and schema
v13 or newer with `allow_structured_metadata: true`. Alloy increments and alerts on
non-retryable rejection, including structured-metadata size/count limits.

## Audit stream

The authoritative audit record is first committed under `audit/v1/` in a separate
private ledger bucket using a stable idempotency key, conditional creation, HEAD
verification, versioning, and backend-enforced write-once retention. The mTLS audit
sink acknowledges only after that verification.
Loki is a searchable replay target: ingestion failure increases backlog health and
does not erase the durable record.

Audit JSON uses indexed labels only:

| Label | Allowed values |
|---|---|
| `service_name` | `trawl-audit` |
| `cluster` | Installation-configured cluster identifier |
| `action` | Bounded action enum |
| `decision` | `allowed`, `denied`, `succeeded`, `failed` |

The body includes `recorded_at`, sanitized actor identity, resource group/kind,
namespace/name/UID when known, reason enum, and request ID. Actor, resource names,
and request IDs are structured metadata, not indexed labels.

Required actions:

- `networktap.create`, `networktap.update`, `networktap.delete`
- `capturepolicy.create`, `capturepolicy.update`, `capturepolicy.delete`
- `capturepolicy.arm`, `capturepolicy.disarm`
- `capturejob.manual_create`, `capturejob.policy_create`
- `capturejob.transition`
- `artifact.download`
- `retention.change`, `artifact.expire`

Admission logs the authenticated actor for API mutations. Controllers and workers
use their workload identity for automatic actions while preserving the initiating
policy/user reference as a structured field. Gateway download audits occur before
returning any redirect.

Successful user mutations, automatic action commits, lifecycle transitions,
retention changes, expiry deletion, and successful download authorization wait for
the durable ledger acknowledgement. A user action fails closed when acknowledgement
is unavailable; this never changes or blocks monitored traffic. Metrics expose
ledger write failures, conflicting idempotency keys, replay backlog, and oldest
unforwarded-record age without high-cardinality labels.

Potentially fallible actions have distinct stable `allowed` intent and
`succeeded`/`failed` outcome records. Ledger replay uses a persisted cursor and
overlap window. Duplicate Loki delivery copies preserve `stable_key`; audit queries
and dashboards collapse them by that field and treat the object ledger as authority.

## Prometheus metrics

All counters are monotonic. Histograms define explicit buckets during
implementation and are tested against the success criteria. Labels listed below
are exhaustive unless this contract is amended.

### Audit ledger and replay

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `trawl_audit_commit_total` | counter | `decision`, `result` | Conditional ledger commits and idempotent retries. |
| `trawl_audit_conflict_total` | counter | none | Same stable key observed with different content. |
| `trawl_audit_replay_total` | counter | `result` | Ledger records forwarded to the searchable stream. |
| `trawl_audit_backlog_objects` | gauge | none | Objects not yet covered by the persisted replay cursor. |
| `trawl_audit_oldest_unforwarded_seconds` | gauge | none | Age of the oldest replay backlog object. |

Allowed `decision`: `allowed`, `denied`, `succeeded`, `failed`. Allowed `result`:
`success`, `retry`, `unavailable`, `conflict`.

### Controller and reconciliation

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `trawl_reconcile_total` | counter | `controller`, `result` | Reconciliations by bounded controller/result enums. |
| `trawl_reconcile_duration_seconds` | histogram | `controller` | Reconcile latency. |
| `trawl_workqueue_depth` | gauge | `controller` | Pending work. |
| `trawl_status_update_failures_total` | counter | `resource_kind`, `reason` | Failed status writes. |
| `trawl_finalizer_failures_total` | counter | `resource_kind`, `reason` | External cleanup failures. |

Allowed `controller`: `networktap`, `capturejob`, `retention`. Allowed `result`:
`success`, `requeue`, `invalid`, `dependency_unavailable`, `error`.

### Sensor and ingestion

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `trawl_sensor_packets_total` | counter | `source_type`, `analyzer` | Packets reported at capture/analyzer boundary. |
| `trawl_sensor_kernel_drops_total` | counter | `source_type`, `analyzer` | Kernel drops where available. |
| `trawl_sensor_records_total` | counter | `source_kind`, `observation_type`, `result` | Normalized, unsupported, or malformed records. |
| `trawl_sensor_last_packet_timestamp_seconds` | gauge | `source_type`, `analyzer` | Latest packet time per sensor process; target identity is supplied out of band at scrape time, not a custom label. |
| `trawl_alloy_delivery_failures_total` | counter | `reason` | Trawl-observed downstream log delivery failures. |

Allowed `source_type`: `mirror_interface`, `node_interface`. Allowed `analyzer`:
`suricata`, `zeek`. Allowed record `result`: `accepted`, `unsupported`, `malformed`.

### Trigger evaluation

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `trawl_trigger_events_total` | counter | `source`, `result` | Events processed, replayed, malformed, or lost. |
| `trawl_policy_decisions_total` | counter | `trigger_type`, `decision` | Match outcomes. |
| `trawl_trigger_source_connected` | gauge | `source` | `1` when source connection/query path is healthy. |
| `trawl_trigger_lag_seconds` | gauge | `source` | Now minus latest fully processed observation. |
| `trawl_trigger_gap_total` | counter | `source`, `reason` | Known coverage gaps. |

Allowed `source`: `suricata_loki`, `hubble_relay`. Allowed `decision`:
`not_matched`, `created`, `duplicate`, `rate_limited`, `disarmed`, `failed`.
No policy or rule identifier is a metric label.

### Capture and artifact

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `trawl_capture_requests_total` | counter | `request_type`, `result` | Manual/policy requests and admission/resolution outcome. |
| `trawl_capture_transitions_total` | counter | `from`, `to` | Lifecycle transitions. |
| `trawl_capture_start_latency_seconds` | histogram | `request_type` | Request time to actual capture start. |
| `trawl_capture_store_latency_seconds` | histogram | `result` | Capture end to verified terminal storage result. |
| `trawl_capture_size_bytes` | histogram | `request_type` | Completed artifact sizes. |
| `trawl_capture_bound_stop_total` | counter | `bound` | Duration, size, cancellation, or error stop reason. |
| `trawl_artifact_operations_total` | counter | `operation`, `result` | Upload, verify, presign, delete. |
| `trawl_artifact_expiry_lag_seconds` | histogram | none | Verified deletion time minus retention deadline. |
| `trawl_artifact_download_total` | counter | `decision` | Gateway outcomes without capture/user labels. |

### Process

Each long-running binary exposes standard Go/process metrics plus:

- `/healthz`: process liveness only.
- `/readyz`: required dependency readiness; reports only bounded dependency names
  and safe reasons.
- build information with version, commit, and dirty boolean; never a mutable tag.

## Kubernetes conditions

Conditions use `status: True|False|Unknown`, `observedGeneration`, a transition
timestamp, a stable PascalCase reason, and a sanitized message no longer than 512
bytes. Messages describe remediation but do not embed raw dependency responses.

### NetworkTap

- `Accepted`
- `TargetsResolved`
- `WorkloadReady`
- `AnalyzersHealthy`
- `PacketsObserved`

### CapturePolicy

- `Accepted`
- `TapResolved`
- `SourceConnected`
- `WithinRateLimit`
- `Ready`

### CaptureJob

- `Accepted`
- `TargetReady`
- `FilterValid`
- `CaptureStarted`
- `ArtifactVerified`
- `Downloadable`
- `RetentionEnforced`

Status is stale whenever `status.observedGeneration != metadata.generation`.
Dashboards must surface stale status rather than treating it as current truth.

## Grafana dashboard contract

1. **Trawl Overview**: observation volume, signature severity/category, protocol
   activity, Hubble allowed/denied counts, aggregate tap phases, capture phases.
2. **Alert Investigation**: signature detail, exact Community ID pivot, explicitly
   approximate endpoint/time pivot, related Zeek/Hubble timeline.
3. **Protocol Analysis**: connection, DNS, HTTP, TLS/certificate, file, notice, and
   weird views using supported schema fields.
4. **Capture Management**: policy state/decision counts, execution lifecycle,
   storage/retention health, and a non-secret copyable `trawlctl` download command
   only for downloadable captures.

Dashboards must not embed a MinIO object URL, gateway link, credential, bearer token,
presigned URL, or service-account token. Sensitive panels remain restricted to the
approved Grafana team boundary; the CLI/gateway independently enforces Kubernetes
RBAC using the analyst's identity.

## Alerting baseline

Alert when any of these persist beyond a tuned grace interval:

- NetworkTap is `Error` or `Degraded`.
- Kernel packet loss ratio exceeds 1% at the capture boundary.
- An analyzer is unhealthy or record rejection rises.
- Trigger source disconnects, processing lag exceeds 30 seconds, or a known gap is
  reported.
- Capture, upload, verification, download authorization, or retention deletion
  fails.
- Artifact deletion lag approaches 24 hours.
- Audit or observation ingestion is rejected.

Alerts identify the affected Kubernetes resource through annotations/query output,
not by adding high-cardinality metric labels.
