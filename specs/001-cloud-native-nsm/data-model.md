# Data Model: Trawl MVP

**API group**: `trawl.cloud`  
**API version**: `v1alpha1`  
**Scope**: Namespaced API, accepted only in the configured system namespace  
**Primary/default namespace**: `trawl-system`

The Kubernetes API stores desired state and lifecycle metadata. Loki stores
observations and searchable audit copies. MinIO-compatible object storage holds
sensitive pcapng artifacts and the authoritative audit ledger in separate private
buckets with distinct credentials. The ledger bucket uses versioning and backend-
enforced write-once retention. Packet payloads never enter Kubernetes objects or
application telemetry.

## Entity Relationships

```text
NetworkTap 1 ──────── * TapTargetHealth
     │
     ├── 1 ──────── * SecurityEvent / ProtocolObservation (Loki)
     ├── 1 ──────── * CapturePolicy
     └── 1 ──────── * CaptureJob ─────── 0..1 CaptureArtifact (MinIO)
                              │
CapturePolicy 0..1 ───────────┘
                              │
SecurityEvent or ClusterFlowEvent 0..1 trigger snapshot

Configuration/capture/download/expiry actions ─────── * AuditRecord (MinIO ledger ─▶ Loki)
```

References are same-namespace names in desired state and are resolved to immutable
UIDs in execution status/context. Deleting a NetworkTap or CapturePolicy does not
cascade to historical CaptureJobs, artifacts, observations, or audit records.

## 1. NetworkTap

A declarative passive packet source and its requested analyzers.

### Desired fields

| Field | Type | Rules |
|---|---|---|
| `metadata.name/namespace/uid/generation` | Kubernetes metadata | Namespace-scoped; UID/generation used for ownership and status. |
| `spec.mode` | enum | Required/default `Passive`; no other value served in the MVP. |
| `spec.type` | enum | Exactly `MirrorInterface` or `NodeInterface`. |
| `spec.mirrorInterface` | object | Present only for `MirrorInterface`; contains interface, promiscuous flag, and node selector. |
| `spec.nodeInterface` | object | Present only for `NodeInterface`; contains interface, promiscuous flag, and node selector. |
| `spec.*.interface` | string | Linux interface-name syntax, 1–15 bytes; existence is verified on each selected node. |
| `spec.*.nodeSelector` | label selector | Mirror source must resolve to exactly one eligible node; node source must resolve to at least one. |
| `spec.analyzers.suricata.enabled` | boolean | At least one of Suricata or Zeek must be enabled. |
| `spec.analyzers.zeek.enabled` | boolean | At least one of Suricata or Zeek must be enabled. |
| `spec.analyzers.*.resources` | Kubernetes resource requirements | CPU/memory requests and limits are mandatory when the analyzer is enabled; requests may not exceed limits. |

Rulesets, Zeek scripts, pod selectors, TLS keys, inline mode, and arbitrary images
are intentionally absent from the MVP API. Reviewed analyzer content is part of
the installed Trawl release.

### Observed fields

| Field | Type | Meaning |
|---|---|---|
| `status.observedGeneration` | int64 | Latest spec generation reflected in status. |
| `status.phase` | enum | `Pending`, `Active`, `Degraded`, or `Error`. |
| `status.matchedTargets` | int32 | Number of nodes selected by desired state. |
| `status.readyTargets` | int32 | Number with interface and all requested analyzers healthy. |
| `status.lastPacketTime` | timestamp? | Latest packet time across healthy target reports. |
| `status.targets[]` | map keyed by node name | Per-target interface and analyzer health, counters, and last heartbeat. |
| `status.conditions[]` | standard conditions | At least `Accepted`, `TargetsResolved`, `WorkloadReady`, `AnalyzersHealthy`, and `PacketsObserved`. |

Each target holds node name, interface, pod reference, heartbeat time, last packet
time, packet count, kernel drop count where available, duplication indicator when
determinable, rejected-record count, and one health record per analyzer. Counter
resets are represented with a new reporter instance ID rather than subtracted from
the previous value.

The sensor uses a bounded rolling fingerprint cache to classify an observation as a
suspected duplicate without dropping it. The target reports duplicate count plus
`Unknown`, `NotDetected`, or `Suspected`; dashboards call these observation counts,
not incidents.

The fingerprint covers tap UID, target, source kind/type, direction-normalized five-
tuple, event time rounded to one millisecond, and available analyzer-stable fields.
Repeats within one second are suspected duplicates. The cache holds at most 100,000
entries per target; eviction or insufficient fields sets the indicator to `Unknown`.

### Phase derivation

```text
new or new generation ─▶ Pending
Pending ─▶ Active       all selected targets and requested analyzers ready
Pending ─▶ Degraded     at least one useful target/mode ready, at least one unhealthy
Pending ─▶ Error        invalid/unresolvable dependency or no useful target/mode
Active  ─▶ Degraded     target/interface/analyzer becomes partially unhealthy
Active/Degraded/Error ─▶ Pending on a new generation or dependency recovery
```

The controller derives phase from target facts; sensor agents never set aggregate
phase directly.

## 2. CapturePolicy

An operator-managed rule mapping one automatic trigger to bounded capture behavior.

### Desired fields

| Field | Type | Rules |
|---|---|---|
| `spec.tapRef.name` | string | Required, same namespace; must resolve to an accepted NetworkTap. |
| `spec.armed` | boolean | Defaults false; disarmed policies evaluate no events. |
| `spec.trigger.type` | enum | Exactly `SuricataAlert` or `HubbleDrop`. |
| `spec.trigger.suricataAlert.severities` | unique int array | Required for Suricata; values 1–4. |
| `spec.trigger.suricataAlert.ruleIDs` | unique uint32 array | Optional narrowing. |
| `spec.trigger.suricataAlert.categories` | unique string array | Optional narrowing with bounded item length/count. |
| `spec.trigger.hubbleDrop.reasons` | unique string array | Required non-empty denied reasons. |
| `spec.trigger.hubbleDrop.sourceNamespaces` | unique string array | Optional narrowing. |
| `spec.trigger.hubbleDrop.threshold` | count + duration | Optional; count 1–10,000 and window 1s–15m. |
| `spec.capture.duration` | duration | Required, 1s–1h. |
| `spec.capture.filterTemplate` | string | Optional, at most 1,024 bytes; only documented typed event placeholders. |
| `spec.capture.snaplen` | int32 | `0` for full packet or 64–262,144 bytes. |
| `spec.capture.maxSize` | quantity | Required, 1Mi–1Gi for MVP. |
| `spec.retention` | duration | Required/default 30d, allowed 1h–30d. |
| `spec.rateLimit.maxCapturesPerHour` | int32 | Required, 1–100. |
| `spec.rateLimit.cooldown` | duration | Required, 1s–1h. |

Storage endpoints, bucket names, object keys, credentials, arbitrary Go templates,
schedule triggers, generic Hubble flows, and anomaly triggers are not user fields.

### Observed fields

| Field | Type | Meaning |
|---|---|---|
| `status.observedGeneration` | int64 | Policy generation being evaluated. |
| `status.phase` | enum | `Disarmed`, `Armed`, `Degraded`, or `RateLimited`. |
| `status.resolvedTapUID` | UID? | Tap identity bound for current generation. |
| `status.totalCaptures` | int64 | Successfully requested unique executions. |
| `status.activeCaptures` | int32 | Non-terminal executions originating from this policy. |
| `status.lastTriggerTime` | timestamp? | Last matching event, including suppressed decisions. |
| `status.lastCaptureRef` | object reference? | Most recent created or deduplicated execution. |
| `status.decisions` | counters | `matched`, `notMatched`, `duplicate`, `rateLimited`, `failed`. |
| `status.conditions[]` | standard conditions | `Accepted`, `TapResolved`, `SourceConnected`, `WithinRateLimit`, `Ready`. |

Counters are monotonic for a policy UID and may be rebuilt from persisted
CaptureJobs plus checkpoints after process restart.

## 3. CaptureJob (Capture Execution)

One packet-collection attempt with immutable execution fields. Users with analyst
permission may create a manual request; only the event worker may create a policy
execution or populate trigger context. A separate retention-administrator role may
change only the bounded retention period before expiry.

### Desired fields

| Field | Type | Rules |
|---|---|---|
| `spec.requestType` | enum | `Manual` or `Policy`; defaults `Manual`. |
| `spec.tapRef.name` | string | Required, same namespace. |
| `spec.targetNode` | string? | Required for manual; resolved before create for successful policy captures; may be absent only on an operator-created failed attempt. |
| `spec.filter` | string | Optional BPF, at most 1,024 bytes; parsed by the runner before collection. |
| `spec.duration` | duration | Required, 1s–1h. |
| `spec.snaplen` | int32 | `0` or 64–262,144 bytes. |
| `spec.maxSize` | quantity | Required, 1Mi–1Gi. |
| `spec.retention` | duration | Required/default 30d, 1h–30d. |
| `spec.policyRef` | immutable reference? | Policy name, UID, and generation; event-worker only. |
| `spec.trigger` | immutable snapshot? | Source type, fingerprint, event/observation times, flow and safe source fields; event-worker only. |
| `spec.deduplicationKey` | string? | Controller-computed hash; event-worker only. |

All spec fields except `retention` are immutable after create. Retention changes
require the retention-administrator identity, remain within 1h–30d, recompute the
deadline from the original completion time, and cannot move an already-expired job
back to `Completed`. Object storage location and credentials are never accepted
from a requester.

### Observed fields

| Field | Type | Meaning |
|---|---|---|
| `status.observedGeneration` | int64 | Always the admitted immutable generation. |
| `status.phase` | enum | `Pending`, `Capturing`, `Storing`, `Completed`, `Failed`, `Expired`. |
| `status.resolvedTapUID` | UID? | Exact source identity used. |
| `status.resolvedInterface` | string? | Interface opened by the runner. |
| `status.runnerJobRef` | object reference? | Owned Kubernetes Job. |
| `status.requestedAt` | timestamp | API creation time copied for display. |
| `status.startedAt` / `captureEndedAt` / `completedAt` | timestamps? | Actual lifecycle times. |
| `status.packetCount` | int64? | Zero is a valid completed result. |
| `status.sizeBytes` | int64? | Verified artifact size. |
| `status.sha256` | lowercase hex? | SHA-256 of the stored bytes. |
| `status.artifact` | object? | Private bucket profile ID, opaque key, ETag/version where available, and verified time. |
| `status.retentionDeadline` | timestamp? | `completedAt + spec.retention`; downloads denied at this instant. |
| `status.failure` | object? | Stable reason enum, safe message, failed phase, retry count; no raw tool output. |
| `status.conditions[]` | standard conditions | `Accepted`, `TargetReady`, `FilterValid`, `CaptureStarted`, `ArtifactVerified`, `Downloadable`, `RetentionEnforced`. |

### Lifecycle invariants

- Status never skips to `Completed` without a verified object, size, and checksum.
- The first configured duration or size boundary ends capture.
- `Failed` is terminal and never downloadable.
- `Completed` is downloadable only before `retentionDeadline` and with a positive
  authorization decision.
- At the deadline, `Downloadable=False` immediately even if object deletion is
  pending; deletion must verify within 24 hours before `Expired`.
- An authorized pre-expiry retention change recomputes the deadline from
  `completedAt`, is audited, and never alters capture or trigger facts.
- One CaptureJob UID maps to one runner Job name and one object key.
- A controller restart observes existing Jobs/objects before taking action.

Live progress originates in atomic versioned records on the runner/reporter shared
`emptyDir`. The unprivileged reporter validates them and owns only live progress
status fields for its CaptureJob; the controller owns aggregate and terminal state.
The runner has no Kubernetes token, and the reporter's token/Role can patch only the
owning CaptureJob `/status` by resource name.

### Failure reasons

`InvalidFilter`, `InvalidBounds`, `TapInactive`, `TargetUnavailable`,
`InterfaceUnavailable`, `RunnerCreateFailed`, `CaptureFailed`, `SizeExceeded`,
`UploadFailed`, `ArtifactMissing`, `ArtifactMismatch`, `RetentionDeleteFailed`, and
`InternalError`. Messages identify the action an operator can take but contain no
packet bytes, credentials, bearer values, object URLs, or analyzer raw records.

## 4. CaptureArtifact

A sensitive pcapng object represented inside CaptureJob status, not a public CRD.

| Field | Location | Rule |
|---|---|---|
| Artifact bytes | Private MinIO/S3 object | Server-side private, encrypted transport, no anonymous access. |
| Manifest | Adjacent private object | CaptureJob UID, requested/actual range, packet count, size, SHA-256, analyzer/tool versions; no credentials. |
| Object key | CaptureJob status | Controller-derived from namespace and UID; requester cannot set it. |
| Retention deadline | CaptureJob status | Exact authorization cutoff. |
| Presigned URL | Response only | Never persisted or logged; at most 5 minutes and never past retention. |

## 5. Normalized Observation

An append-only `trawl.observation/v1alpha1` JSON record in Loki. The normative
schema is `contracts/observation.schema.json`.

Common fields are schema version, unique record ID, event time, observation time,
source kind/version, NetworkTap name/namespace/UID, target node/interface,
observation type, optional direction-normalized flow, and type-specific details.

### Observation subtypes

- **SecurityEvent**: Suricata signature ID/revision, severity, category, message,
  action, and flow fields.
- **ProtocolObservation**: Zeek connection, DNS, HTTP, TLS, certificate, file,
  notice, or weird metadata with Zeek UID and protocol-specific details.
- **ClusterFlowEvent**: Hubble verdict, drop reason, endpoints/scopes, traffic
  fields, observation point, and node; used for overview and policy input.

Community ID is optional because not every source/event can derive it. Matching by
the same value is exact; all other cross-record association is query output marked
`attribute-time` and is not written back as fact.

## 6. Trigger Snapshot

An immutable subset of the source event embedded in a policy-created CaptureJob.

| Field | Rule |
|---|---|
| `source` | `SuricataAlert` or `HubbleDrop`. |
| `fingerprint` | SHA-256 over canonical safe fields; never raw payload. |
| `eventTime` / `observedAt` | Both retained. |
| `flow` | Available addresses, ports, protocol, direction, Community ID. |
| `suricata` | Rule ID, revision, severity, category, message. |
| `hubble` | Verdict, drop reason, source/destination namespace and workload. |

The snapshot never contains packet payload, HTTP body, credentials, full raw EVE
JSON, or the complete Hubble protobuf.

## 7. Policy Decision and Cursor

Internal state, not additional public resources.

- A **PolicyDecision** is emitted as structured audit/operational JSON and updates
  CapturePolicy status counters. Its outcome is `NotMatched`, `Created`,
  `Duplicate`, `RateLimited`, `Disarmed`, or `Failed`.
- A **SuricataCursor** stores the last fully processed timestamp plus fingerprints
  at that timestamp in a controller-owned ConfigMap. Queries overlap the cursor;
  fingerprint deduplication makes replay safe.
- Hubble reconnect state stores the last observed event time. Threshold windows
  rebuild from replayable Relay history when available; any loss event creates a
  visible source-gap condition.

Neither cursor is evidence authority; Loki/Hubble and CaptureJobs remain the
source records. Cursor loss causes safe replay and deduplication, not skipped data.

## 8. AuditRecord

A sanitized, append-only structured JSON record committed to the private object
ledger before a successful security-sensitive action is reported. Loki receives a
searchable replayed copy and is not the durability authority.

| Field | Meaning |
|---|---|
| `recorded_at` | Trawl system time. |
| `actor.username`, `actor.uid`, `actor.groups` | Admission or TokenReview identity; groups may be filtered. |
| `action` | Create/update/delete/arm/disarm/capture/download/retention/expire. |
| `resource` | API group, kind, namespace, name, UID when known. |
| `decision` | Allowed, denied, succeeded, or failed. |
| `reason` | Stable low-cardinality reason. |
| `request_id` | Correlation ID, structured metadata rather than label. |
| `schema_version`, `stable_key` | Versioned format and idempotency identity derived from the admission UID or automatic action. |
| `ledger_key`, `committed_at` | Controller-derived opaque object reference and verified durable-commit time. |

Audit records exclude token material, presigned URLs, storage credentials, packet
payload, and unbounded request bodies. Conditional creation makes an identical retry
successful and a conflicting retry an observable integrity error. Ledger retention
defaults to 365 days, is installation-controlled within 90–730 days, and is enforced
by the object store before lifecycle deletion.

## Ownership and Deletion Matrix

| Parent action | Owned runtime resources | Historical CaptureJobs | Artifact | Observations/audit ledger |
|---|---|---|---|---|
| Delete NetworkTap | Stop and remove tap workload/config/RBAC only | Preserve | Preserve to deadline | Preserve per Loki retention |
| Delete CapturePolicy | Stop future evaluation | Preserve | Preserve to deadline | Preserve |
| Delete CaptureJob before expiry | Admission denies by default; explicit admin override requires security/audit path | N/A | Preserve or explicitly purge under override | Preserve metadata/audit |
| Reach retention deadline | No effect on tap/policy | Mark non-downloadable then `Expired` | Delete and verify within 24h | Preserve non-sensitive execution/audit metadata |
| Uninstall Trawl | Stop managed processes/workloads | Preserve by default | Preserve by default | Preserve by platform policy |
