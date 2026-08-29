# Implementation Plan: Trawl MVP

**Branch**: `001-cloud-native-nsm` | **Date**: 2026-08-29 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/001-cloud-native-nsm/spec.md` and
architecture authority from the repository root `spec.md`.

## Summary

Deliver Trawl as a passive, Kubernetes-native network security monitoring
operator for Talos Linux. Operators declare namespaced `NetworkTap` resources for
physical mirror or node interfaces; Trawl reconciles bounded Suricata and Zeek
workloads and ships a normalized observation envelope through Alloy to Loki.
Analysts investigate exact Community ID correlations in Grafana and request
bounded `CaptureJob` executions. Armed `CapturePolicy` resources create the same
execution type from qualifying Suricata alerts or denied Hubble flows, with
persistent deduplication and rate limits. Captures run as short-lived, node-pinned
dumpcap Jobs, are verified in private MinIO-compatible storage, expire on schedule,
and are downloaded only through a Kubernetes-authorized gateway/CLI. Security-
sensitive actions commit first to an immutable object-backed audit ledger whose
records are then forwarded to Loki.

The MVP deliberately excludes pod injection, TLS decryption, inline prevention,
CRD-based content lifecycle management, scheduled/anomaly triggers, and packet
replay.

## Technical Context

**Language/Version**: Go 1.26.7 for Trawl binaries; Suricata 8.0.6; Zeek 8.0.10
LTS; pcapng produced by the reviewed dumpcap release in the capture-runner image.

**Primary Dependencies**: Kubebuilder 4.15.0 Go v4 scaffold; controller-runtime
0.24.1; Kubernetes Go libraries 0.36.0; Cilium/Hubble Observer gRPC API matching the
deployed Cilium release; gRPC-Go; MinIO Go SDK v7; Prometheus Go client; existing
Grafana Alloy, Loki, Grafana, Cilium/Hubble, and MinIO-compatible services.

**Storage**: Kubernetes etcd through CRDs for desired state and execution/status
metadata; Loki TSDB schema v13+ for observations and searchable audit copies; one
MinIO/S3 service with separate private artifact and audit-ledger buckets, distinct
credentials, and backend-enforced versioning/write-once retention on the ledger;
bounded `emptyDir` only for in-flight analyzer logs, capture files, and the runner-
to-reporter protocol.

**Testing**: Go `testing`, fuzz tests, envtest, controller-runtime fake clock/client
where appropriate, golden schema/dashboard tests, real analyzer and MinIO
integration tests, Hubble gRPC fixtures, and a disposable Kubernetes end-to-end
cluster plus the representative Talos homelab acceptance run.

**Target Platform**: Talos Linux Kubernetes 1.35-1.37 on Linux amd64/arm64 nodes,
Cilium with Hubble Relay, and a dedicated physical mirror NIC where configured.

**Project Type**: Multi-binary Kubernetes operator and infrastructure workloads,
with generated CRDs/RBAC, an internal HTTPS artifact gateway, observability
configuration, and Grafana dashboards.

**Performance Goals**:

- First observation within 15 minutes of applying a valid tap.
- 95% of valid tap reconciliations reach truthful status within 2 minutes.
- Less than 1% capture-boundary packet loss at 100 Mb/s for 60 minutes.
- 95% of valid observations searchable within 30 seconds.
- At least 18 of 20 timed exact-correlation pivots complete within 3 minutes.
- 95% of manual captures begin within 10 seconds and become downloadable within
  60 seconds after capture ends when storage is healthy.
- Capture size overshoot no greater than 1 MiB and no duplicate execution within
  a cooldown bucket.

**Constraints**:

- Passive and fail-open with respect to monitored traffic; no packet-path changes.
- No host installation, SSH, interactive repair, hostPath artifact storage, or
  floating image tags.
- Every capture has positive duration and size bounds; automatic capture also has
  cooldown, hourly rate, deduplication, and retention bounds.
- Packet data, credentials, bearer tokens, presigned URLs, and raw malformed
  records never appear in logs, metrics, status, or Kubernetes Events.
- High-cardinality values remain JSON fields/Loki structured metadata, never
  indexed labels or Prometheus labels.
- A single component, source, analyzer, policy, capture, or storage failure cannot
  stop independent active monitoring.
- Analyzer pods require outbound access to upstream detection feeds at startup;
  custom content is pulled from a cluster-local OCI registry. No runtime internet
  access is required after init containers complete.

**Scale/Scope**: One trusted homelab cluster, tens of nodes and taps rather than
multi-tenant fleet scale, sustained observed traffic up to the 100 Mb/s reference
load, three public CRD kinds, four user stories, and the analyzers/observation types
listed in the feature specification.

## Constitution Check

*GATE: Passed before Phase 0 research; re-evaluated and passed after Phase 1 design.*

| Principle or constraint | Design evidence | Initial gate | Post-design gate |
|---|---|---:|---:|
| I. Passive and Fail-Open | AF_PACKET/libpcap observation only; no routes, policies, NFQUEUE, or inline hooks; analyzer and control failures do not touch the packet path. | PASS | PASS |
| II. Declarative Control and Truthful State | Three versioned CRDs, structural validation, idempotent reconcilers, `observedGeneration`, standard conditions, verified artifact state, explicit ownership/finalizer cleanup. | PASS | PASS |
| III. Evidence Integrity and Least Privilege | Explicit Linux capabilities, enforced system namespace, separate private buckets/credentials, checksums, immutable trigger snapshots, Kubernetes RBAC, short presigned URLs, bounded retention, and a versioned write-once audit ledger. | PASS | PASS |
| IV. Observable and Correlatable | Common observation envelope, Community ID, original/observed timestamps, health/conditions/metrics, explicit loss/rejection/suppression/storage signals, bounded labels. | PASS | PASS |
| V. Verification at Every Boundary | Unit, schema, webhook, reconciliation, analyzer, Hubble, Loki, MinIO, authorization, restart, load, and end-to-end validation are part of the plan. | PASS | PASS |
| VI. Small, Phased, Reversible Delivery | MVP-only source types and triggers; existing platform reused; direct mirror capture; deterministic generated resources; rollback and cleanup behavior defined below. | PASS | PASS |
| Talos/Kubernetes baseline | All functions run as managed workloads; no host packages or shell dependency. | PASS | PASS |
| Approved technology baseline | Cilium/Hubble, Suricata, Zeek, Alloy/Loki, Grafana, and MinIO are reused; no replacement store or analyzer. | PASS | PASS |
| Go and API compatibility | Go controller-runtime implementation; namespaced `trawl.cloud/v1alpha1`; structural schemas and conversion-ready version layout. | PASS | PASS |
| Privileged workload isolation | Admission, manager cache, and RBAC accept Trawl CRs only in configured `trawl-system`; capture containers receive only reviewed capabilities; control-plane pods remain Restricted-compatible. | PASS | PASS |
| Immutable supply chain | Analyzer binaries are digest-pinned; upstream rules are fetched by init containers with logged feed timestamps; custom content uses OCI digest references; all content versions are reported in target health status; generated artifacts are drift-checked. | PASS | PASS |

No constitutional exception is required. Security review is mandatory before
merging CRD schemas, RBAC, admission, privileged workload templates, BPF filter
handling, artifact access, or retention behavior.

## Design Divergences from Root Architecture Document

The root `spec.md` was the initial design sketch. This plan refines it in several
areas. These are intentional and documented here to prevent confusion.

1. **Five binaries instead of one operator**: The architecture doc shows a single
   Trawl Operator. This plan splits it into controller-manager, event-worker,
   sensor-agent, capture-runner, and artifact-gateway for privilege and lifecycle
   isolation.

2. **No owner references from CapturePolicy to CaptureJob**: The architecture doc
   shows CaptureJob with ownerReferences pointing to CapturePolicy. This plan
   forbids that — forensic evidence must not be garbage-collected when a policy is
   deleted.

3. **Restricted template placeholders instead of Go templates**: The architecture
   doc uses `{{.Alert.SrcIP}}` syntax. This plan uses a closed set of typed
   placeholders (`{{source.ip}}`) with no functions, loops, or expressions for
   security.

4. **Installation-level storage config instead of per-policy**: The architecture
   doc puts MinIO endpoint/bucket config on each CapturePolicy. This plan uses a
   single installation-level storage profile referenced by all captures.

5. **Artifact gateway**: Not in the architecture doc. Required for authorized,
   audited pcap downloads with short-lived presigned URLs.

6. **Sensor agent normalization layer**: The architecture doc has Alloy scraping
   raw Suricata/Zeek JSON. This plan interposes a sensor-agent sidecar for
   normalized observation envelopes, health reporting, and sensitive-field
   redaction before logs reach Alloy.

7. **Analyzer content lifecycle**: The architecture doc includes a suricata-update
   CronJob. This plan uses init containers for upstream refresh and OCI artifacts
   for git-managed custom content, fitting the immutable Talos and gitops model.

## Architecture and Data Flow

```text
NetworkTap ──reconcile──▶ per-tap Deployment/DaemonSet
                              │
                  ┌───────────┼───────────┐
                  ▼           ▼           ▼
              Suricata      Zeek    trawl-sensor-agent
                  │           │           │
                  └── JSON files ─────────┤
                                          ├── normalized JSON stdout ─▶ Alloy ─▶ Loki ─▶ Grafana
                                          └── target health ──────────▶ NetworkTap/status

Suricata alerts in Loki ─┐
                         ├─▶ trawl-event-worker ─▶ CapturePolicy match/dedupe ─▶ CaptureJob
Hubble Relay GetFlows ───┘                                                        │
                                                                                  ▼
Manual CaptureJob ──────────────────────────────────────────────────────────▶ node-pinned Job
                                                                                  │
                                                   dumpcap ─▶ progress files ─▶ reporter
                                                                 │                 │
                                                       SHA-256/upload              ▼
                                                                 │          CaptureJob/status
                                                                 ▼                 │
                                                                MinIO ◀── verify ─ controller
       │
       └── authorized CLI/API request ─▶ artifact gateway ─▶ short presigned download

Admission/controllers/worker/gateway ─▶ mTLS audit sink ─▶ immutable MinIO ledger
                                                               │
                                                               └─▶ Alloy ─▶ Loki
```

### Control-plane processes

1. `trawl-controller-manager` hosts NetworkTap and CaptureJob reconcilers,
   retention reconciliation, admission/defaulting webhooks, the mTLS audit sink and
   ledger forwarder, leader election, and standard health/metrics endpoints.
2. `trawl-event-worker` independently consumes Hubble flows and Loki alerts, emits
   normalized cluster-flow observations, evaluates CapturePolicy objects, and
   creates deterministic CaptureJobs. Its failure does not stop existing taps or
   manual capture reconciliation.
3. `trawl-artifact-gateway` authenticates and authorizes download requests, checks
   live execution/retention state, issues short presigned URLs, and audits every
   decision.
4. `trawl-sensor-agent` runs only inside generated analyzer pods, normalizes
   records, reports component health, and patches its owning target status. Its
   resource requirements are set by installation-level configuration and rendered
   by the operator into the pod spec alongside the user-configured analyzer
   resources.
5. `trawl-capture-runner` exists only in short-lived capture Jobs and performs
   validation, bounded collection, checksum/count generation, and idempotent
   upload.
6. `trawl-capture-reporter` is an unprivileged sidecar in each capture Job. It
   validates the runner's bounded progress protocol and may patch only its owning
   CaptureJob status with a projected short-lived token.

### NetworkTap reconciliation

1. Reject resources outside the configured system namespace, then validate passive
   mode, one supported source union, interface syntax, selectors,
   at least one analyzer, and complete resource requests/limits.
2. Resolve eligible nodes. A mirror selector must match exactly one node; a node
   interface selector may match one or more. Missing interfaces remain observable
   through sensor-agent readiness rather than being guessed by the controller.
3. Render deterministic names from the tap UID and set owner references on the
   workload/config/service-account resources.
4. Render init containers for upstream rule/script refresh (suricata-update, Zeek
   base scripts) writing to a shared `emptyDir` volume. When the NetworkTap's
   analyzer config includes a custom content OCI reference, render a second init
   container that pulls and overlays custom content. The analyzer containers read
   merged content from the shared volume.
5. Roll analyzer configuration on spec generation changes. Each target reports
   analyzer-specific readiness, last packet time, packet/drop counters, and
   sanitized failure reasons through status.
6. Aggregate target status: `Active` only when every selected target and requested
   analyzer is healthy; `Degraded` for partial health; `Error` for invalid or
   wholly unavailable dependencies; `Pending` while unresolved or rolling out.
7. On deletion, stop only owned workloads and remove per-tap access. Historical
   observations, CaptureJobs, and artifacts remain under their independent
   retention rules.

### Observation processing

The sensor agent emits `trawl.observation/v1alpha1` records described in
`contracts/observation.schema.json`. It preserves analyzer-native details needed
for signature, connection, DNS, HTTP, TLS, certificate, file, notice, and unusual
traffic investigation while enforcing a common source, target, timestamp, and
flow envelope. Unsupported or malformed records increment counters and produce a
sanitized diagnostic hash; valid neighboring records continue.

A bounded rolling fingerprint cache marks suspected duplicate observations and
increments per-target duplicate counters without discarding raw evidence. Dashboards
display observation counts and the duplicate signal; the MVP does not infer or
create incident records.

The duplicate fingerprint hashes the tap UID, target, source kind, observation type,
direction-normalized five-tuple, event time rounded to one millisecond, and available
analyzer-stable record fields. A repeat within one second is marked suspected. Each
target cache is capped at 100,000 entries; eviction or missing fingerprint fields
produces `Unknown` rather than a false `NotDetected` result.

Alloy keeps only bounded labels. Required search fields are structured metadata
and JSON fields. Exact investigation pivots use Community ID; fallback queries
normalize endpoint direction and use a documented time tolerance while visibly
marking results approximate.

### Policy evaluation and execution creation

CapturePolicy supports exactly two automatic trigger unions in this MVP:
Suricata signature alerts and denied Hubble flows. Matching logic is deterministic
and has no side effects until it requests a CaptureJob. Each decision updates
policy counters and emits an auditable reason: non-match, created, duplicate,
rate-limited, disarmed, or failed.

The deduplication identity is based on the traffic and source, not the triggering
policy. If several policies produce an equivalent request during the applicable
cooldown bucket, the first creates the execution and later policies record a
suppression reference. The originating execution retains an immutable policy UID,
generation, trigger fingerprint, event timestamp, observation timestamp, traffic
context, and resolved bounds. Hourly counts and cooldown state are reconstructed
from persisted CaptureJobs after restart.

### Capture and artifact lifecycle

CaptureJob is both the manual request API and immutable execution record. The
webhook permits an analyst to supply only manual fields; policy identity and
trigger context are accepted only from the event worker. Execution fields are
immutable after create. An authorized retention administrator may shorten or
extend only `spec.retention` within the deployment's 30-day ceiling before expiry;
the change is audited and can never resurrect expired evidence. The reconciler
resolves the exact active tap target before opening a capture socket.

The lifecycle is:

```text
Pending ─▶ Capturing ─▶ Storing ─▶ Completed ─▶ Expired
   │            │           │
   └────────────┴───────────┴────▶ Failed
```

- `Pending`: admitted, validating filter/target, or waiting for the Kubernetes Job.
- `Capturing`: the reporter has observed the runner's atomic `CaptureStarted` record,
  emitted only after the interface socket opens, and patched the actual start time.
- `Storing`: the reporter has observed `CaptureEnded` and upload/verification is in
  progress.
- `Completed`: object existence, size, and SHA-256 metadata are verified.
- `Failed`: a terminal, sanitized reason is present; no download is exposed.
- `Expired`: downloads were denied at the deadline and object deletion was verified.

The controller uses a stable Kubernetes Job name and stable object key derived from
the CaptureJob UID. Reconciliation observes existing Jobs and objects before
creating or uploading, making restart retries converge to one execution and one
artifact. A missing or inconsistent object can never produce `Completed`.

The runner and reporter share only a bounded `emptyDir`. The reporter owns live
progress fields through server-side apply; the controller owns aggregate conditions
and terminal state. The runner has no Kubernetes API token, while the reporter's
generated Role is restricted by `resourceNames` to the owning CaptureJob `/status`.

### Audit lifecycle

The controller manager exposes an internal mTLS audit sink to the admission path,
event worker, reconcilers, retention worker, and artifact gateway. Each client
submits a sanitized versioned record whose stable key is derived from the admission
UID or automatic action identity. The sink conditionally writes the record under a
separate private audit-ledger bucket under `audit/v1/` and verifies it with HEAD before
acknowledging. A retry with the same content is successful; conflicting content for
the same key is rejected and alerted.

User mutations and successful download authorization complete only after this
acknowledgement. Controllers commit audited lifecycle/status changes only after it;
artifact expiry records are durable before deletion begins. The sink emits committed
records to stdout and replays the object ledger to Loki after delivery outages.
Ledger backlog, conflicts, write failure, replay lag, and retention failure are
bounded metrics/conditions. Audit objects have installation-controlled bounded
retention longer than capture retention and are never requester-addressable.

An action that can fail after authorization has separate stable `allowed` intent and
`succeeded`/`failed` outcome records. Replay uses a persisted ConfigMap cursor plus
an overlap window. Duplicate Loki delivery copies keep the same `stable_key` and are
collapsed by audit views; the immutable ledger remains authoritative.

## Project Structure

### Documentation (this feature)

```text
specs/001-cloud-native-nsm/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   ├── artifact-api.openapi.yaml
│   ├── crd-api.md
│   ├── observation.schema.json
│   └── telemetry.md
└── tasks.md                         # created by /speckit.tasks, not this command
```

### Source Code (repository root)

```text
api/
└── v1alpha1/
    ├── groupversion_info.go
    ├── networktap_types.go
    ├── capturepolicy_types.go
    ├── capturejob_types.go
    └── zz_generated.deepcopy.go

cmd/
├── controller-manager/main.go
├── event-worker/main.go
├── sensor-agent/main.go
├── capture-runner/main.go
├── artifact-gateway/main.go
└── trawlctl/main.go

internal/
├── admission/                       # defaulting, cross-field and caller validation
├── audit/                           # durable ledger client/sink, replay, stable keys
├── authz/                           # TokenReview and SubjectAccessReview
├── capture/                         # bounds, filter rendering, runner protocol, manifest
├── content/                         # upstream fetch, OCI pull, merge, version reporting
├── controller/                      # NetworkTap and CaptureJob reconciliation, retention
├── events/                          # Hubble/Loki clients, cursors, normalized trigger input
├── observation/                     # Suricata/Zeek normalization and correlation fields
├── policy/                          # pure match, threshold, dedupe, cooldown, hourly limit
├── status/                          # phases, conditions, per-target merge helpers
└── storage/                         # private S3 operations and object verification

config/
├── audit/                            # internal mTLS sink service and client policy
├── content/                         # default upstream feed URLs, refresh schedule
├── crd/bases/                       # generated CRDs
├── default/                         # install overlay
├── manager/                         # controller and event-worker deployments
├── gateway/                         # artifact gateway service
├── rbac/                            # operator, worker, gateway, analyst/operator roles
├── webhook/                         # admission service and certificates
├── samples/                         # MVP tap, policy, and manual capture examples
├── analyzers/                       # Suricata/Zeek base configuration
├── alloy/                           # processing and structured-metadata stages
└── grafana/                         # four dashboards and non-secret CLI action hints

images/
├── suricata/                        # verified upstream build, rules loaded at startup
├── zeek/                            # LTS build, scripts loaded at startup
├── content-init/                    # suricata-update + zeek pkg tooling for init container
└── capture-runner/                  # dumpcap and Trawl runner

test/
├── fixtures/                        # synthetic EVE, Zeek, Hubble, and pcap data
├── integration/                     # analyzers, gRPC, Loki, MinIO, audit, auth, capture boundaries
└── e2e/                             # disposable cluster and Talos acceptance scenarios

docs/src/content/docs/
├── adr/                             # irreversible choices and rollback implications
├── operations/                      # health, loss, storage, retention, recovery runbooks
└── security/                        # privilege, RBAC, evidence handling, threat review
```

**Structure Decision**: Use one Go module with several narrowly scoped binaries
sharing internal domain packages. Keep generated Kubernetes installation artifacts
under `config/`, analyzer supply-chain definitions under `images/`, and boundary
tests under `test/`. This preserves one coherent API/domain model without coupling
the privileged data plane to the control-plane process lifecycle.

## Phase 0: Research Outcome

All technical unknowns are resolved in [research.md](research.md), including
versions, supported Kubernetes range, workload topology, privileges, analyzer
supply chain, normalization, correlation, trigger replay, deduplication, capture
bounds, object lifecycle, download authorization, audit, and verification. There
are no remaining `NEEDS CLARIFICATION` markers.

## Phase 1: Design Outcome

- [data-model.md](data-model.md) defines public resources, internal records,
  relationships, validation, lifecycle, and ownership.
- [contracts/crd-api.md](contracts/crd-api.md) fixes the `trawl.cloud/v1alpha1`
  desired-state and status contract.
- [contracts/observation.schema.json](contracts/observation.schema.json) defines the
  normalized Loki record envelope.
- [contracts/artifact-api.openapi.yaml](contracts/artifact-api.openapi.yaml) defines
  the authenticated download exchange.
- [contracts/telemetry.md](contracts/telemetry.md) fixes label, metric, condition,
  and audit boundaries.
- [quickstart.md](quickstart.md) defines runnable end-to-end validation scenarios.

## Requirement Traceability

| Requirement area | Primary design elements | Validation boundary |
|---|---|---|
| FR-001–008 Traffic sources | NetworkTap schema/webhook, reconciler, per-tap workloads, target status, finalizer | Schema + envtest + cluster interface/failure tests |
| FR-009–016 Analysis | Analyzer images, sensor agent, observation schema, Alloy/Loki, Community ID, Grafana | Real analyzer fixtures + malformed isolation + Loki queries |
| FR-017–025 Capture/storage | CaptureJob, capture runner, dumpcap bounds, S3 verifier, gateway, retention reconciler | Filter/bounds tests + real capture + MinIO/auth/expiry tests |
| FR-026–034 Event-driven capture | CapturePolicy, event worker, Loki cursor, Hubble stream, pure matcher, persistent dedupe/rate accounting | Unit/property tests + replay/restart + real boundary integration |
| FR-035–040 Safety/operations | Namespace enforcement, RBAC, admission identity, explicit capabilities, durable audit ledger, conditions/metrics, deterministic names | Security review + authorization + audit-outage + restart/failure-injection E2E |
| FR-041–045 Analyzer content | Content init containers, upstream feed fetch, OCI custom overlay, merge precedence, scheduled analyzer rollout, feed/digest reporting in target status | Content unit tests + init-container integration + corrupt/missing fallback + status currency checks |

## Delivery, Upgrade, Rollback, and Cleanup

1. Deliver vertical slices in user-story order: active tap and observations;
   investigation; manual capture and download; automatic capture. Each slice must
   remain runnable and independently verified before the next begins.
2. Treat `v1alpha1` stored fields as compatibility commitments within that version.
   Additive schema changes require defaulting and old-object tests. A breaking
   shape requires a new served/storage version and conversion plan.
3. Roll analyzer workloads by immutable digest through NetworkTap generation
   changes. Roll back by restoring the prior digest/config revision; observations
   and captures remain readable because their schema version is explicit.
4. Roll back the operator only to a release that serves every stored API version.
   CRDs are never removed as part of a routine application rollback.
5. Uninstall stops event-worker/control/gateway processes and tap workloads after
   explicit confirmation. It does not delete CRDs, CaptureJobs, Loki data, or
   artifacts by default. A separate documented purge path enumerates exact objects
   and retention implications.
6. Before implementation, record ADRs for the normalized envelope, persistent
   trigger/dedup semantics, central artifact storage plus authorization gateway,
   capability-minimized packet capture, and the two-layer analyzer content model.

## Complexity Tracking

No constitution violations require justification. The five workload binaries are
deployment roles around one shared Go domain, and `trawlctl` is a client CLI. The
capture-runner binary also provides the unprivileged reporter entrypoint used by its
sidecar. Each boundary exists to isolate a required privilege, availability, or
lifecycle concern rather than create a separate product service.
