# Phase 0 Research: Trawl MVP

**Feature**: `001-cloud-native-nsm`  
**Date**: 2026-08-29  
**Architecture authority**: [`../../spec.md`](../../spec.md)

This document resolves the technical choices needed to plan the MVP. Versions are
the reviewed baseline as of the planning date; release manifests must pin image
digests and Go module checksums rather than floating tags.

## 1. Operator toolchain and Kubernetes compatibility

**Decision**: Build the control-plane binaries with Go 1.26.7, Kubebuilder 4.15.0,
`controller-runtime` 0.24.1, and Kubernetes Go libraries 0.36.0. Test against
Kubernetes 1.35, 1.36, and 1.37;
the deployed Talos cluster version must be one of those supported minors before
installation.

**Rationale**: Go 1.26 is a supported, patched toolchain and is the minimum line
used by controller-runtime 0.24. Kubernetes libraries 0.36 align exactly with
Kubernetes 1.36 while using stable APIs shared by the supported server range. The
MVP needs generated structural CRDs, `/status` subresources, admission webhooks,
leader election, and controller reconciliation rather than a custom control loop.

**Alternatives considered**:

- Go 1.27: released only ten days before this plan; defer adoption until the
  controller ecosystem and build images have a stabilization window.
- Operator SDK: capable, but adds no requirement beyond Kubebuilder's Go plugin.
- A scripting-language operator: conflicts with the constitution's Go requirement.

**Sources**: [Go release history](https://go.dev/doc/devel/release),
[Kubebuilder 4.15.0 release](https://github.com/kubernetes-sigs/kubebuilder/releases/tag/v4.15.0),
[controller-runtime compatibility](https://github.com/kubernetes-sigs/controller-runtime),
[Kubebuilder CRD generation](https://book.kubebuilder.io/reference/generating-crd.html),
[Kubernetes supported versions](https://kubernetes.io/releases/version-skew-policy/).

## 2. API shape and reconciliation

**Decision**: Expose three namespace-scoped `trawl.cloud/v1alpha1` resources:
`NetworkTap`, `CapturePolicy`, and `CaptureJob`. Generate structural OpenAPI
schemas, use CEL for representable cross-field rules, and use a fail-closed
validating webhook for identity-aware and environment-dependent checks. All three
resources use `/status`, `observedGeneration`, standard conditions, and immutable
execution fields where applicable.

Although the CRDs are discoverable cluster-wide, the MVP accepts resources only in
the installation-configured system namespace (`trawl-system` by default). The
manager cache and namespaced Roles are scoped there, and the validating webhook
rejects every off-namespace Trawl resource before evaluating its remaining fields.
This makes the namespace containing privileged analyzer/capture workloads an
explicit API boundary rather than an example-only convention.

`NetworkTap` owns only its ServiceAccount, narrowly scoped Role/RoleBinding,
configuration, Service, and analyzer Deployment or DaemonSet. A qualified
`trawl.cloud/finalizer` stops owned monitoring workloads and restores any
controller-managed interface state; it never deletes observations, CaptureJobs,
or artifacts.

**Rationale**: Kubernetes validation rejects bad desired state early, while status
updates remain controller-owned and independent from spec updates. Owner
references handle ordinary in-cluster dependents; a finalizer is required only for
cleanup that garbage collection cannot prove.

**Alternatives considered**:

- Cluster-scoped resources: unnecessary for a single-organization MVP and harder
  to delegate safely.
- Persisting runtime truth in annotations: mixes desired and observed state and
  makes retries unsafe.
- Additional target-binding and storage-profile CRDs: useful later, but not needed
  for the current three-resource contract.

**Sources**: [Kubebuilder status subresource](https://book.kubebuilder.io/reference/markers/crd.html),
[Kubebuilder validation](https://book.kubebuilder.io/reference/markers/crd-validation.html),
[Kubebuilder admission webhooks](https://book.kubebuilder.io/reference/admission-webhook),
[Kubernetes finalizers](https://kubernetes.io/docs/concepts/overview/working-with-objects/finalizers/).

## 3. Tap workload topology

**Decision**: Reconcile one workload per `NetworkTap`:

- `mirror-interface` becomes a single-replica Deployment pinned by a selector that
  must resolve to exactly one eligible node.
- `node-interface` becomes a DaemonSet on all eligible selected nodes.

Each pod shares the host network namespace and the declared interface. Enabled
Suricata and Zeek containers capture the interface directly; no mirror-broker pod
or packet-forwarding overlay is introduced. A small `trawl-sensor-agent` sidecar
normalizes analyzer files to JSON on stdout, reports per-analyzer health and packet
counters, and patches only its own target entry in `NetworkTap/status`.

**Rationale**: Direct co-located capture is the smallest design that preserves the
packet source and avoids another privileged hop. A per-tap workload gives clear
ownership, rollout, resource limits, and failure attribution. The sensor agent is
required to satisfy truthful per-mode health, rejected-record counts, last-packet
time, and a common observation envelope.

**Alternatives considered**:

- A mirror receiver that rebroadcasts packets: adds packet copies, MTU and loss
  failure modes without value when analyzers can bind the mirror NIC directly.
- One global analyzer DaemonSet: cannot independently reconcile interfaces,
  analyzers, limits, ownership, and status for multiple taps.
- Pod injection: explicitly outside this MVP.

## 4. Capture privileges and passive behavior

**Decision**: Label only `trawl-system` for the privileged Pod Security profile,
then harden each workload individually. Analyzer and capture containers use
`hostNetwork: true`, drop all capabilities, add only `NET_RAW` and `NET_ADMIN`,
set `allowPrivilegeEscalation: false`, use `RuntimeDefault` seccomp, mount a
read-only root filesystem where the upstream tool permits it, and receive no
Kubernetes token. `SYS_NICE` may be added only after a measured need and security
review. Do not set `securityContext.privileged: true` by default.

The configured system namespace is the only namespace in which Trawl resources are
admitted or reconciled. Changing it is an installation operation that updates the
namespace label, namespaced RBAC, manager cache, and webhook configuration together;
it is not selectable by a CR author.

The sensor agent alone receives a projected, short-lived service-account token.
Its generated Role is restricted with `resourceNames` to the owning NetworkTap's
status subresource. The operator and event worker run under the Restricted Pod
Security profile and have no host namespace access.

**Rationale**: Host-network packet capture requires elevated network capabilities,
but full privilege grants every Linux capability and bypasses important runtime
controls. Passive sockets observe copies; no component installs routes, firewall
rules, Cilium policies, or inline hooks.

**Alternatives considered**:

- Fully privileged containers: broader than the required packet-capture boundary.
- Host package installation or system extensions: incompatible with Talos and the
  immutable-host constraint.
- Reusing capture capability for IPS: constitutionally prohibited in this feature.

**Sources**: [Kubernetes Linux kernel security constraints](https://kubernetes.io/docs/concepts/security/linux-kernel-security-constraints/),
[Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/),
[RuntimeDefault seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/).

## 5. Analyzer and rule supply chain

**Decision**: Baseline on Suricata 8.0.6 and Zeek 8.0.10 LTS. Build
Trawl-maintained analyzer images from verified upstream releases, package a
reviewed ET Open/custom rule snapshot and approved Zeek scripts into immutable
images or ConfigMaps, and record source checksums and final image digests. Analyzer
versions, rules, and scripts change only through a reviewed deployment update.

**Rationale**: These are the current stable/LTS maintenance releases. Packaging
the effective rules and scripts makes rollbacks deterministic and prevents an
unreviewed daily rule download from changing detection behavior underneath an
otherwise unchanged release.

**Alternatives considered**:

- `latest` image tags: prohibited by the constitution and not reproducible.
- A daily `suricata-update` CronJob: mutable and outside the MVP's deferred
  user-managed rule lifecycle.
- Feature-release Zeek 8.2: less conservative than the maintained LTS line.

**Sources**: [Suricata stable download](https://suricata.io/download/),
[Zeek current LTS](https://zeek.org/get-zeek/),
[Suricata source verification](https://docs.suricata.io/en/suricata-8.0.0/verifying-source-files.html).

## 6. Observation normalization, transport, and search

**Decision**: Suricata writes EVE JSON and Zeek writes JSON log files to a
pod-local `emptyDir`. `trawl-sensor-agent` tails both, validates supported record
types, adds the `trawl.observation/v1alpha1` envelope, writes one JSON object per
line to stdout, and quarantines only a bounded diagnostic fingerprint for rejected
records. Existing Alloy Kubernetes log collection ships those lines to Loki.

Use only bounded labels (`service_name`, `source_kind`, `observation_type`, and
cluster). Store tap UID, node, addresses, ports, rule IDs, Zeek UID, Community ID,
and other unbounded fields as structured metadata and in the JSON body. Require
Loki TSDB schema v13 or later with structured metadata enabled. Dashboards retain
a JSON-parser fallback so a record remains inspectable if selected metadata was
not promoted.

**Rationale**: A common envelope gives every record event time, observation time,
tap, target, type, flow fields, and analyzer-specific details. Loki remains the
existing durable query plane without cardinality explosion. Malformed input is
isolated before it can poison the rest of the stream.

**Alternatives considered**:

- Indexing IPs, rule IDs, UIDs, or Community IDs as Loki labels: creates unbounded
  stream cardinality.
- Elasticsearch or a new event database: duplicates an approved platform
  capability.
- Emitting raw analyzer formats only: cannot guarantee the common fields or stable
  cross-source queries required by the feature.

**Sources**: [Loki structured metadata](https://grafana.com/docs/loki/latest/get-started/labels/structured-metadata/),
[Loki label guidance](https://grafana.com/docs/loki/latest/get-started/labels/),
[Alloy Kubernetes log source](https://grafana.com/docs/alloy/latest/reference/components/loki/loki.source.kubernetes/).

## 7. Correlation

**Decision**: Enable Community ID v1 with seed `0` and base64 encoding in both
Suricata and Zeek. Preserve the analyzers' value verbatim as `flow.community_id`.
Grafana marks a shared value as an exact match. When absent, the investigation view
uses a bounded time window plus protocol, normalized endpoint pair, and ports, and
labels the result `attribute-time` rather than exact.

**Rationale**: Community ID is already implemented by both analyzers and avoids a
custom hash. Original event and observation timestamps remain separate so clock
skew is visible.

**Alternatives considered**:

- Zeek UID: not generated by Suricata.
- A Trawl-specific flow hash: unnecessary incompatibility with standard tooling.
- Treating five-tuple/time matches as exact: misrepresents ambiguous evidence.

**Sources**: [Suricata Community Flow ID](https://docs.suricata.io/en/suricata-8.0.4/output/eve/eve-json-output.html),
[Zeek Community ID logging](https://docs.zeek.org/en/lts/scripts/policy/protocols/conn/community-id-logging.zeek.html).

## 8. Event-driven policy evaluation

**Decision**: Run a leader-elected `trawl-event-worker` separately from the
controller manager:

- Subscribe to Hubble Relay's stable `Observer.GetFlows` gRPC stream over TLS and
  process denied flows.
- Poll normalized Suricata alerts from Loki with an overlap window and a persisted
  `(timestamp, fingerprint)` cursor. This favors durable replay over tailing an
  inaccessible node-local file.

Policy matching is pure, deterministic Go. Hourly limits and cooldown decisions
are derived from persisted CaptureJobs, not process memory. A canonical
deduplication key hashes tap UID, selected target, direction-neutral five-tuple,
protocol, and a cooldown bucket. The worker uses deterministic names plus
create-or-get semantics, so retries and leader changes do not create a second
execution. Each policy is evaluated independently; a later equivalent match is
recorded as suppressed and references the existing CaptureJob.

For Hubble threshold policies, the worker reconnects far enough back to rebuild
the active threshold window when the Relay ring still contains it. Lost Hubble
events and Loki query gaps increment explicit metrics and set policy conditions;
the system never claims complete trigger coverage across an observed gap.

**Rationale**: The two approved event sources have different durable semantics.
Persisted cursors and CaptureJobs make retries truthful and provide the state
needed for restart recovery, cooldown, and hourly rate limits.

**Alternatives considered**:

- Tail Suricata files from the central operator: node-local volumes are not
  available to it and restarts lose the tail position.
- Store every alert or flow as a Kubernetes object: inappropriate load on etcd.
- In-memory deduplication: loses correctness on restart or leader failover.

**Sources**: [Hubble internals and GetFlows](https://docs.cilium.io/en/stable/internals/hubble/),
[Hubble gRPC API stability](https://docs.cilium.io/en/stable/grpcapi/),
[Hubble TLS](https://docs.cilium.io/en/stable/observability/hubble/configuration/tls/).

## 9. Capture execution

**Decision**: A `CaptureJob` reconciles to one Kubernetes Job pinned to the
resolved node and interface. A Trawl capture-runner image first validates the BPF
filter with the same libpcap/dumpcap build used for collection, then invokes
`dumpcap` with both `duration` and `filesize` autostop conditions. It writes pcapng
to bounded ephemeral storage, calculates SHA-256 and packet count, uploads the
artifact plus a small manifest to the configured private S3 bucket, and exits.

The runner also writes atomic, versioned, bounded progress/result records to a
pod-local `emptyDir`. A separate unprivileged `trawl-capture-reporter` sidecar reads
only that directory and uses a projected short-lived token to patch only the owning
CaptureJob `/status`, enforced by a generated `resourceNames` Role. The capture
runner receives no Kubernetes token. `CaptureStarted` is reported only after the
socket opens; `CaptureEnded` is reported before upload starts. The controller uses
those field-owned facts for `Capturing` and `Storing`, derives failure from the Job,
and verifies the object with an S3 HEAD before setting `Completed`. Stable names
based on the CaptureJob UID and conditional/idempotent upload semantics prevent
duplicate artifacts. A zero-packet file completes successfully. An invalid filter
fails before opening the capture socket.

**Rationale**: `dumpcap` supports repeatable `duration` and `filesize` autostop
conditions and stops at the first condition. A one-packet overshoot remains below
the specification's 1 MiB allowance under the supported MTU bounds and is verified
at the reference load.

**Alternatives considered**:

- Suricata conditional pcap logging: does not implement the general manual and
  Hubble-triggered lifecycle.
- Long-running capture daemons: increase privilege duration and make cleanup less
  explicit.
- Writing directly to host paths or PVCs: broadens sensitive evidence exposure and
  duplicates object storage.

**Source**: [dumpcap manual](https://www.wireshark.org/docs/man-pages/dumpcap.html).

## 10. Artifact storage, retention, and download

**Decision**: Configure one private artifact bucket at installation; users and
policies choose retention within an allowed range but cannot provide endpoints,
buckets, keys, or credentials. The object key is derived from namespace and
CaptureJob UID. The controller denies download at `retentionDeadline`, runs an
hourly expiry reconciliation, deletes the object, verifies absence, preserves
non-sensitive execution metadata, and transitions the job to `Expired`. A bucket
lifecycle rule provides defense-in-depth cleanup, not authoritative state.

Expose an internal HTTPS artifact gateway and supported `trawlctl capture download`
command. The CLI accepts a bearer-producing kubeconfig exec credential or token on
stdin and never places it in process arguments. The gateway authenticates bearer tokens through
Kubernetes TokenReview and authorizes a SubjectAccessReview for
`get capturejobs/download` in the requested namespace. Only a `Completed`,
unexpired job with a verified object receives a presigned GET URL valid for at most
five minutes and never beyond the retention deadline. Every attempt is audited;
tokens, URLs, object credentials, and packet data are never logged.

Grafana shows capture identity, status, and a non-secret copyable `trawlctl` command
template;
it does not render a live download link in the MVP. A browser link would require an
OIDC/session handoff that is not part of the approved baseline and cannot safely be
implemented by putting a Kubernetes bearer token or presigned URL in a dashboard.

**Rationale**: Central storage configuration prevents CR authors from exfiltrating
captures to arbitrary destinations. Application-side deadline enforcement gives
precise denial semantics even though asynchronous object lifecycle deletion can
lag. The Kubernetes authorization plane remains the single identity policy.

**Alternatives considered**:

- Public buckets or direct permanent MinIO links: bypass authorization and expiry.
- User-controlled S3 destinations: creates an evidence-exfiltration primitive.
- Lifecycle rules alone: deletion is asynchronous and cannot provide exact
  download denial at the deadline.

**Sources**: [MinIO Go presigned operations](https://docs.min.io/aistor/developers/sdk/go/api/),
[S3 lifecycle behavior](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html),
[Kubernetes TokenReview](https://kubernetes.io/docs/reference/kubernetes-api/definitions/token-review-v1-authentication/),
[Kubernetes SubjectAccessReview](https://kubernetes.io/docs/reference/access-authn-authz/authorization/),
[RBAC subresources](https://kubernetes.io/docs/reference/access-authn-authz/rbac/).

## 11. Audit and observability

**Decision**: The controller manager hosts an internal mTLS audit sink backed by an
separate private audit-ledger bucket. Audit clients construct a versioned,
sanitized record with a stable key derived from the AdmissionReview UID or automatic
action ID. The sink uses conditional put and HEAD verification and acknowledges only
after the immutable record is durable. Admission, trigger, controller, retention,
and gateway paths must receive that acknowledgement before reporting or committing
a successful security-sensitive action. User mutations and successful download
authorization fail closed when the ledger is unavailable; monitored traffic remains
fail-open.

The authoritative ledger bucket uses distinct credentials, versioning, and backend-
enforced write-once retention. Its default retention is 365 days, configurable only
at installation from 90 to 730 days. Application IAM denies overwrite and early
delete; lifecycle cleanup applies only after the write-once deadline.
After committing a record, the sink emits its JSON to stdout and replays undelivered
objects so Alloy can maintain the searchable Loki audit stream. Loki unavailability
therefore creates an observable delivery backlog rather than an audit gap. Artifact
expiration records are committed before deletion; if the common durable store is
unavailable, retention reports failure and retries within its existing 24-hour
window. Audit records never include raw CR secrets, rendered credential values,
packet payloads, tokens, query strings, or presigned URLs.

Actions that can fail after authorization use two stable records: an `allowed`
intent committed before the action and a `succeeded` or `failed` outcome committed
after it. The replay worker stores a namespaced ConfigMap cursor and uses an overlap
window; replayed Loki copies retain `stable_key`, and audit views collapse duplicate
delivery copies by that key. The immutable ledger remains the source of truth.

Every component exposes `/healthz`, `/readyz`, Prometheus metrics, structured logs,
and Kubernetes conditions where it owns a resource. High-cardinality identifiers
appear in logs/status, never metric labels.

**Rationale**: Admission is the only application boundary that has both the
requested mutation and authenticated user identity. Loki alone cannot prove audit
durability when its delivery path is unavailable. The existing private object store
provides an immutable outbox without adding a fourth public CRD, while the internal
sink prevents every client from receiving broad object credentials.

**Alternatives considered**:

- Controller-only change audit: reconcilers do not receive the requesting user's
  identity.
- Audit records as one CR per action: unnecessary persistent control-plane load.
- Stdout/Loki-only audit: cannot prove durability across collector or Loki outages.
- Metrics labeled by tap, rule, address, or capture UID: violates cardinality
  constraints.

## 12. Verification strategy

**Decision**: Use table-driven Go unit tests for validation, matching, canonical
flow keys, deduplication, rate limits, state machines, and normalization; envtest
for schemas, webhooks, status, RBAC intent, and reconcilers; container integration
tests with real Suricata, Zeek, dumpcap, Loki-compatible ingestion, Hubble gRPC
fixtures, and separate MinIO artifact/audit buckets; and a disposable representative
Kubernetes cluster for the four user stories, restart recovery, failure isolation,
authorization, audit replay, retention, and the 100 Mb/s / packet-loss goals.

Generated CRDs, RBAC, examples, dashboards, and documentation are regenerated and
diff-checked in CI. Tests use synthetic traffic and non-sensitive fixtures only.

**Rationale**: The risky boundaries are kernel capture, external analyzers,
Kubernetes reconciliation, stream replay, object storage, and authorization. Unit
tests alone cannot establish their behavior.

**Alternatives considered**:

- Mock-only tests: cannot validate capture limits, analyzer schemas, storage, or
  restart behavior.
- A live homelab as the only test environment: slow, non-repeatable, and unsuitable
  for pull-request gates.

## Resolved architecture deltas

The plan intentionally narrows several examples in the architecture source to the
active MVP specification:

- The public identity is `Trawl`, API group `trawl.cloud`, namespace
  `trawl-system`.
- `pod-selector`, TLS decryption, scheduled/Hubble-flow/anomaly triggers, inline
  mode, dynamic rules/scripts, and replay remain outside this feature.
- The mirror interface is captured directly; no mirror-receiver broker is needed.
- CapturePolicy does not accept arbitrary storage destinations.
- Analyzer and rule images are immutable; no `latest` tags or daily rule mutation.
- Explicit capabilities replace blanket privileged containers unless testing
  proves an unavoidable requirement and an exception is reviewed.

No `NEEDS CLARIFICATION` items remain.
