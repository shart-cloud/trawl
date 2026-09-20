---
title: "Post-MVP Evolution Plan"
description: The nine workstreams after the MVP release gates, the order they have to be built in, and the decisions that have to be made before code exists.
---

**Status**: Draft for review · **Scope**: everything after the `001-cloud-native-nsm` MVP release gates · **Specification**: `specs/002-post-mvp-evolution`

## How to read this document

This is a roadmap across several Spec Kit features, not a single feature spec.
Each workstream below is sized to become its own `specs/NNN-*/` directory with
its own `spec.md`, `plan.md` and `tasks.md`. The value of keeping them in one
document is the dependency graph below: several of these items are cheap now
and expensive later, and at least two of them are worthless if built in the
wrong order.

Nothing here is a task list. Where a workstream has a decision that has to be
made before code exists, the decision is named as a decision and not disguised
as an implementation detail.

### Principles carried forward from the MVP

These are not restated as requirements in each workstream; they apply
throughout.

1. **Passive by default.** `TapMode` has one member and adding a second is a
   visible API change requiring a separate approved specification. Nothing in
   this plan changes that.
2. **Status must be true or absent.** A field that makes a coverage claim is a
   claim an investigation will later rest on. `Unknown` is a real answer.
   `Active` means complete, not mostly working.
3. **A gate nobody has executed is not a gate.** Phase 7 of the MVP found six
   contract tests silently skipping, three security jobs that had never run, and
   two expiry specs never executed. Every workstream below that adds a gate also
   names how the gate is proven to run.
4. **Evidence is the product.** Anything that touches captured traffic touches
   the write-once ledger, the authorizing gateway, and retention.
5. **Strict configuration decoding.** Per [ADR-0006](/adr/0006-strict-installation-configuration/),
   a config schema change is a breaking change for every component that parses
   config, and the symptom appears at next restart. Several workstreams below
   change the config schema.

## Where the MVP left off

Shipped and gated:

- Declarative passive taps on mirror and node interfaces (`NetworkTap`)
- Normalized observation envelope, Suricata and Zeek normalizers, Community ID
  correlation, Loki pipeline, four Grafana dashboards
- Manual capture with authorized download, retention sweep, write-once audit
  ledger (`CaptureJob`, artifact gateway, analyst/viewer/retention-admin roles)
- Event-driven capture from Suricata alerts and Hubble drops (`CapturePolicy`)
- Declarative physical port mirroring via a pluggable fabric provider, MikroTik
  implementation only (`PortMirror`)
- Two-layer analyzer content: upstream refresh at pod start, digest-pinned OCI
  overlay for custom content, GitOps-managed

Deliberately not built, and recorded as such: pod injection, TLS decryption,
dynamic rule/script CRDs, schedule/anomaly/generic-flow triggers, inline
enforcement, packet replay.

## Workstream 0 — Close the carried gaps

**Priority: first. Nothing below should start while these are open.**

These are not roadmap items, they are the MVP's own recorded debts. Two of them
are status lies, which is the failure class this project is most careful about
everywhere else.

### 0.1 A dead event worker leaves every CapturePolicy reporting `Armed` — **closed**

The staleness logic that would report a disconnected source lived inside the
worker, so the component that should declare the outage was the component that
was down. Nothing else wrote policy status.

This is ordinary Kubernetes behaviour for a stopped controller and completely
extraordinary for a field that is a detection-coverage claim. An analyst reading
`Armed` six weeks later reads it as "this policy was watching."

Closed by an external witness (`internal/witness`). The controller-manager
already runs, already watches `CapturePolicy`, and now holds the worker's
liveness lease. When the lease expires, the controller writes a stale-heartbeat
reason onto every policy the dead worker owned.

**Gate:** the existing trigger-source failure injection already severs the
worker's egress. It now asserts the policy status changes, not just that the
injection applied.

### 0.2 PortMirror device contention — **closed**

Nothing stopped two `PortMirror` resources naming the same `deviceRef`. A
RouterOS switch has one global `mirror-target`, so each observed the other's
configuration as drift and rewrote it every resync: indefinite flapping,
filling the device log and the write-once audit ledger. The ledger cannot be
pruned, so a contention nobody noticed was one nobody could clean up after.

Closed by `checkDeviceConflict`, following the `ProbePortConflict` precedent.
The controller detects the overlap and reports `DeviceConflict` on whichever
resource holds the younger claim; the incumbent keeps the device and keeps
mirroring. Creation time decides the claim with the UID as a tie-break, so two
resources created in the same instant still agree on which yields — the rule is
now shared with `ProbePortConflict` as `olderClaim`. Admission does not reject,
because admission sees one object and cannot see reconcile-time state; a pair
created concurrently would both pass and both be wrong.

The contended resource also declines the revert finalizer. That is not
incidental: the finalizer exists to un-configure the device on deletion, so a
resource that never configured it would, in reverting, tear down the mirror the
incumbent owns.

**Why it mattered now rather than later:** Workstream 5 adds cloud vTAP
providers, where repointing a mirror session is a single API call and a leftover
mirror copies production traffic to an interface nobody is watching. The
contention rule needed to exist before the provider count grew.

**Turned up on the way:** `status.AllReasons()` was missing every PortMirror
reason. It is what the condition-shape contract test walks, so the six of them
had gone unverified since the fabric work landed — the same failure class as a
silently skipping test. The list is complete now, and a new test parses the
source to prove it stays that way.

### 0.3 No observed-byte counter — **closed**

SC-003's rate clause was unverifiable from Trawl's own telemetry, because
throughput could not be computed from what the system exported. This was not
only a test problem: throughput is the first number anyone asks a sensor for,
and without it "is this tap keeping up" could not be answered from the tap.

Closed by `BytesObserved` alongside the existing `PacketsObserved` in
`NetworkTap` status, folded through `PacketMeter` and exported on the metrics
plane. The source is Suricata's `decoder.bytes`, confirmed against 8.0.6 rather
than its documentation. Suricata reports bytes from its decoder alone, so
`packetReading`'s kernel-first rule has no byte analogue and the counter carries
that caveat.

**Release decision accepted:** SC-003 now measures a full hour at whatever
sustained rate the installation produces and requires the evidence to report
that rate. The existing run remains exactly what it was—roughly 72 packets/s,
not a 100 Mb/s test—and future runs also report decoder-accepted byte rate from
the counter above.

### 0.4 The smaller ones — **closed**

- `requireReachableObjectStore` needs a host-level `/etc/hosts` entry, and six
  e2e specs skipped silently without it — every download path, the expiry
  refusal, the retention enforcement and the audit-outage spec — so
  `make test-acceptance` exited zero having asserted none of them. Same family
  as the `kustomize` silent skip, not fixable by a Makefile dependency.
  **Closed**: it fails now, with the port-forward and `/etc/hosts` remedy in the
  message. Not-applicable is still a skip and still lives above it, in
  `requireAcceptanceCluster`.
- `README.md` was the untouched kubebuilder scaffold, every `TODO(user)`
  included. **Closed.** Writing it turned up two things: the repository asserts
  Apache 2.0 in 195 file headers and shipped no `LICENSE`, which is now added,
  and no published install bundle existed — `dist/` is gitignored and no workflow
  released one, so the scaffold's one-command `kubectl apply` install was never
  going to work. **Both closed.** A `Release` workflow now renders the bundle
  from a tagged tree and attaches it, with the supply-chain manifest and
  checksums, to the GitHub release. It refuses a tag whose committed generated
  artifacts do not match its source, and refuses a bundle carrying any image not
  pinned by digest — `install.yaml` is the one artifact where the
  no-floating-tags rule is checkable after the fact and the easiest to break by
  accident. No release has been cut yet, so the first tag is what proves it.
- `AGENTS.md` was the generic kubebuilder scaffold and actively wrong: it
  described `internal/webhook/` when admission lives in `internal/admission/`,
  pointed at a `cmd/main.go` that does not exist, and said nothing about the
  audit ledger, the fabric providers, the observation envelope, the analyzer
  images, or the suppression workflow. **Closed.** Rewritten against the tree
  and then audited claim by claim against it, which caught nine errors in the
  rewrite — the most consequential being that the manager's CapturePolicy
  reconciler is the witness rather than the policy controller, which is exactly
  the confusion the file exists to prevent. The scaffold's dead
  `config/network-policy/` went with it; Trawl's own `networkpolicy/` has
  carried default-deny and a policy per component since the fabric work.
- The docs site landing page was the unmodified Starlight welcome scaffold, and
  `guides/example.md` and `reference/example.md` were stock placeholders.
  **Closed.** The landing page is Trawl's now, the placeholders are gone, and
  the Reference section holds the two normative contracts —
  `contracts/crd-api.md` and `contracts/telemetry.md` — rendered through
  `sync-content.mjs` rather than copied, which is what the `PAGES` table was for.
  The GitHub link in the header had pointed at the Starlight repository since
  the site was scaffolded, and `site` was unset so no sitemap was ever emitted.
  Both fixed.
- `docs/src/content/docs/quickstart.md` carried a generated-by header naming
  `docs/scripts/sync-content.mjs`, which did not exist in the repository — the
  file was hand-maintained while claiming not to be. **Closed** by writing the
  script rather than dropping the header, because the page really is derived
  from `specs/001-cloud-native-nsm/quickstart.md` and the duplicate was free to
  drift. The script runs from `prebuild`/`predev`, the generated page is
  gitignored so there is nothing to hand-edit, and the quickstart is now in the
  sidebar — it had been unreachable and absent from a clean clone.
- PortMirror had no admission webhook, and a comment in its controller claimed
  one rejected off-namespace resources. **Closed on `main` in PR #36**, which
  reached this independently and went further: it added the validating webhook,
  made `deviceRef` and `provider` immutable, gave API mutations their own audit
  actions, and found three status lies on the way — an off-namespace mirror
  reporting `Accepted` as the reason it was refused, `DeviceReachable=False`
  about a device that had never been contacted, and a reconciler that never
  re-validated a stored spec before configuring hardware. No mutating webhook,
  deliberately: the type's only default is structural.
- Known code issues from the code-quality assessment:
  - ~~Hand-rolled `itoa32` with a `MinInt32` edge case in `correlation.go`.~~
    **Closed** — deleted in favour of `strconv`, with a test that pins every
    extreme of the range.
  - ~~Forward-defined status conditions for unimplemented CRDs.~~ **Closed by
    audit** — every condition type in `internal/status` has a current production
    writer across the four implemented CRDs; the stale `CaptureJob`/`PortMirror`
    grouping comment was corrected rather than leaving a future-looking block.
  - ~~Informer cache lag in `workloadReady`.~~ **Closed** — the manager supplies
    its uncached API reader for the readiness read. The unit regression keeps a
    stale Deployment in the cached client and the current one in the direct
    reader.
  - ~~Get-then-update on owned resources.~~ **Closed** — owned resources use
    server-side apply under `trawl-networktap-controller`; envtest proves a field
    owned elsewhere survives reconciliation.
  - ~~`sourceOf` nil dereference risk after re-validation.~~ **Closed** — the
    discriminated-union helper returns a safe value for an absent source, while
    reconcile still rejects the object as `InvalidSpec` before rendering. The
    unit regression reaches the old panic seam directly.
  - ~~Controller unit coverage leaning on e2e.~~ **Closed for the assessed
    gap** — phase derivation, target health, stale-heartbeat summarization,
    uncached readiness, and invalid-source handling now have unit tests; API
    ownership and status-subresource behaviour remain in envtest where those
    semantics belong.
  - ~~Misassociated godoc on `Counters()`.~~ **Closed** — `LastRecord` and
    `Counters` now each describe the method immediately below them.

The remaining release work is validation rather than an unimplemented 0.4
item: run the complete gates, prove the tag-only image workflow and SBOM output,
then repeat the live PortMirror exercise against the release candidate,
including packet status and off-namespace rejection.

## Workstream 1 — The observation time model

**Priority: immediately after Workstream 0. This gates Workstreams 2, 6 and 8.**

**Size: small. Cost of deferring: large and compounding.**

### The problem

Every observation today is produced near-live, so the timestamp on a record and
the moment it entered the pipeline are effectively identical. Nothing in the
system distinguishes them because nothing has needed to.

Offline analysis breaks that permanently. A ring extract from twenty minutes ago
produces observations carrying twenty-minute-old packet timestamps that arrive
now, interleaved with live records. Cloud flow logs (Workstream 6) are worse:
aggregated over one to ten minute windows and delivered minutes after that,
always out of order relative to live traffic.

Three subsystems assume monotonic near-now arrival:

- **Loki cursors and replay bounds** ([ADR-0002](/adr/0002-trigger-replay-and-deduplication/)).
  A cursor over event time cannot advance past a replayed old record without
  losing it; a cursor over ingest time cannot answer "what happened at 14:32."
- **CapturePolicy cooldown buckets and rate limits.** A batch of replayed
  observations looks like a burst and will exhaust a rate limit that exists to
  prevent capture storms from live traffic.
- **Duplicate fingerprint windows.** A bounded rolling window keyed on arrival
  cannot recognise a record it already saw twenty minutes ago.

### The change

Split `eventTime` from `ingestTime` in the `trawl.observation/v1alpha1`
envelope, and make every consumer state which one it uses and why.

This is a versioned schema change to the normative envelope, so it is governed
by [ADR-0001](/adr/0001-normalized-observation-envelope/)'s compatibility rules.
Doing it now, while there are exactly two producers and a known set of
consumers, is a contained change. Doing it after the ring buffer, cloud flow
ingestion and flow-addressable retrieval all depend on the current shape is a
migration.

### Decisions this forces

1. **Do rate limits and cooldowns run on event time or ingest time?** Probably
   ingest, because their purpose is protecting the cluster from capture storms,
   which is a now-problem. That should be written down rather than inherited.
2. **Is a replayed observation distinguishable from a live one?** It should be.
   An analyst pivoting from a dashboard needs to know whether a record is
   first-pass live output or the product of a re-analysis with a different
   ruleset version.
3. **What is the maximum tolerated lateness before a record is marked as such?**
   Needs a bound, because an unbounded one means the dedup window is unbounded.

### Gate

Contract tests on the envelope. An integration test that submits an out-of-order
batch and asserts the cursor, the dedup window and the cooldown accounting each
behave as the decision above says they should.

## Workstream 2 — Ring buffer and AnalysisJob

**Priority: the headline increment. Build both together.**

### Why the ring buffer is the biggest functional gap

Today a `CapturePolicy` fires on a Suricata alert and *then* starts capturing.
The packets that caused the alert are already gone. Trawl collects the aftermath
of a beacon and never the beacon.

For SEC503-style analysis that is the wrong half of the conversation, and it is
precisely the capability Security Onion and Arkime have that Trawl does not.

### The ring

Sensors maintain a continuous bounded on-disk ring of captured packets.
`CaptureJob` gains an extraction semantics alongside the existing start-now
semantics: "give me T-60s through T+300s around this trigger."

Everything downstream is reused unchanged: the runner pod pattern, the storage
client, the artifact gateway, the retention sweeper, the write-once ledger.

**The honest-degradation problem, which is the interesting part:** a requested
window may have already rolled out of the buffer, partially or entirely. This
must be a distinct, first-class outcome, not a short file. A partial extract
that looks like a complete one is the same class of failure as a tap reporting
`Active` while an analyzer is down. Suggested shape: the artifact records the
window actually covered, the window requested, and a condition distinguishing
`WindowComplete` from `WindowTruncated` from `WindowExpired`.

**Open decision: what writes the ring.**

| Option | For | Against |
|---|---|---|
| Suricata `pcap-log` in ring mode | Cheap. Working in days. No new binary. | Ties the evidence buffer to one analyzer's lifecycle, config and restarts. A Suricata rolling restart for content refresh becomes an evidence gap. |
| Dedicated eBPF/AF_PACKET ring writer | Buffer outlives any analyzer. Independent disk budget, independent restarts. Feeds AnalysisJob directly. | A new privileged binary, its own capability review, its own drop accounting. |

Recommendation: the dedicated writer, because the moment AnalysisJob exists the
ring stops being a Suricata feature and becomes the system's evidence substrate.
But building the Suricata version first as a throwaway to learn the disk-budget
and extraction ergonomics is defensible, as long as it is thrown away.

**Disk budget is a safety property.** An unbounded ring fills a Talos node's
disk and takes the node down. The budget belongs in installation config, the
enforcement belongs in the writer, and the exhaustion behaviour (overwrite
oldest, never refuse to write, report pressure) belongs in an ADR.

### AnalysisJob

Four separate-sounding things are one CRD:

- Offline Zeek and Suricata over stored pcap
- `tcpdump`/`tshark` jobs
- A job with decryption key material mounted as evidence (Workstream 7)
- Reprocessing pcap out of a cloud bucket (Workstream 6)

`AnalysisJob` takes a source (a `CaptureJob` artifact, a ring extract window, or
a bucket object), an analyzer with a pinned image digest, optional key material,
and emits observations plus a ledger record.

Three capabilities fall out for free:

- **PCAP replay for SEC503 exercises.** A Phase 4 item in the original
  architecture doc, now a special case of AnalysisJob.
- **Cloud bucket reprocessing.** A source type, nothing more.
- **Detection regression testing.** Run today's ruleset against last month's
  retained traffic and diff the observations. This is a genuinely strong story
  for a CRD-driven system, because "which content digest produced this evidence"
  is already first-class in the OCI content model. Security Onion does this
  badly.

### The three offline gotchas

**Zeek splits connections at file boundaries.** A connection spanning two ring
segments becomes two `conn.log` records with different UIDs, split byte counts,
split durations and truncated history strings. Community ID survives, because it
is derived from the 5-tuple, so the correlation pivot still works. But "one
connection, one conn record" stops being true and an analyst counting sessions
gets the wrong number.

The existing `DuplicationState` enum is the precedent for how to handle this: a
record whose flow touches a segment edge should say so, rather than being
silently presented as whole. Overlapping segment windows reduce boundary
splitting but create real duplicates, which is a different lie; pick one and
record why.

**Suricata may have a better answer.** Its unix-socket runmode keeps the engine
resident and processes submitted pcap files sequentially while retaining flow
state across them. **Verify this holds in 8.x before designing around it** — if
it does, boundary splitting is a Zeek-only problem and the design simplifies
considerably.

**Detection latency becomes segment duration.** A 60-second ring segment means a
60-second floor on offline alert latency. That is a change to what Trawl *is*,
not just how fast it is.

This argues for a hybrid rather than a replacement:

- Suricata stays **live** for the trigger path that is already built and tested
- The ring writes **continuously** alongside it
- Zeek and deep reprocessing run **offline** over ring extracts

You get low-latency triggers and complete retrospective evidence instead of
trading one for the other.

## Workstream 3 — Storage portability

**Priority: before the second backend is written, not after.**

### The easy part

`internal/storage/store.go` is already an interface with a `fake` and a
conformance suite in `storagetest/`. GCS and Azure Blob are new implementations
plus a conformance run.

### The landmine

The audit ledger's guarantees rest on S3-shaped primitives: conditional put,
versioning, HEAD verification, Object Lock retention. The equivalents exist
everywhere and are not the same shape.

| Capability | S3 | GCS | Azure Blob |
|---|---|---|---|
| Write-once retention | Object Lock, per object | Retention policy + Bucket Lock, bucket-scoped | Immutability policy, time-based retention, container or version scoped |
| Conditional write | Supported | Preconditions on generation | Conditional headers / ETag |
| Version identity | Version ID | Generation number | Version ID / snapshot |
| Presigned read | Presign | V4 signed URL, needs SignBlob via workload identity to avoid a key on disk | User-delegation SAS |

Writing the GCS implementation against the current interface will either weaken
the ledger's guarantee silently or accumulate special cases.

**Sequence:** revise the interface around what all three can actually promise,
run the existing conformance suite against the revision with S3 still the only
implementation, and only then write the second backend. The conformance suite
then catches a backend that cannot hold the line, instead of a code review
catching it.

### Credentials

Cloud means workload identity (IRSA, GKE Workload Identity, Azure Workload
Identity) rather than static keys. That is a config schema change, and per
[ADR-0006](/adr/0006-strict-installation-configuration/) that means rolling
every config-parsing component: controller-manager, event-worker,
artifact-gateway, and any new binary from Workstream 2.

This is exactly the failure that broke the artifact gateway for a day during the
MVP. It is written into the runbook; the point of writing it there was this
moment.

## Workstream 4 — eBPF capture via AF_XDP

**Priority: after the ring, because the ring is the consumer that justifies it.**

### What is already free

AF_XDP redirects ingress frames into user-space memory rings, bypassing the
network stack, and Suricata supports it natively (`suricata --af-xdp=<iface>`).
It requires `libxdp` and `libbpf` at build time and is enabled automatically
when they are present. Since `images/suricata/Containerfile` already builds from
verified source with a `SOURCES.lock`, this is two build dependencies and a
config stanza, not a fork.

### Two constraints that belong in the API, not the docs

**1. AF_XDP takes the interface away from the host.** During AF_XDP operation
the selected interface cannot be used for regular network traffic. On a SPAN
port that is ideal. On a node's primary NIC it severs the node.

This maps onto the existing `TapSourceType` enum: AF_XDP is a `MirrorInterface`
capability and must be **refused at admission** for `NodeInterface`. Given how
this codebase treats status lies, a CEL rule is the right enforcement, because
the failure mode is an operator taking a Talos node off the network with a
`kubectl edit`.

**2. The achieved mode is not the requested mode.** XDP_DRV requires driver
support and silently falls back to XDP_SKB. Zero-copy binding falls back to
copy mode. "AF_XDP enabled" and "AF_XDP in generic SKB copy mode" are very
different performance claims.

The tap must report the mode actually achieved. An operator reading `Active`
should not have to shell into a pod to find out which one they got — and on
Talos they cannot.

### What AF_XDP does not solve

Zeek has no equivalent native AF_XDP source. So "one capture socket, both
analyzers" is not achievable this way, which is the second reason the ring
buffer comes first: the ring *is* the fan-out point.

### The other eBPF payoff

eBPF gives metadata the wire does not carry: cgroup and container identity,
process and socket ownership, and (see Workstream 7) pre-encryption plaintext at
the TLS library boundary. Per-pod attribution via cgroup ID is a better answer
to the original architecture doc's sidecar-injection plan than the sidecar was —
no mutating webhook, no workload restart, no privileged container inside
someone else's pod. Worth an ADR superseding that section of the doc.

## Workstream 5 — Cloud fabric providers

**Priority: after 0.2 (device contention) and independent of the rest.**

`internal/fabric/provider.go` is an interface with one implementation. The next
implementations are not more switches:

- **AWS VPC Traffic Mirroring** — mirror session, target, filter; source is an ENI
- **Azure Virtual Network TAP**
- **GCP Packet Mirroring** — policy attached to a subnet or instance set

Same `PortMirror` CRD, same finalizer-revert discipline, same "configuration in
effect on infrastructure nobody can `kubectl get`" problem already solved once.

**Why this is the item that makes Trawl legible to other people.** A K8s-native
NSM operator that configures cloud packet mirroring declaratively, with an audit
ledger recording every device mutation and a finalizer that reverts on delete,
is a thing that does not currently exist and that an enterprise would
understand immediately.

**The immutability finding matters more here.** `provider` and `deviceRef` are
immutable because revert resolves `deviceRef` at deletion time, so repointing a
live mirror configures the new target and leaves the old one copying traffic
with nothing in the cluster recording that it does. In cloud that repoint is a
single API call and the leftover is billable, ongoing, and invisible.

**Open questions:**

- Credentials per provider, and whether `deviceRef` becomes a typed union rather
  than a string
- Whether mirror *filters* (AWS filter rules, GCP mirroring filters) belong in
  the CRD or are deliberately out of scope, given that a filter is a detection
  coverage decision
- Cost. Cloud traffic mirroring is metered. A `PortMirror` that silently
  generates spend is a different kind of surprise than a switch port, and the
  status should probably say something about volume.

## Workstream 6 — Cloud flow log ingestion

**Priority: after the ring buffer, which is what makes it useful.**

### Why this depends on Workstream 2

VPC Flow Logs, Azure NSG/VNet Flow Logs and GCP flow logs are aggregated over
one to ten minute windows and delivered minutes after that. As a live
`CapturePolicy` trigger this is useless: the traffic is long gone by the time
the signal arrives.

With retro-capture it is excellent. A flow log anomaly triggers extraction of
the ring window the flow log describes, and you get the actual packets for an
event you learned about twelve minutes late. Very little else in this space does
that.

### Different machinery than Hubble

Hubble is a gRPC stream with a cursor. Cloud flow logs are objects appearing in
a bucket. That needs a lister with a watermark, late-arrival tolerance, and
idempotency against re-delivery — different enough that it likely wants its own
CRD rather than another arm of the `CapturePolicyTrigger` union.

It also leans hard on Workstream 1. Every record is late by construction.

### Open decisions

- One `FlowSource` CRD per provider, or a provider union inside one kind
- Whether cloud flow records become `ClusterFlowEvent` observations or a
  sibling type (they describe VPC-level flows, not cluster-level ones, and
  flattening them loses that)
- Retention: flow logs in a bucket are already retained by the cloud provider.
  Does Trawl copy them, index them, or only read them?

## Workstream 7 — TLS decryption, reframed

**Priority: last of the major workstreams. Depends on AnalysisJob.**

### The thing that changes the design

**Mounting the server's private key decrypts almost nothing in 2026.** Any
ECDHE suite and all of TLS 1.3 provide forward secrecy, so the private key
cannot recover session keys. The original architecture doc half-admits this in
its "what this won't cover" note.

The analyzer support confirms it rather than working around it:

- **Zeek**: decryption is explicitly experimental, works from *session key
  material* rather than the server private key, and supports only TLS 1.2
  connections using `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`. The Zeek docs state
  there is no plan to extend to other versions or ciphersuites. Key material
  arrives via `SSL::keylog_file` for trace files or Broker events for live.
- **Suricata**: narrower still.
- **tshark**: the one that decrypts broadly from an NSS key log, including
  TLS 1.3.

### The reframe

Key material mounted as evidence into a job, rather than standing decryption on
the sensor, is the right shape. Point it at session secrets instead of private
keys.

**Key material union on `AnalysisJob`:**

| Form | Source | Coverage |
|---|---|---|
| NSS key log | Instrumented clients, load balancers with session key logging, terminating proxies | TLS 1.2 and 1.3, broad |
| eBPF uprobe plaintext | `SSL_write`/`SSL_read` in OpenSSL, GnuTLS, BoringSSL | In-cluster workloads, no key custody at all |
| RSA private key | Certificate Secrets | TLS 1.2 RSA key exchange only. Nearly extinct. Build last or never. |

**Analyzer priority: tshark first, Zeek second within its narrow band, Suricata
last.** That is the inverse of the original doc's ordering and it follows
directly from what the tools actually do.

### The eBPF uprobe path is the real enterprise answer for in-cluster traffic

Plaintext at the library boundary, before encryption, with no keys to custody,
no PFS problem and no ciphersuite matrix. Given that Workstream 4 already
commits to eBPF infrastructure on the sensors, the probe machinery is largely
there. It does not help for mirrored north-south traffic from devices you do not
control, which is exactly where key material still matters — so the two are
complementary rather than competing.

### Evidence packaging: pcapng Decryption Secrets Blocks

Secrets can be embedded in the pcapng file itself. A decryptable capture becomes
a single sealed artifact with one chain of custody, rather than a file plus a
key that has to travel beside it and be tracked separately. This fits the
existing evidence model unusually well and is worth designing toward from the
start.

### Key custody design

- **Memory-backed mount only.** Never a disk-backed volume, never a layer.
- **Ephemeral pod, short-lived.** The key exists for the duration of the job.
- **The mount is itself a ledgered act.** The ledger already answers "who
  downloaded what, when." It must equally answer "who decrypted what, with whose
  key material, when."
- **A distinct RBAC role.** Someone who can read a capture must not
  automatically be able to read its plaintext. `capture-analyst` and
  `decryption-analyst` are different grants. The `capturejobs/download`
  subresource split is the precedent, and the T092 note about
  `kubectl auth can-i` not measuring subresources applies again here — assert
  with `SubjectAccessReview` and an explicit `subresource` field.

## Workstream 8 — Flow-addressable evidence

**Priority: research first, then decide. Depends on Workstream 2.**

Today an artifact is downloaded whole. Community ID correlation, a normalized
observation envelope and an authorizing gateway all already exist. The natural
next capability is asking the gateway for the packets belonging to
`community_id=X` rather than for a file.

This is the Arkime capability, built on pieces that already exist, and it pairs
naturally with the ring buffer because the ring is where "all packets, indexed"
lives.

**Why it is marked research.** Two hard parts:

1. **Indexing.** A flow index over a rolling ring is a real data structure
   problem with a disk and memory budget, and getting it wrong makes the ring
   writer the system's bottleneck.
2. **Authorization granularity.** A per-flow read is a much finer grant than
   `capturejobs/download`, and Kubernetes RBAC cannot express "this analyst may
   read flows involving namespace X." That either lives in the gateway as
   application-level authorization (with the ledger carrying the burden of
   proof) or it does not exist. That is an ADR, not a code decision.

## API versioning

**Decision needed before Workstream 1, not discovered during Workstream 6.**

Cumulatively this plan adds or changes:

- A new `TapSourceType` behaviour and an AF_XDP capture mode with achieved-mode
  status (Workstream 4)
- Ring extraction semantics and new outcome conditions on `CaptureJob`
  (Workstream 2)
- A new kind, `AnalysisJob` (Workstream 2)
- A reshaped storage configuration and a credential model change (Workstream 3)
- A new trigger or flow-source kind (Workstream 6)
- Key material types (Workstream 7)
- A versioned change to the `trawl.observation` envelope (Workstream 1)

That is a `v1alpha1` → `v1beta1` move with a conversion webhook, hub-and-spoke,
`v1alpha1` as hub. `AGENTS.md` already carries the kubebuilder instructions for
it, unused.

Deciding this now means these land as one deliberate version bump. Deciding it
later means eight alpha mutations that each break someone's manifests, and a
conversion webhook written under pressure against a shape nobody planned.

## Dependency graph and sequencing

```text
WS0  Carried gaps
      │
      ▼
WS1  Observation time model  ◄──── gates WS2, WS6, WS8
      │
      ├──────────────┐
      ▼              ▼
WS2  Ring +        WS3  Storage interface revision
     AnalysisJob         │
      │                  ▼
      │             WS3b Second/third backend
      │
      ├──────────────┬──────────────┐
      ▼              ▼              ▼
WS4  AF_XDP     WS6  Cloud flow  WS7  TLS key material
     capture         ingestion        (needs AnalysisJob)
                     (needs ring)
      │
      ▼
WS8  Flow-addressable evidence  (research first)

WS5  Cloud fabric providers  ──── independent, needs only WS0.2
```

**Recommended order:**

1. **WS0** — carried gaps. 0.1, 0.2 and 0.3 are closed; 0.4 remains.
2. **WS1** — event time versus ingest time. Small now, a migration later.
3. **WS2** — ring buffer and AnalysisJob as one increment. The headline.
4. **WS3** — storage interface revision, then the second backend.
5. **WS4** — AF_XDP as a mirror-tap capture mode.
6. **WS5** — cloud fabric providers. Can be pulled earlier; it is independent.
7. **WS6** — cloud flow ingestion, once late triggers are useful.
8. **WS7** — decryption key material on AnalysisJob.
9. **WS8** — flow-addressable evidence, after research.

## ADRs this plan requires

Following ADR-0001 through 0007, the next numbers:

| # | Subject | Blocks |
|---|---|---|
| 0008 | Event time versus ingest time; lateness bounds; which clock governs rate limits and dedup | WS1 |
| 0009 | Ring buffer ownership (dedicated writer vs analyzer-owned), disk budget, exhaustion behaviour, truncation honesty | WS2 |
| 0010 | AnalysisJob source union and the offline connection-boundary treatment | WS2 |
| 0011 | Storage interface portability: the write-once guarantee all backends must hold, and what is refused rather than weakened | WS3 |
| 0012 | AF_XDP constraints: mirror-only, achieved-mode reporting, fallback semantics | WS4 |
| 0013 | Per-pod attribution via eBPF cgroup identity, superseding the sidecar-injection design in the original architecture document | WS4 |
| 0014 | Cloud fabric provider model: credential handling, `deviceRef` typing, filter scope, cost visibility | WS5 |
| 0015 | Late-arriving flow sources: watermarks, idempotency, and whether cloud flows are observations or a sibling type | WS6 |
| 0016 | Key material custody: forms supported, memory-backed mounts, ledger obligations, the `decryption-analyst` grant | WS7 |
| 0017 | API promotion to `v1beta1` and the conversion strategy | API versioning |

## Open questions that need answers, not code

1. **The ring writer.** Suricata `pcap-log` as a throwaway to learn the
   ergonomics, or the dedicated eBPF writer directly?
2. **Does Suricata's unix-socket runmode retain flow state across submitted pcap
   files in 8.x?** If yes, boundary splitting is Zeek-only and the offline
   design simplifies. Test this early; it changes the design.
3. **SC-003 — resolved for the alpha.** The criterion uses the installation's
   honestly reported produced rate. The 72 packets/s evidence stays labelled as
   ambient traffic and is not promoted into a 100 Mb/s claim.
4. **SC-005 fixtures — resolved for the alpha.** The criterion names the ten
   bidirectional Community ID pivots the five exactly-correlatable fixtures
   support. Only one fixture supports the complete signature/protocol round
   trip, and the evidence continues to say so.
5. **Cost model for cloud mirroring.** Is spend visibility in scope for
   `PortMirror` status, or explicitly out of scope?
6. **Who is this for?** Coursework depth, portfolio and conference artifact, or
   something someone else installs. WS2 and WS8 serve the first. WS3, WS5 and
   WS7 serve the third. WS4 serves the second. The order above hedges; a clear
   answer would sharpen it considerably.

## What this plan deliberately does not include

- **IPS / inline mode.** `TapMode` has one member and the comment explaining why
  adding a second requires a separate approved specification is correct. The
  blast radius is not worth it while the detection pipeline is this young.
- **A RuleSet CRD for dynamic rule and script management.**
  [ADR-0005](/adr/0005-analyzer-content-management/)'s digest-pinned OCI content
  with GitOps is a better answer than a CRD holding rule text. This item from the
  original architecture document should be closed as *done differently*, not
  carried.
- **Sidecar injection via mutating admission webhook.** Superseded by eBPF
  cgroup attribution (Workstream 4, ADR-0013). The original design mutates user
  workloads, requires a pod restart to take effect, couples tap lifecycle to
  workload lifecycle, and places a privileged container inside someone else's
  pod.
- **Server-private-key TLS decryption as a primary path.** See Workstream 7. It
  decrypts a shrinking remnant and carries the full custody burden of something
  that works.
