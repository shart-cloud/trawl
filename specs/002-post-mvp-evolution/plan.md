# Implementation Plan: Post-MVP Evolution

**Branch**: `002-post-mvp-evolution` | **Date**: 2026-09-13 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/002-post-mvp-evolution/spec.md`

## Summary

This is a **program decomposition plan**, not a single implementation plan. The
specification covers nine workstreams; this plan establishes the delivery
sequence, states what each workstream inherits from the one before it, and
defines the boundary at which each is extracted into its own
`specs/NNN-*/` feature.

The load-bearing output is the sequence in **Delivery Sequence** below. It is
not the roadmap's recommended order. Decision D-001 resolved the audience as a
portfolio and conference artifact, which promotes the two workstreams that read
as novel to an outside audience — cloud packet mirroring and kernel-bypass
capture — ahead of the continuous buffer, which remains the larger functional
gap. That promotion has a cost, recorded in **Sequencing Costs** rather than
absorbed silently.

`/speckit.tasks` should **not** be run against this plan to produce an
implementation task list. It should be run against each extracted workstream
feature. WS0 is closed. This revision records candidate slices for WS5 and WS4; each
still requires its governing ADR, an extracted feature spec, and its own gate
before implementation begins.

## Technical Context

**Language/Version**: Go 1.26.7

**Primary Dependencies**: controller-runtime 0.24.1, Kubernetes API 0.36.0, Cilium/Hubble 1.18.11, MinIO Go client 7.3.0, Prometheus client 1.24.1, jsonschema/v6

**Storage**: MinIO-compatible object storage for artifacts and the write-once ledger; Loki for observations; node-local disk for the continuous buffer introduced in WS2

**Testing**: Go unit tests, envtest control-plane integration tests under `test/integration/`, e2e acceptance under `test/e2e/` against an isolated Kind or Talos cluster, storage conformance under `internal/storage/storagetest/`, telemetry contract tests under `internal/telemetry/`

**Target Platform**: Talos Linux on Kubernetes; no SSH into cluster nodes, no host shell, no host package installation. WS5a may use outbound SSH from the controller to a supported network device.

**Project Type**: Kubebuilder v4 single-group operator with seven satellite binaries

**Performance Goals**: Sustained capture at the reference rate with under 1% loss at the capture boundary, verified with the acquired traffic generator (D-002); the continuous buffer must not become the limiting factor on retained coverage

**Constraints**: Passive only; bounded disk for the buffer with no path to host storage exhaustion; low-cardinality telemetry labels; strict configuration decoding, so a schema change rolls every config-parsing component

**Scale/Scope**: Homelab reference cluster. Nine workstreams with WS4 and WS5 split into bounded slices, twelve user stories, 65 functional requirements, 19 measurable outcomes, ten architecture decision records, one API version promotion.

## Constitution Check

*GATE: evaluated against `.specify/memory/constitution.md` v1.0.0 before Phase 0.*

| Principle | Applies to | Assessment |
|---|---|---|
| **I. Passive and Fail-Open** | WS2 buffer writer, WS4 kernel-bypass capture | **Attention required.** WS4 takes an interface away from the host during operation. On a mirror port that is passive; on a node port it severs the node. FR-034 refuses it at admission for node-level sources. The buffer writer is a receive path only and adds no transmit capability. No workstream introduces traffic modification. **Pass, conditional on FR-034 being enforced at admission rather than documented.** |
| **II. Declarative Control and Truthful State** | Every workstream | The program's organizing purpose. FR-001/002 close two status lies; FR-016/017 make partial extraction a first-class outcome; FR-035 reports achieved rather than requested mode; FR-050 reports partial decryption coverage; FR-054 reports partial flow coverage. **Pass.** |
| **III. Evidence Integrity and Least Privilege** | WS2, WS3, WS5, WS7, WS8 | FR-021 routes extracts through the existing storage, authorization, retention and ledger path rather than a parallel one. FR-047 splits decryption from capture-read. FR-049 forbids key material in storage, layers, logs, status and metrics. FR-052 authorizes per-flow reads at flow granularity. FR-030 refuses a storage provider that cannot hold the write-once guarantee rather than weakening it. **Pass.** |
| **IV. Observable and Correlatable by Design** | WS1, WS2, WS3, WS5 | FR-018 reports buffer storage pressure; FR-020 makes coverage gaps discoverable; FR-025 marks segment-boundary-affected records; FR-041 reports mirrored volume. Correlation values remain structured fields, not index labels. **Watch item:** WS8's flow index is a new high-cardinality surface and must keep flow identifiers as structured metadata. |
| **V. Verification at Every Boundary** | Every workstream | FR-055 requires each new gate to be demonstrated executing — written directly against the MVP's finding of six silently skipping contract tests. FR-004 converts silent environmental skips to loud failures. D-002 acquires the generator that makes the throughput criterion verifiable rather than nominal. **Pass.** |
| **VI. Small, Phased, Reversible Delivery** | Program structure | **Attention required.** This is the principle most at risk from a nine-workstream program. Mitigated by extracting one workstream at a time, and by requiring a governing ADR and feature extraction before each new slice. FR-056's single version promotion needs an explicit upgrade, rollback and cleanup definition before implementation, per the principle's third sentence. **Pass, conditional on the extraction discipline below being followed.** |

### Platform and security constraints

- **Baseline replacement**: WS3 adds storage providers beyond the MinIO-compatible baseline, and WS5 adds fabric providers beyond MikroTik. Both are additive implementations behind existing interfaces, not baseline replacements, so neither triggers the replacement clause. ADR-0011 and ADR-0014 document them regardless.
- **Privileged workloads**: WS2's buffer writer and WS4's kernel-bypass path both request host access. Each requires an explicit capability justification and confinement to the existing privileged namespace and eligible targets. Neither may reuse capture privilege for any other purpose.
- **API compatibility**: the cumulative changes exceed what `v1alpha1` can absorb compatibly. FR-056 requires one promotion to `v1beta1` with a conversion path. This is the constraint's documented-migration requirement, and it is why the version decision is made in WS1 rather than discovered in WS6.
- **Credentials**: WS3's workload identity and WS5's per-provider credentials both come from the cluster secret-management boundary. WS7's key material is stricter still — memory-backed and bounded by the run's lifetime.
- **Capture bounds**: WS2 extends capture semantics, so extraction requests inherit the existing duration and size bounds, and the buffer adds a disk budget as a third bound.

**Security review required** (per Workflow item 4) for: WS2 (new privileged binary, new evidence path), WS3 (credential model change), WS4a (pod metadata RBAC and any new kernel collector), WS4b (privileged capture mode), WS5a (SSH host keys and device mutation), WS5b (external infrastructure mutation), WS7 (key custody, new RBAC grant), WS8 (authorization granularity below what RBAC expresses).

## Delivery Sequence

Ordering under D-001 (portfolio and conference artifact). Deviations from the
roadmap's recommended order are marked and justified.

| # | Workstream slice | Story | Depends on | Exit gate |
|---|---|---|---|---|
| 1 | WS0 Carried gaps | US1 | — | Closed |
| 2 | WS1 Observation time model | US2 | WS0 | Occurrence and ingest time contract, conversion decision |
| 3 | WS5a SSH-managed physical mirror | US11 | WS0.2, ADR-0014 | One profile verified on disposable hardware; wrong key and unsupported capability cause zero writes |
| 4 | WS4a Pod attribution | US12 | WS1, ADR-0013 | Correct UID through pod churn; ambiguous and external traffic stay unknown |
| 5 | WS5b Cloud fabric providers | US7 | WS0.2, WS5a provider lessons | First provider creates, observes, and reverts owned resources; volume observable |
| 6 | WS4b AF_XDP capture | US6 | WS0.3, D-002 generator | Mirror-only admission; achieved mode and fallback measured |
| 7 | WS2 Ring buffer + AnalysisJob | US3, US4 | WS1, ADR-0009/0010 | Pre-trigger extraction, bounded disk, honest coverage, pinned re-analysis |
| 8 | WS3 Storage portability | US5 | ADR-0011 | Shared conformance suite passes second provider without weaker guarantees |
| 9 | WS6 Cloud flow ingestion | US8 | WS1, WS2, WS3 | Late/repeated records extract exactly once |
| 10 | WS7 TLS key material | US9 | WS2, ADR-0016 | Separate authorization and no key bytes in durable surfaces |
| 11 | WS8 Flow-addressable evidence | US10 | WS2, R-5 research | Go/no-go on index cost and flow-granularity authorization |

WS5a and WS4a are the newly scoped slices. WS5b and WS4b preserve the
portfolio-first order in D-001. Splitting attribution from AF_XDP is deliberate:
node-local identity does not require a kernel-bypass packet path.


### Why WS1 stays second despite the audience answer

WS1 demonstrates nothing to an audience. It stays second because it is small
now and a migration later, and because WS2, WS6 and WS8 all depend on it. Moving
it after the demonstrable work would mean the buffer, cloud flow ingestion and
flow retrieval each rediscover the event-time problem separately. The API
version decision (FR-056) is also made here, before eight workstreams mutate
`v1alpha1` independently.

### Sequencing Costs

Recorded so that a later reader sees these were chosen, not overlooked.

1. **Kernel-bypass capture lands before the fan-out point exists.** The roadmap
   sequenced WS4 after WS2 because the buffer is what lets both analyzers share
   one capture path; the protocol analyzer has no native kernel-bypass source of
   its own. Delivered at position 6, kernel-bypass capture benefits the
   signature analyzer only, and the protocol analyzer stays on the existing path
   until WS2 lands. Accepted: the demonstrable artifact is the achieved-mode
   reporting and the throughput number, both of which work with one analyzer.

2. **The largest functional gap ships seventh.** Capturing the packets that
   preceded a detection is the product's biggest missing capability, and under
   this ordering it lands after two portfolio-facing workstreams and the newly
   requested SSH and attribution slices. If the audience answer changes, WS2
   is the first thing to promote.

3. **Storage portability is deferred behind cloud mirroring.** WS5b does not
   depend on WS3, so this is safe, but it means the platform demonstrates cloud
   mirroring while still bound to one storage provider. WS3 is pulled ahead of
   WS6 because cloud flow ingestion reads from provider buckets and wants the
   workload-identity credential model already in place.

## WS5a — SSH-managed physical mirrors

RouterOS 7 over HTTPS REST is already implemented. SSH is a second transport,
not a universal mirror command language. The first built-in CLI profile should
target RouterOS 7 on the reference switch, which gives an end-to-end device
test; a second vendor profile is a separate feature once a device and its
mirror capabilities are named. PortMirror remains the sole authorizable
resource and keeps the existing Configure, Observe, Revert, finalizer, and
write-once audit path.

1. Decide the first profile's supported model, firmware range, port layout,
   mirror directions, and ownership rule in ADR-0014. Refuse anything outside
   that matrix before writing. Preserve the one-device-one-owner contention
   rule and immutable provider and device reference.
2. Add a shared SSH transport with pinned host-key verification, bounded
   connect/command timeouts, and Secret-held authentication. Extend the
   device-credential decoder with a typed SSH form while keeping existing REST
   Secrets valid. Restrict controller egress to approved device endpoints and
   port 22. Never accept shell text from a CR or Secret.
3. Implement profile-specific read, set, and clear operations. Parse a stable
   machine-readable device output where available. Read back after each
   configuration attempt and deletion. Treat partial writes as degraded until
   observed and converged. Confirm direction in the shared state comparison
   before using it for a new provider.
4. Test refusal and lifecycle against a fake SSH server, then the reference
   switch with a disposable mirror. Verify actual copied traffic, not only
   configuration output; test host-key rotation, mid-write disconnect,
   repeated reconcile, and deletion after manual drift.

The deliverable is one supported SSH profile plus a reusable transport. A
device without a reviewed profile remains unsupported, even if it offers SSH.

## WS4a — Pod attribution

This slice is independent of AF_XDP. The current Hubble normalizer already
carries namespace, pod, and workload names for cluster flows, while Suricata
and Zeek carry packet-derived flow keys. Hubble does not provide a Community
ID in Trawl's current path, so joining those records is an inference that
requires source, destination, ports, protocol, direction, node, and a bounded
occurrence-time window. The record must expose its attribution source and an
unknown or ambiguous state.

1. Settle the endpoint identity schema in ADR-0013 after WS1 defines
   occurrence time: pod UID, namespace, name, provenance, and time interval.
   Store UID rather than treating a reusable name or IP as identity.
2. Build a bounded pod-lifecycle cache from Kubernetes watch events. Resolve
   Hubble's pod name to a UID only when the event time falls within one
   unambiguous pod lifetime; otherwise record unknown. Do not attach current
   pod metadata retroactively to old events.
3. Correlate packet-analyzer observations with Hubble flow observations only
   when the tuple, direction, node, and time uniquely agree. Preserve the
   existing correlation grade; do not relabel an inferred match as exact.
   NAT, shared addresses, missing records, and mirrored external traffic
   remain unknown unless independent evidence resolves them.
4. Run a narrow eBPF/cgroup spike on a node-local traffic path to determine
   whether the kernel can emit a reliable socket or cgroup identifier and
   whether that identifier can be mapped to Pod UID on Talos. Add a collector
   only if the spike demonstrates higher coverage without wrong identities.
   This is separate from AF_XDP capture and does not change user pods.
5. Verify pod deletion and replacement, address reuse, traffic in both
   directions, NAT, and a physical switch mirror. The acceptance threshold is
   zero wrong UIDs in those fixtures, with unknown or ambiguous when proof is
   absent.

Packet copies from a switch have no originating process context. A cgroup
helper running while processing such a packet would identify the processing
context, not the source pod; this path must never invent pod ownership.

## Later major features and gates

- **WS5b cloud mirroring:** extract AWS first only after reviewing the
  existing unmerged AWS branch; verify provider-owned resources, readback,
  finalizer cleanup, audit, and mirrored volume. Scope GCP and Azure as
  separate provider slices with the same gates.
- **WS4b AF_XDP:** keep it on mirror interfaces, prove the achieved mode and
  fallback on the reference NIC, and verify no node-level source can enable it.
- **WS2 buffer and AnalysisJob:** preserve pre-trigger packets within a hard
  disk budget, report complete/truncated/expired windows, and re-analyze
  artifacts at pinned content versions.
- **WS3 storage portability:** revise the interface before a second backend
  and prove write-once semantics through a common conformance suite.
- **WS6 late cloud flows:** ingest with watermarks and idempotency, then
  extract the earlier packet window. It depends on WS1, WS2, and WS3.
- **WS7 TLS session keys:** run only through AnalysisJob with separate
  authorization, ephemeral custody, a non-secret ledger identifier, and
  measured decryption coverage.
- **WS8 per-flow retrieval:** research index cost and authorization first;
  proceed only if both can preserve buffer coverage and evidence isolation.
- **Runtime-security-triggered capture:** dropped from this program. It has
  no implementation slot or acceptance target.

## Extraction Discipline

Constitution Principle VI is the one this program most threatens. It is held by
the following rules, which apply to every workstream after WS1:

1. **One workstream in flight at a time.** A workstream is extracted into
   `specs/NNN-*/` only after its predecessor's feature has merged and its
   measurable outcomes are demonstrated.
2. **The governing ADR precedes the feature.** A workstream whose ADR is not
   accepted is not extracted. The ADR is where the decision the roadmap named as
   a decision gets settled.
3. **No speculative scaffolding.** A workstream may not add an abstraction whose
   only consumer is a later workstream. If WS2's source union needs a shape WS7
   will use, WS2 builds only what WS2 consumes.
4. **Each extraction re-runs the Constitution Check** against its own design,
   not against this program-level assessment.
5. **Each extraction restates its slice of FR-055.** The gates it adds must be
   demonstrated to execute and to fail when violated.

## Phase 0 — Research

`research.md` is required before WS2 is extracted, and must resolve:

| # | Question | Blocks | Method |
|---|---|---|---|
| R-1 | Does the signature analyzer's socket runmode retain flow state across sequentially submitted stored files in 8.x? | ADR-0010, WS2 offline design | Empirical, against 8.0.6, as with the `decoder.bytes` verification |
| R-2 | Dedicated buffer writer vs analyzer-owned packet logging | ADR-0009, WS2 scope | Prototype the analyzer-owned version to learn disk-budget and extraction ergonomics; discard it |
| R-3 | Buffer disk budget and exhaustion behaviour on a Talos node | ADR-0009, FR-018/019 | Measure at the reference rate using the D-002 generator |
| R-4 | Which write-once guarantees all three storage providers can actually hold | ADR-0011, WS3 interface revision | Provider documentation plus a conformance spike against each |
| R-5 | Flow index cost over a rolling buffer | WS8 go/no-go | Research spike; WS8 is not extracted until this concludes |
| R-6 | Achieved-mode detection for the kernel-bypass path | ADR-0012, FR-035 | Empirical on the reference NIC and driver |
| R-7 | First SSH profile capability and readback matrix | ADR-0014, WS5a | Test RouterOS 7 CLI on the reference switch; reject unsupported shapes before mutation |
| R-8 | Node-local cgroup identity and Pod UID mapping feasibility | ADR-0013, WS4a | Spike on Talos, compare against Hubble metadata and pod-churn fixtures |

R-7 precedes WS5a and R-8 precedes any WS4a kernel collector. R-6 precedes
WS4b. R-1, R-2 and R-3 precede WS2; R-4 precedes WS3; R-5 precedes WS8.

## Project Structure

### Documentation (this feature)

```text
specs/002-post-mvp-evolution/
├── spec.md              # Program specification (12 stories, 65 FRs, 19 SCs)
├── plan.md              # This file — sequencing and decomposition
├── research.md          # Phase 0 — required before WS2 extraction
└── checklists/
    └── requirements.md  # Initial draft validation; new slices revalidate
```

Per-workstream features are created by `/speckit.specify` at extraction time:

```text
specs/003-carried-gaps/           # WS0 — US1
specs/004-observation-time/       # WS1 — US2
specs/005-ssh-fabric/             # WS5a — US11
specs/006-pod-attribution/        # WS4a — US12
specs/007-cloud-fabric/           # WS5b — US7
specs/008-afxdp-capture/          # WS4b — US6
specs/009-ring-buffer-analysis/   # WS2 — US3, US4
specs/010-storage-portability/    # WS3 — US5
specs/011-cloud-flow-ingestion/   # WS6 — US8
specs/012-decryption-material/    # WS7 — US9
specs/013-flow-addressable/       # WS8 — US10
```

### Source Code (repository root)

Existing directories each workstream extends. No new top-level structure is
introduced by this program; every workstream lands in the layout already in
place.

```text
api/v1alpha1/                     # WS1 envelope split, WS2 AnalysisJob +
                                  #   CaptureJob extraction, WS4 capture mode,
                                  #   WS6 flow source, WS7 key material
api/v1beta1/                      # NEW — FR-056 version promotion, hub-and-spoke

cmd/
├── controller-manager/           # WS2 AnalysisJob controller registration
├── event-worker/                 # WS1 cursor/dedup, WS6 late flow lister
├── capture-runner/               # WS2 extraction mode
├── sensor-agent/                 # WS1 time fields, WS4 achieved-mode reporting
├── artifact-gateway/             # WS3 credentials, WS8 per-flow retrieval
├── buffer-writer/                # NEW — WS2, second privileged data-plane binary
└── trawlctl/                     # WS2 extraction, WS8 flow retrieval

internal/
├── admission/                    # WS4 FR-034 node-source refusal (CEL),
                                  #   WS5 deviceRef typing
├── audit/                        # WS2 extract records, WS7 decryption records,
                                  #   WS8 per-flow reads
├── authz/                        # WS7 decryption-analyst grant,
                                  #   WS8 flow-granularity authorization
├── capture/                      # WS2 extraction semantics and outcomes
├── config/                       # WS3 credential model (ADR-0006: rolls all
                                  #   config-parsing components together)
├── controller/                   # WS0.2 device contention, WS2 AnalysisJob,
                                  #   WS6 flow source
├── events/                       # WS1 cursor split, WS6 watermark + idempotency
├── fabric/                       # WS5a ssh/ and first profile; WS5b cloud providers
├── observation/                  # WS1 envelope, WS2 boundary marking
├── sensor/                       # WS4 kernel-bypass path and mode detection
├── storage/                      # WS3 interface revision, then gcs/, azure/
├── storagetest/                  # WS3 conformance suite drives the revision
└── telemetry/                    # WS2 buffer pressure, WS4 achieved mode

images/suricata/                  # WS4 libxdp + libbpf build deps, SOURCES.lock

test/
├── integration/                  # WS1 out-of-order batch, WS2 outcome matrix
└── e2e/                          # WS0.4 loud preflight, D-002 generator harness

docs/src/content/docs/adr/        # ADR-0008 .. ADR-0017
```

**Structure Decision**: The existing Kubebuilder v4 single-group layout is
retained. The program plans one API version directory (api/v1beta1 for FR-056),
one new binary (cmd/buffer-writer for WS2), and provider subpackages under
internal/fabric and internal/storage. WS4a may need another collector binary
if R-8 succeeds; that choice belongs to its extracted feature and security
review. No new API group is planned.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|---|---|---|
| Second privileged data-plane binary (`cmd/buffer-writer/`) — Principle VI, "new components require a demonstrated current need" | US3 requires a continuous buffer whose lifetime is independent of any analyzer. Its consumer, US4's AnalysisJob, is delivered in the same increment, so the need is current rather than speculative. | Reusing the signature analyzer's own packet logging ties the evidence buffer to one analyzer's lifecycle, configuration and restarts, making a routine content-refresh restart an evidence gap. R-2 prototypes that option to learn the ergonomics and discards it. |
| Nine-workstream program specification — Workflow item 1 expects a feature-scoped spec | The sequencing constraints are the deliverable. Two workstreams are worthless if built in the wrong order, and several are cheap now and expensive later; nine isolated specs would lose that and rediscover it during implementation. | Nine independent specs were rejected because the dependency graph has no owner in that arrangement. Mitigated by the Extraction Discipline rules, which restore per-workstream vertical slices. |
| API version promotion touching seven resource surfaces at once (FR-056) | The alternative is not fewer changes, it is the same changes spread across eight uncoordinated alpha mutations. | Incremental alpha mutation was rejected because it breaks manifests eight times and produces a conversion webhook written under pressure against a shape nobody planned. |

## Next Actions

1. Finish WS1's occurrence/ingest-time ADR and extracted feature. It is a
   prerequisite for time-correct pod attribution and later evidence features.
2. Complete ADR-0014's SSH profile and credential decisions, run R-7 on the
   reference RouterOS switch, then extract WS5a with FR-057 through FR-060.
3. Draft ADR-0013's attribution contract, run R-8, then extract WS4a with
   FR-061 through FR-064. The eBPF collector is conditional on that spike.
4. Resume WS5b, WS4b, WS2, WS3, WS6, WS7, and WS8 in the delivery order,
   with each slice's ADR and measured exit gate. Do not run a task generator
   against this program-level plan.
