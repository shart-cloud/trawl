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
feature. What this plan authorizes is the extraction of WS0 and WS1, and nothing
beyond them, because the later workstreams depend on decisions the earlier ones
produce.

## Technical Context

**Language/Version**: Go 1.26.7

**Primary Dependencies**: controller-runtime 0.24.1, Kubernetes API 0.36.0, Cilium/Hubble 1.18.11, MinIO Go client 7.3.0, Prometheus client 1.24.1, jsonschema/v6

**Storage**: MinIO-compatible object storage for artifacts and the write-once ledger; Loki for observations; node-local disk for the continuous buffer introduced in WS2

**Testing**: Go unit tests, envtest control-plane integration tests under `test/integration/`, e2e acceptance under `test/e2e/` against an isolated Kind or Talos cluster, storage conformance under `internal/storage/storagetest/`, telemetry contract tests under `internal/telemetry/`

**Target Platform**: Talos Linux on Kubernetes; no SSH, no host shell, no host package installation

**Project Type**: Kubebuilder v4 single-group operator with seven satellite binaries

**Performance Goals**: Sustained capture at the reference rate with under 1% loss at the capture boundary, verified with the acquired traffic generator (D-002); the continuous buffer must not become the limiting factor on retained coverage

**Constraints**: Passive only; bounded disk for the buffer with no path to host storage exhaustion; low-cardinality telemetry labels; strict configuration decoding, so a schema change rolls every config-parsing component

**Scale/Scope**: Homelab reference cluster. Nine workstreams, ten user stories, 57 functional requirements, 17 measurable outcomes, ten new architecture decision records, one API version promotion.

## Constitution Check

*GATE: evaluated against `.specify/memory/constitution.md` v1.0.0 before Phase 0.*

| Principle | Applies to | Assessment |
|---|---|---|
| **I. Passive and Fail-Open** | WS2 buffer writer, WS4 kernel-bypass capture | **Attention required.** WS4 takes an interface away from the host during operation. On a mirror port that is passive; on a node port it severs the node. FR-034 refuses it at admission for node-level sources. The buffer writer is a receive path only and adds no transmit capability. No workstream introduces traffic modification. **Pass, conditional on FR-034 being enforced at admission rather than documented.** |
| **II. Declarative Control and Truthful State** | Every workstream | The program's organizing purpose. FR-001/002 close two status lies; FR-016/017 make partial extraction a first-class outcome; FR-035 reports achieved rather than requested mode; FR-050 reports partial decryption coverage; FR-054 reports partial flow coverage. **Pass.** |
| **III. Evidence Integrity and Least Privilege** | WS2, WS3, WS5, WS7, WS8 | FR-021 routes extracts through the existing storage, authorization, retention and ledger path rather than a parallel one. FR-047 splits decryption from capture-read. FR-049 forbids key material in storage, layers, logs, status and metrics. FR-052 authorizes per-flow reads at flow granularity. FR-030 refuses a storage provider that cannot hold the write-once guarantee rather than weakening it. **Pass.** |
| **IV. Observable and Correlatable by Design** | WS1, WS2, WS3, WS5 | FR-018 reports buffer storage pressure; FR-020 makes coverage gaps discoverable; FR-025 marks segment-boundary-affected records; FR-041 reports mirrored volume. Correlation values remain structured fields, not index labels. **Watch item:** WS8's flow index is a new high-cardinality surface and must keep flow identifiers as structured metadata. |
| **V. Verification at Every Boundary** | Every workstream | FR-055 requires each new gate to be demonstrated executing — written directly against the MVP's finding of six silently skipping contract tests. FR-004 converts silent environmental skips to loud failures. D-002 acquires the generator that makes the throughput criterion verifiable rather than nominal. **Pass.** |
| **VI. Small, Phased, Reversible Delivery** | Program structure | **Attention required.** This is the principle most at risk from a nine-workstream program. Mitigated by extracting one workstream at a time, and by authorizing only WS0 and WS1 extraction now. FR-056's single version promotion needs an explicit upgrade, rollback and cleanup definition before implementation, per the principle's third sentence. **Pass, conditional on the extraction discipline below being followed.** |

### Platform and security constraints

- **Baseline replacement**: WS3 adds storage providers beyond the MinIO-compatible baseline, and WS5 adds fabric providers beyond MikroTik. Both are additive implementations behind existing interfaces, not baseline replacements, so neither triggers the replacement clause. ADR-0011 and ADR-0014 document them regardless.
- **Privileged workloads**: WS2's buffer writer and WS4's kernel-bypass path both request host access. Each requires an explicit capability justification and confinement to the existing privileged namespace and eligible targets. Neither may reuse capture privilege for any other purpose.
- **API compatibility**: the cumulative changes exceed what `v1alpha1` can absorb compatibly. FR-056 requires one promotion to `v1beta1` with a conversion path. This is the constraint's documented-migration requirement, and it is why the version decision is made in WS1 rather than discovered in WS6.
- **Credentials**: WS3's workload identity and WS5's per-provider credentials both come from the cluster secret-management boundary. WS7's key material is stricter still — memory-backed and bounded by the run's lifetime.
- **Capture bounds**: WS2 extends capture semantics, so extraction requests inherit the existing duration and size bounds, and the buffer adds a disk budget as a third bound.

**Security review required** (per Workflow item 4) for: WS2 (new privileged binary, new evidence path), WS3 (credential model change), WS4 (privileged capture mode, node-severing failure mode), WS5 (external infrastructure mutation), WS7 (key custody, new RBAC grant), WS8 (authorization granularity below what RBAC expresses).

## Delivery Sequence

Ordering under D-001 (portfolio and conference artifact). Deviations from the
roadmap's recommended order are marked and justified.

| # | Workstream | Story | Depends on | Extract when |
|---|---|---|---|---|
| 1 | WS0 Carried gaps | US1 | — | Now |
| 2 | WS1 Observation time model | US2 | WS0 | Now |
| 3 | WS5 Cloud fabric providers ⬆ | US7 | WS0.2 | After WS1 lands |
| 4 | WS4 Kernel-bypass capture ⬆ | US6 | WS0.3, D-002 generator | After WS5 lands |
| 5 | WS2 Ring buffer + AnalysisJob ⬇ | US3, US4 | WS1, ADR-0009/0010 | After WS4 lands |
| 6 | WS3 Storage portability ⬇ | US5 | — (pulled ahead of WS6) | After WS2 lands |
| 7 | WS6 Cloud flow ingestion | US8 | WS1, WS2, WS3 | After WS3 lands |
| 8 | WS7 TLS key material | US9 | WS2 (AnalysisJob) | After WS6 lands |
| 9 | WS8 Flow-addressable evidence | US10 | WS2, research | After research concludes |

⬆ promoted under D-001 ⬇ demoted under D-001

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
   its own. Delivered at position 4, kernel-bypass capture benefits the
   signature analyzer only, and the protocol analyzer stays on the existing path
   until WS2 lands. Accepted: the demonstrable artifact is the achieved-mode
   reporting and the throughput number, both of which work with one analyzer.

2. **The largest functional gap ships fifth.** Capturing the packets that
   preceded a detection is the product's biggest missing capability, and under
   this ordering it lands after two workstreams that are more visible but less
   useful. If the audience answer changes, WS2 is the first thing to promote.

3. **Storage portability is deferred behind cloud mirroring.** WS5 does not
   depend on WS3, so this is safe, but it means the platform demonstrates cloud
   mirroring while still bound to one storage provider. WS3 is pulled ahead of
   WS6 because cloud flow ingestion reads from provider buckets and wants the
   workload-identity credential model already in place.

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

R-6 is required before WS4 (position 4). R-1, R-2 and R-3 are required before
WS2 (position 5). R-4 before WS3. R-5 before WS8.

## Project Structure

### Documentation (this feature)

```text
specs/002-post-mvp-evolution/
├── spec.md              # Program specification (10 stories, 57 FRs, 17 SCs)
├── plan.md              # This file — sequencing and decomposition
├── research.md          # Phase 0 — required before WS2 extraction
└── checklists/
    └── requirements.md  # Spec quality validation (all items pass)
```

Per-workstream features are created by `/speckit.specify` at extraction time:

```text
specs/003-carried-gaps/           # WS0 — US1
specs/004-observation-time/       # WS1 — US2
specs/005-cloud-fabric/           # WS5 — US7
specs/006-afxdp-capture/          # WS4 — US6
specs/007-ring-buffer-analysis/   # WS2 — US3, US4
specs/008-storage-portability/    # WS3 — US5
specs/009-cloud-flow-ingestion/   # WS6 — US8
specs/010-decryption-material/    # WS7 — US9
specs/011-flow-addressable/       # WS8 — US10
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
├── fabric/                       # WS5 aws/, azure/, gcp/ beside mikrotik/
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
retained. The program adds one API version directory (`api/v1beta1/` for
FR-056), one binary (`cmd/buffer-writer/` for WS2), and provider subpackages
under the two existing provider interfaces (`internal/fabric/`,
`internal/storage/`). Everything else extends packages already present. No
workstream requires a layout change, and the multi-group conversion described in
`AGENTS.md` is not triggered, because every new kind stays in the `trawl.cloud`
group.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|---|---|---|
| Second privileged data-plane binary (`cmd/buffer-writer/`) — Principle VI, "new components require a demonstrated current need" | US3 requires a continuous buffer whose lifetime is independent of any analyzer. Its consumer, US4's AnalysisJob, is delivered in the same increment, so the need is current rather than speculative. | Reusing the signature analyzer's own packet logging ties the evidence buffer to one analyzer's lifecycle, configuration and restarts, making a routine content-refresh restart an evidence gap. R-2 prototypes that option to learn the ergonomics and discards it. |
| Nine-workstream program specification — Workflow item 1 expects a feature-scoped spec | The sequencing constraints are the deliverable. Two workstreams are worthless if built in the wrong order, and several are cheap now and expensive later; nine isolated specs would lose that and rediscover it during implementation. | Nine independent specs were rejected because the dependency graph has no owner in that arrangement. Mitigated by the Extraction Discipline rules, which restore per-workstream vertical slices. |
| API version promotion touching seven resource surfaces at once (FR-056) | The alternative is not fewer changes, it is the same changes spread across eight uncoordinated alpha mutations. | Incremental alpha mutation was rejected because it breaks manifests eight times and produces a conversion webhook written under pressure against a shape nobody planned. |

## Next Actions

1. Accept or amend this plan's Delivery Sequence, particularly the D-001 promotions and their recorded costs.
2. Extract **WS0** — `/speckit.specify` for the carried gaps, including the D-002 traffic generator as a prerequisite rather than a side task. Two of the four items (the external witness, the observed-byte counter) are already delivered on `phase7-carried-gaps`; the feature covers device contention and the §0.4 list.
3. Draft **ADR-0008** (event time vs ingest time, lateness bounds, which clock governs rate limits and dedup) and **ADR-0017** (v1beta1 promotion and conversion strategy). WS1 is not extracted until both are accepted.
4. Do **not** run `/speckit.tasks` against this plan. Run it against each extracted workstream feature.
