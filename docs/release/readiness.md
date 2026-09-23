# Trawl release readiness

**Status: not ready.** Ten of eleven measurable outcomes have accepted evidence;
SC-011's existing failure-path evidence is incomplete until the new invalid-source
and invalid-bounds acceptance checks run against the release candidate. SC-003 is
evaluated at the honestly reported rate the installation produced, and SC-005's
criterion is the ten-attempt sample the fixtures actually support.
The WS0.4 implementation and its review corrections passed the complete local
gates on 2026-09-20. On 2026-09-23, the pre-AWS release-prep branch merged the
later upstream supply-chain work and passed `make lint`, `make test`, `make verify`,
and `make security` locally. The release remains blocked on a green tag-triggered
supply-chain workflow and release-candidate cluster validation.

Assembled 2026-09-11 against `admin@talos-cluster` (single node `talos-node`,
Kubernetes v1.35.5, Cilium/Hubble 1.18.11), on the build merged as `96ec4f1`.

This document links to evidence produced by runs that actually happened. Where a
criterion has not been measured it says so; nothing here is inferred from a
shorter or adjacent run. The whole argument of this phase is that a gate nobody
has executed is not a gate, and a checklist that infers is the same failure in a
nicer font.

---

## Measurable outcomes

| | Criterion | Status | Evidence |
|---|---|---|---|
| SC-001 | First structured record within 15 minutes | **pass** | `TestAFirstStructuredObservationArrivesWithinFifteenMinutes` |
| SC-002 | 95% of tap create/update actionable within 2 minutes | **pass** (20/20, p95 39.6s) | `test/e2e/results/reference-load.md` |
| SC-003 | 60 min at the measured produced rate, <1% capture-boundary loss | **pass** — 0.0112% over 60 min at roughly 72 packets/s | `test/e2e/results/reference-load.md` |
| SC-004 | 95% of observations searchable within 30s | **pass** | `test/e2e/results/sc-004-searchability.md` |
| SC-005 | 10/10 exact pivots under 3 minutes | **pass** — p50 2.169s | `test/e2e/results/quickstart.md` |
| SC-006 | 95% of captures start <10s, downloadable <60s | **pass** | `test/e2e/results/manual-capture.md` |
| SC-007 | Captures stop at their bounds | **pass** | `test/e2e/results/manual-capture.md` |
| SC-008 | Trigger dedup, cooldown and hourly limits hold | **pass** | `test/e2e/results/automatic-capture.md` |
| SC-009 | Restart and single-component failure converge | **pass** | `test/e2e/results/failure-isolation.md` |
| SC-010 | Expired artifacts are refused at the deadline and removed within 24h | **pass** — refused and absent within 15s | `test/e2e/results/manual-capture.md`, `test/e2e/results/retention.md` |
| SC-011 | Invalid inputs and unavailable dependencies never claim false health | **partial** — existing filter, target, interface, and dependency paths pass; invalid source and bounds checks await the release-candidate run | `test/e2e/results/manual-capture.md`, `test/e2e/results/failure-isolation.md`, `test/e2e/results/t092-security-review.md` |

### SC-005's accepted sample is bounded by the fixtures

Ten timed attempts: **10 of 10 under budget, p50 2.169s against 3m**. The
sample boundary is a fixture gap, not a hidden claim — five
fixture sessions correlate exactly and only one of those also carries a Suricata
alert, so the signature-to-protocol round trip the protocol describes exists for
one session. The accepted protocol measures one pivot from each end of the five
exactly-correlatable flows. It does not claim ten complete signature/protocol
session pairs, and the test records that limitation in its own output.

---

## SC-003 release decision

The criterion now asks whether the capture boundary holds for 60 minutes at the
rate the installation actually produces, with that rate reported. The evidence
measured **260,034
packets, 29 drops, 0.0112% loss over a full hour**, with the tap Active
throughout. That is roughly **72 packets/s**, ordinary background traffic. It is
not relabelled as a 100 Mb/s run and makes no claim about behavior at that load.
The run predates `trawl_sensor_bytes_total`, so no historical bit rate is
invented; future runs report both packet rate and decoder-accepted byte rate.

---

## Constitutional gates

| Principle | Status | Evidence |
|---|---|---|
| I. Passive and fail-open | **pass** | monitoring survives every injected fault: `test/e2e/results/failure-isolation.md` |
| II. Declarative control and truthful state | **pass, one caveat** | conditions and phases asserted throughout; see "Known gaps" |
| III. Evidence integrity and least privilege | **pass** | `test/contract/security_manifests_test.go`, `test/integration/audit_test.go` |
| IV. Observable and correlatable by design | **pass** | SC-004 and SC-005 above |
| V. Verification at every boundary | **partial** | local contract and integration gates pass; the new SC-011 acceptance checks and release-candidate cluster validation remain open |
| VI. Small, phased, reversible delivery | **pass** | `make undeploy` leaves evidence intact (T122); CRD removal is deliberate |

---

## Security gates

| Gate | Status | Evidence |
|---|---|---|
| No secrets in history | **pass** | gitleaks, 171 commits, 0 findings after four verified false positives |
| No reachable Go vulnerabilities | **pass** | govulncheck, 0 reachable |
| No vulnerable dependencies | **pass** | osv-scanner, 109 packages, 0 advisories |
| No HIGH/CRITICAL in images | **pass** | Trivy, all five binary images |
| Manifest privilege | **pass** | `make manifest-security` + rendered-manifest contract tests |
| Suppressions reviewed and expiring | **pass** | `security/suppressions.yaml` empty; expiry enforced by `hack/verify-suppressions.sh` |
| Release-blocking enforcement | **pass** | 16 required checks on `main`, admin bypass off |

All five security jobs failed the first time they ran and were fixed; see
`tasks.md`. That is the reason this table is worth more than it was yesterday.

---

## Operational gates

| Gate | Status | Evidence |
|---|---|---|
| Runbook | **pass** | `docs/src/content/docs/operations/runbook.md` |
| Evidence handling | **pass** | `docs/src/content/docs/security/evidence-handling.md` |
| Supply-chain manifest | **pending** | the 2026-09-20 Images run generated the manifest but its folded YAML gate made `jq` read empty stdin; the release-prep fix and executable workflow regression pass locally, but a hosted tag-triggered build has not proved the artifact |
| Upgrade and rollback | **pass** | `test/integration/upgrade_rollback_test.go` |
| Quickstart executable | **pass** | every command resolves; `test/e2e/results/quickstart.md` |

---

## Known gaps carried into the release

None of these blocks a release on its own. All are recorded rather than fixed,
and each is a decision someone should make knowingly.

1. **A thresholded drop policy cannot report that it is accumulating.** A flow
   held below its threshold records as `notMatched`, the same counter every
   forwarded flow increments, so "counting toward five" is indistinguishable
   from "seeing nothing".

2. **A `failed` policy decision logs nothing.** It appears only as a status
   counter and an audit record. The ledger is what made the US4 identity defect
   findable at all.

3. **Config schema additions are breaking changes for lagging components.**
   Decided deliberately in ADR-0006; the ordering rule is operational and
   nothing enforces it automatically.

4. **`CapturePolicy` clamps an over-ceiling retention while `CaptureJob` rejects
   one.** The same input gets two answers, and in GitOps the clamp shows as
   permanent drift with no signal that evidence is being deleted early.

5. **Alloy drops entries with `entry too far behind`.** The Loki copy has gaps,
   so exact observation counts must not be asserted from it. Cause still
   unexplained.

---

## Closed after this document was assembled

**A dead event worker no longer leaves policies reporting `Armed`.** The manager
now runs the `capturepolicy-witness`, reads the event worker's lease, and writes
the stale-worker condition only after that lease expires. It writes nothing
while the worker is alive, so the process that knows policy decisions remains
the ordinary status owner.

**`PortMirror` now has a validating webhook** (2026-09-11). It was gap 6 above:
the only kind for which the CRD contract's claim that "the validating webhook
rejects off-namespace resources" was untrue. The controller declined to act on an
off-namespace mirror, but the API server accepted it, so the object existed and
read as configuration that had taken effect.

`vportmirror.trawl.cloud` now enforces the namespace rule, the semantic rules the
schema cannot express on a stored object, `provider` and `deviceRef`
immutability, and the FR-036 audit gate, with `portmirror.create`,
`portmirror.update` and `portmirror.delete` added to the telemetry contract.
Three defects turned up alongside it and are fixed: the reconciler never
re-validated a stored spec before configuring hardware, an off-namespace mirror
reported `Accepted` as the reason it was refused, and a pre-device failure
reported `DeviceReachable=False` about a device that had never been contacted.

**Evidence now includes the live device path, but not the admission rejection.** The
unwired-webhook contract test covers the new path
(`TestEveryConfiguredWebhookIsWiredIntoTheManager`), and
`internal/admission/portmirror_webhook_test.go` covers the rules. A live CRS328
run exercised configure, independent device readback, mirrored packet capture,
normalized Zeek output, audit intent/outcome, and finalizer-driven revert. It
also exposed and led to the narrow `secrets/get` plus uncached-reader fix. The
specific off-namespace rejection has still not been exercised against the
release candidate. That run must confirm the API server refuses it, because
`failurePolicy: Fail` on a new webhook path is also the way to break every
`PortMirror` write in the installation.

---

## Sign-off

Not signed. The measurable-outcome decisions are accepted. Blocking items:

- [x] SC-003 — evaluate the full-hour run at its honestly reported produced rate
- [x] SC-005 — accept the ten-attempt fixture-supported protocol
- [x] Close the remaining WS0.4 code-quality items
- [ ] Run the invalid-source and invalid-bounds SC-011 checks against the release candidate
- [ ] Prove the fixed supply-chain job in a tag-triggered Images workflow
- [x] Rerun `make lint`, `make test`, `make verify`, and `make security` on the pre-AWS release-prep branch (2026-09-23; all pass locally)
- [ ] Rerun PortMirror configure/readback/data/revert, verify packet status, and exercise off-namespace rejection

Non-blocking but worth a decision before release:

- [x] Former gap 1 — the external witness reports a dead worker in policy status
- [ ] Gap 5 — reconcile the retention clamp asymmetry
