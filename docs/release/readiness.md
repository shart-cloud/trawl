# Trawl release readiness

**Status: not ready.** Eight of nine measurable outcomes pass with evidence.
SC-003 passes on its loss and availability clauses and its rate clause cannot
be verified on this architecture at all; SC-005 passes on a smaller sample than
specified. Both need a decision rather than more testing.

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
| SC-003 | 60 min at 100 Mb/s, <1% capture-boundary loss | **partial** — loss 0.0112% over 60 min, rate unverified | `test/e2e/results/reference-load.md` |
| SC-004 | 95% of observations searchable within 30s | **pass** | `test/e2e/results/sc-004-searchability.md` |
| SC-005 | Exact correlation under 3 minutes | **pass, reduced sample** | `test/e2e/results/quickstart.md` |
| SC-006 | 95% of captures start <10s, downloadable <60s | **pass** | `test/e2e/results/manual-capture.md` |
| SC-007 | Captures stop at their bounds | **pass** | `test/e2e/results/manual-capture.md` |
| SC-008 | Trigger dedup, cooldown and hourly limits hold | **pass** | `test/e2e/results/automatic-capture.md` |
| SC-009 | Restart and single-component failure converge | **pass** | `test/e2e/results/failure-isolation.md` |

### SC-005 passed on a smaller sample than specified

Ten timed attempts, not the specified twenty: **10 of 10 under budget, p50
2.169s against 3m**. The shortfall is a fixture gap, not a shortcut — five
fixture sessions correlate exactly and only one of those also carries a Suricata
alert, so the signature-to-protocol round trip the protocol describes exists for
one session. Reaching twenty means writing nine more hand-built analyzer
fixtures. Recorded in the test's own output so evidence transcribed from it
cannot claim otherwise.

**Release decision required:** accept the reduced sample, or fund the fixtures.

---

## What cannot be verified here

**SC-003's rate clause.** Two independent reasons, neither of which a test can
work around:

1. **Trawl exports no observed-byte counter.** The telemetry contract has
   `trawl_sensor_packets_total` and no bytes equivalent; the only byte metric is
   `trawl_capture_size_bytes`, which is artifact size. "100 Mb/s observed" is
   not computable from Trawl's own signals at all.
2. **The tap observes a physical node interface.** In-cluster load traverses
   Cilium's veth path and never appears on `eno1`, so generating 100 Mb/s needs
   the external isolated traffic source the quickstart calls for and this
   installation does not have.

The *loss* and *availability* clauses were measured and passed: **260,034
packets, 29 drops, 0.0112% loss over a full hour**, with the tap Active
throughout. But that is roughly 72 packets per second - ordinary background
traffic, nowhere near the reference rate. It is evidence that the capture
boundary is sound at ambient load and says nothing about 100 Mb/s. A run
reporting 0.0112% and declaring SC-003 met would retire the criterion without
exercising it.

**Release decision required**, and there are two workable answers:

- provision an external traffic source on the tapped segment *and* add an
  observed-byte counter to the telemetry contract, so the rate becomes both
  generatable and measurable; or
- amend SC-003 to a criterion this architecture can measure - a
  packets-per-second floor with the same loss ceiling would test the same
  property of the capture path without requiring a bit-rate Trawl cannot see.

---

## Constitutional gates

| Principle | Status | Evidence |
|---|---|---|
| I. Passive and fail-open | **pass** | monitoring survives every injected fault: `test/e2e/results/failure-isolation.md` |
| II. Declarative control and truthful state | **pass, one caveat** | conditions and phases asserted throughout; see "Known gaps" |
| III. Evidence integrity and least privilege | **pass** | `test/contract/security_manifests_test.go`, `test/integration/audit_test.go` |
| IV. Observable and correlatable by design | **pass** | SC-004 and SC-005 above |
| V. Verification at every boundary | **pass** | contract, integration, acceptance and investigation suites all run in CI or are gated and executed |
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
| Supply-chain manifest | **pass** | `hack/supply-chain-manifest.sh`, CI job on every image build |
| Upgrade and rollback | **pass** | `test/integration/upgrade_rollback_test.go` |
| Quickstart executable | **pass** | every command resolves; `test/e2e/results/quickstart.md` |

---

## Known gaps carried into the release

None of these blocks a release on its own. All are recorded rather than fixed,
and each is a decision someone should make knowingly.

1. **A dead event worker leaves every policy reporting `Armed`.** The status
   tracker treats "no word about the source" as disconnected, but that logic
   runs *inside* the worker, so a worker that is entirely down cannot apply it.
   An operator sees coverage they do not have. Ordinary Kubernetes behaviour for
   a controller that is down — but `Armed` here is a coverage claim an
   investigation later relies on.

2. **A thresholded drop policy cannot report that it is accumulating.** A flow
   held below its threshold records as `notMatched`, the same counter every
   forwarded flow increments, so "counting toward five" is indistinguishable
   from "seeing nothing".

3. **A `failed` policy decision logs nothing.** It appears only as a status
   counter and an audit record. The ledger is what made the US4 identity defect
   findable at all.

4. **Config schema additions are breaking changes for lagging components.**
   Decided deliberately in ADR-0006; the ordering rule is operational and
   nothing enforces it automatically.

5. **`CapturePolicy` clamps an over-ceiling retention while `CaptureJob` rejects
   one.** The same input gets two answers, and in GitOps the clamp shows as
   permanent drift with no signal that evidence is being deleted early.

6. **`PortMirror` has no admission webhook.** The other three kinds refuse an
   off-namespace resource at admission; this one relies on the controller
   declining to act on one. A `PortMirror` in `default` is accepted by the API
   server and then ignored, which is weaker than the refusal the others give.
   The switch-configuring feature is new (ADR-0007) and this is its sharpest
   loose end.

7. **Alloy drops entries with `entry too far behind`.** The Loki copy has gaps,
   so exact observation counts must not be asserted from it. Cause still
   unexplained.

---

## Sign-off

Not signed. Blocking items:

- [ ] SC-003 — provision an external traffic source and a byte counter, or amend the criterion
- [ ] SC-005 — accept the ten-attempt sample or fund the fixtures

Non-blocking but worth a decision before release:

- [ ] Gap 1 — decide whether a dead worker should be visible in policy status
- [ ] Gap 5 — reconcile the retention clamp asymmetry
