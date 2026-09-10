# US4 automatic capture: the trigger matrix against a deployed cluster

Measured 2026-09-10 against `admin@talos-cluster` (single node `talos-node`,
Kubernetes v1.35.5, Cilium/Hubble 1.18.11), running the build of `b62bc56` —
controller-manager `sha256:35a32745…`, event-worker `sha256:20f6a909…`, built
by a `workflow_dispatch` of `images.yml` on `us4-trigger-captures` (run
34502775752, analyzers skipped because Zeek and Suricata did not change).

Produced by `test/e2e/automatic_capture_test.go` under the `acceptance` tag.
Every figure below comes from a spec that ran; none was measured by hand.

This is the first US4 evidence taken against a deployed worker. Everything
before it ran against envtest or skipped, because the cluster had no
CapturePolicy CRD.

## What the deploy found before the matrix could run

Worth recording first, because it is the whole argument for this task existing.

**Every automatic capture was refused by admission.** The webhook answered

```
admission webhook "vcapturejob.trawl.cloud" denied the request:
CaptureJob.trawl.cloud "trawl-policy-65ea1b70…" is invalid:
spec.requestType: Forbidden: requestType Policy may only be set by the event worker
```

while the requester genuinely was the event worker. `config/default` carries
`namePrefix: trawl-`, so the worker reaches the cluster as
`trawl-event-worker`, and `capture.eventWorkerServiceAccount` named the
pre-prefix `event-worker` that `config/manager/event-worker.yaml` is written
with. The configuration and the manifest agreed with each other and both
disagreed with the installation.

No unit or integration test could have caught it: every check in
`devconfig_check_test.go` pairs the configuration against those same
pre-kustomize manifests. `TestDevConfigNamesTheEventWorkerIdentityTheOverlayDeploys`
now compares against the transformed name.

It also corrected the ledger. `workerActor` derives the audit actor from the
same field, so the `allowed` record committed immediately before each refusal
named an identity that does not exist. After the fix:

| decision | actor | ledger object |
|---|---|---|
| `allowed` | `…:trawl-event-worker` | `audit/v1/records/20260910T170106.908659763Z-0c37f7fe4c057647.json` |
| `succeeded` | `…:trawl-event-worker` | `audit/v1/records/20260910T170106.991587710Z-ba98afdca12149da.json` |

Two further installation gaps, recorded but not fixed:
`config/dev/trawl-config.yaml` and `config/hubble/` are applied out of band and
the rollout does not carry them. The new binaries require
`eventWorker.auditClient.*`, which the deployed ConfigMap did not have, so both
pods crash-looped on `invalid installation configuration` until it was applied
separately. A fresh install has the same hole and nothing announces it.

## The matrix

Thirteen specs, all passing. Windows 16:50–17:03Z and 17:12–17:15Z.

| spec | trigger | result |
|---|---|---|
| `TestAnArmedSignaturePolicyTurnsAnAlertIntoACapture` | Suricata | **PASS** 38.42s |
| `TestAnAlertOutsideThePolicysFiltersCapturesNothing` | Suricata | **PASS** 55.19s |
| `TestEquivalentAlertsInsideTheCooldownCollapseToOneCapture` | Suricata | **PASS** 55.26s |
| `TestTwoPoliciesMatchingOneAlertShareOneCapture` | Suricata | **PASS** 45.83s |
| `TestAPolicyStopsCapturingAtItsHourlyLimit` | Suricata | **PASS** 59.71s |
| `TestADisarmedPolicyReportsWhatItWouldHaveCapturedAndCapturesNothing` | Suricata | **PASS** 63.09s |
| `TestRestartingTheWorkerDoesNotRecaptureWhatItAlreadyHandled` | Suricata | **PASS** 78.98s |
| `TestDeletingAPolicyLeavesTheEvidenceItCollected` | Suricata | **PASS** 73.34s |
| `TestAPolicyWhoseTapIsGoneReportsDegradedRatherThanQuiet` | Suricata | **PASS** 13.09s |
| `TestThePolicyCapturesCarryADeduplicationKeyTheClusterAccepts` | Suricata | **PASS** 30.55s |
| `TestAnArmedDropPolicyTurnsADeniedFlowIntoACapture` | Hubble | **PASS** 32.96s |
| `TestADropPolicyNarrowedToAnotherNamespaceCapturesNothing` | Hubble | **PASS** 63.50s |
| `TestADropPolicyBelowItsThresholdCapturesNothing` | Hubble | **PASS** 58.42s |

Every capture the matrix produced reached `Completed` with real packets — none
is an empty-capture artifact:

| policy | trigger | bytes | packets | collected |
|---|---|---:|---:|---|
| `…equivalentalertsinsidethec` | SuricataAlert | 144956 | 957 | 16:55:34–45 |
| `…twopoliciesmatchingonealer-a` | SuricataAlert | 118604 | 873 | 16:56:35–45 |
| `…apolicystopscapturingatits` | SuricataAlert | 109536 | 824 | 16:57:19–29 |
| `…apolicystopscapturingatits` | SuricataAlert | 113352 | 827 | 16:57:20–30 |
| `…deletingapolicyleavestheev` | SuricataAlert | 90312 | 745 | 16:59:19–29 |
| `…thepolicycapturescarryaded` | SuricataAlert | 142996 | 946 | 17:00:49–59 |
| `…anarmeddroppolicyturnsaden` | **HubbleDrop** | 151328 | 967 | 17:01:09–20 |
| `…adroppolicynarrowedtoanoth-c` | **HubbleDrop** | 98124 | 781 | 17:01:42–52 |
| `…adroppolicybelowitsthresho-c` | **HubbleDrop** | 517352 | 1255 | 17:02:38–49 |
| `…anarmedsignaturepolicyturn` | SuricataAlert | 134028 | 916 | 17:13:05–15 |
| `…restartingtheworkerdoesnot` | SuricataAlert | 96456 | 800 | 17:13:50–14:00 |

## How the two trigger halves are driven, and why they differ

**Suricata alerts are synthetic; everything downstream is real.** Alerts reach
the worker through the observation pipeline, so the specs push a synthetic
alert observation into Loki rather than trying to trip a specific ET rule. A
real worker polls it, real policies evaluate it, a real CaptureJob is admitted
by the installed webhook, and a real runner collects real packets. The
sensor-to-Loki half is covered where it belongs, in the investigation and
NetworkTap suites, against live traffic.

**Denied flows are not synthetic at all, because they cannot be.** The worker
reads drops from Hubble's live gRPC stream, which has no equivalent of Loki's
push door. These specs make the cluster deny real traffic: a scratch namespace,
a `deny-all-egress` NetworkPolicy, and a prober offering one connection a
second to an address the datapath refuses before it leaves the node. Nothing
external is contacted.

`POLICY_DENIED` was read off this cluster with `hubble observe --verdict
DROPPED` rather than taken from the flow API's enum. The field a policy matches
is the drop reason *description*; the numeric code beside it (`133` here) is
not what any policy is written against.

The drop specs are also the only ones that exercise the worker's egress to
Hubble Relay and its client certificate. The alert specs prove its egress to
Loki — a different NetworkPolicy rule and a different secret.

## Mutation checks

Every new spec was mutated and every mutation failed the spec.

| mutation | expected | observed |
|---|---|---|
| `PolicyTypes` emptied, so nothing is denied | armed drop spec fails | **FAIL**, no capture in 3m, `NotMatched` climbing to 58351 on background traffic alone |
| narrowed policy pointed at the denying namespace | narrowed spec fails | **FAIL**, "captured 1 times" |
| gated policy's threshold dropped 10000 → 1 | threshold spec fails | **FAIL**, the gated policy created `trawl-policy-f0d884a6…` at 17:08:56 |

The first of those is worth keeping. `NotMatched: 58351` in three minutes is
the cluster's ordinary forwarded traffic being evaluated and declined by a drop
policy, and it is exactly what an assertion on that counter would have been
resting on.

## Known gaps this run did not close

- **A thresholded drop policy cannot say it is counting.** A qualifying flow
  held below its threshold records as `OutcomeNotMatched` — the same counter
  the 58351 above lands in. An operator has no way to tell "accumulating
  toward five" from "seeing nothing at all"; the two are identical in status
  and in the metrics derived from it. `TestADropPolicyBelowItsThresholdCapturesNothing`
  deliberately asserts nothing about it, because any assertion available today
  would pass with the prober never started.
- **A `Failed` policy decision emits no log line.** The admission refusal above
  was counted in `status.decisions.failed` and appeared in the audit ledger,
  but the worker logged nothing. The ledger is why the cause was findable at
  all; a component without one would have shown a counter and no explanation.
- **Killing an acceptance run leaks armed policies.** An interrupted run left
  `acc-equivalentalertsinsidethec-626843282` armed, and it matched the next
  run's alert first and won the shared capture — so
  `TestAnArmedSignaturePolicyTurnsAnAlertIntoACapture` failed with
  `Duplicate:1` against a capture belonging to a policy that no longer had a
  test. Cross-policy sharing behaving exactly as
  `TestTwoPoliciesMatchingOneAlertShareOneCapture` asserts it should. The spec
  passed in 38s once the leak was removed. Cleanup is `t.Cleanup`, so only an
  interrupt can leak one; check for `acc-*` policies before re-running.
