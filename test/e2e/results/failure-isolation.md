---
title: T125 failure isolation evidence
---

# T125: what survives a component failure, and what refuses to

Measured 2026-09-11 against `admin@talos-cluster` (single node `talos-node`,
Kubernetes v1.35.5, Cilium/Hubble 1.18.11), on the build merged as `96ec4f1`.

Every spec asserts both halves of the failure design against one injected fault:
the passive path keeps observing, and everything that records or authorizes
fails closed. The distinction they protect is **evidence versus availability**.
Losing the ability to start a capture during an outage is acceptable; ceasing to
observe while still reporting `Active`, or producing evidence with no audit
record, is not.

## Results

| injected fault | spec | result | duration |
|---|---|---|---|
| artifact gateway removed | `TestAGatewayOutageRefusesDownloadsAndStillCollectsEvidence` | **PASS** | 36.9s |
| event-source egress removed | `TestATriggerSourceOutageDegradesPoliciesAndLeavesMonitoringRunning` | **PASS** | 208.3s |
| controller manager removed | `TestAControllerOutageRefusesMutationsAndLeavesMonitoringRunning` | **PASS** | 23.1s |
| storage (ledger) stopped | `TestALedgerOutageRefusesMutationsAndLeavesMonitoringRunning` | pre-existing | — |
| audit sink stopped | `TestAnAuditOutageRefusesCapturesAndServesNothingUnrecorded` | pre-existing | — |

The last two were already specified before T125 and are deliberately not
duplicated.

## What each one established

**Gateway removed.** A capture requested *during* the outage still ran and still
reached `Completed`. Losing the read path does not lose the evidence — the
artifact exists to be read once the gateway returns. The tap was untouched
throughout; the gateway is not on the capture path.

**Event-source egress removed.** The policy moved to `Degraded` and said exactly
why:

```
phase="Degraded"
SourceConnected=False (SourceDisconnected: the alert query did not answer)
Ready=False (SourceDisconnected)
TapResolved=True (observing on node-eno1)
```

That is the property the spec exists for. A policy that cannot see events must
not keep reporting itself armed, because an operator would read that as coverage
they do not have. The tap stayed `Active` and kept observing throughout.

**Controller manager removed.** The mutation was refused:

```
failed calling webhook "mnetworktap.trawl.cloud": failed to call webhook:
dial tcp 10.110.18.15:443: connect: no route to host
```

Fail-closed working as designed: `failurePolicy: Fail` means an unreachable
webhook refuses the write rather than admitting it unvalidated. The sensor
DaemonSet kept running and the tap kept observing, so an operator loses the
ability to change the installation but not visibility into their network —
which is the right trade at the moment their control plane is broken.

## The injection took five runs, and four failures were the test

Recorded because every one of them looked like a product defect, and the first
would have been filed as one.

1. **Adding a deny policy does nothing.** Kubernetes NetworkPolicy is
   additive-allow: policies union, and one granting nothing grants nothing. An
   `egress: []` policy alongside the shipped `trawl-event-worker` policy — which
   already allows Loki, Hubble Relay, the API server and the audit sink — left
   the union unchanged. The run was read as "armed policies do not report losing
   their event source", which is false.

2. **An established connection survives a policy change.** Cilium governs new
   connections, and the worker's Loki client uses HTTP keep-alive, so it kept
   polling down a connection that predated the change. The worker has to be
   restarted for the policy to mean anything.

3. **Severing all egress kills the worker instead of blinding it.** With no
   route to the API server it never becomes ready, so nothing evaluates policies
   and nothing writes their status — a different fault with a different symptom.

4. **The restore failed on its own serialisation.** The backup was saved as raw
   `kubectl get -o json`, which carries `resourceVersion`, `uid` and `status`;
   applying it after the object had been modified was refused. The assertions
   passed and the cleanup then failed, leaving the worker isolated on a live
   cluster until it was restored by hand.

The working injection removes only the two egress rules reaching Loki (3100) and
Hubble Relay (4245), leaving DNS, the API server and the audit sink. That
produces the fault the spec names: a worker that is up, reconciling, writing
status, and unable to see events.

**A fault-injection test that does not inject is indistinguishable from a system
that tolerates the fault.** Three of the four failures above passed their
assertions about the injection having been applied.

## A product finding from the third failure

When the event worker is **entirely down**, every `CapturePolicy` keeps
reporting `Armed` with zero decisions, indefinitely.

The status tracker is careful here — it treats "no word about this source at
all" as disconnected, on the stated principle that absence of evidence is not
evidence of coverage. But that logic runs *inside the worker*, so a worker that
is not running cannot apply it. Nothing else writes policy status.

This is ordinary Kubernetes behaviour for a controller that is down, and it is
detectable from the Deployment. It is recorded because `Armed` is not an
ordinary status field: it is a claim about detection coverage that an
investigation may later rely on, and it survives the thing that was supposed to
be making it true.

Carried into `docs/release/readiness.md` as a known gap rather than fixed.

## Operational note

A killed injection run leaves the fault in place — `t.Cleanup` covers a failed
assertion, a panic and a timeout, but not SIGKILL. For the trigger-source
injection what is left behind is the worker's NetworkPolicy *deleted*, and the
namespace default-deny then isolates it indefinitely, which looks exactly like
an event source that failed on its own.

`hack/e2e-cleanup.sh` reports a missing component NetworkPolicy and prints the
restore command. Run it after any interrupted acceptance run.
