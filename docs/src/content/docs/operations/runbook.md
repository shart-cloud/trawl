---
title: Runbook
description: Diagnosing and recovering a Trawl installation, signal by signal.
---

This is the on-call document. Each section names the signal that brings you
here, what it means, what to check in order, and what to do.

Two habits are worth having before the first incident.

**Trawl's output is evidence, so "no data" is a finding, not a null result.** A
quiet dashboard means either that nothing happened or that Trawl stopped
watching, and those have opposite implications for an investigation. Almost
every procedure below exists to tell them apart. When you cannot, say so in the
incident notes rather than reporting a clean network.

**The audit ledger is the record of last resort.** It is write-once and
independent of the Kubernetes objects, so it survives what the cluster does not.
When a resource has been deleted, a controller has restarted, or a status is
lying to you, the ledger is the thing that still knows what happened.

## Quick triage

```bash
# Is the control plane up, and which build?
kubectl get deploy -n trawl-system -o wide

# What does Trawl think about itself?
kubectl get networktaps,capturepolicies,capturejobs -n trawl-system

# The four phases that mean "look closer":
#   NetworkTap     Degraded | Error
#   CapturePolicy  Degraded | RateLimited
#   CaptureJob     Failed
kubectl get networktaps -n trawl-system \
  -o custom-columns=NAME:.metadata.name,PHASE:.status.phase
```

Conditions carry the detail behind a phase. Read them before anything else:

```bash
kubectl get networktap <name> -n trawl-system \
  -o jsonpath='{range .status.conditions[*]}{.type}={.status} ({.reason}: {.message}){"\n"}{end}'
```

---

## A tap is Degraded or Error

**Signal:** `NetworkTap` phase is `Degraded` or `Error`; `trawl_reconcile_total`
shows failures; sensor pods are not `3/3`.

A tap moves out of `Active` when its sensor cannot observe. The condition says
which half is wrong.

| Condition | False means |
|---|---|
| `Accepted` | the spec was refused; the message names the field |
| `TargetsResolved` | no node matched the node selector, or the interface is absent on the node that did |
| `WorkloadReady` | the sensor DaemonSet exists but its pods are not running |
| `AnalyzersHealthy` | a sensor pod is running and Suricata or Zeek inside it is not |
| `PacketsObserved` | the sensor is healthy and has seen no packets |

**Check in this order:**

1. `kubectl describe networktap <name> -n trawl-system` — read the conditions
   and the events together.
2. `kubectl get pods -n trawl-system -l app.kubernetes.io/component=sensor -o wide`
   — is the pod scheduled, and on the node you expected?
3. `kubectl logs <sensor-pod> -n trawl-system -c sensor-agent --tail=100`
4. For `AnalyzersHealthy=False`, the analyzer container is the one to read:
   `-c suricata` or `-c zeek`.

**`TargetsResolved=False` is usually the interface name.** It is validated for
shape at admission but cannot be checked for existence until a pod lands on a
node. Confirm the interface is really there:

```bash
kubectl debug node/<node> -it --image=busybox -- ip -br link
```

**`PacketsObserved=False` on a healthy sensor is the interesting case**, because
it is the one that silently produces an empty investigation. Either the
interface genuinely carries no traffic, or it carries traffic the sensor cannot
see — a mirror that was never configured upstream, or a bond member rather than
the bond. Confirm from the node before concluding the network is quiet.

---

## Packet loss and duplication

**Signal:** `trawl_sensor_kernel_drops_total` rising;
`trawl_sensor_packets_total` far below the link rate.

Kernel drops mean the capture ring filled before userspace drained it. The
sensor is not keeping up, and the records it did produce are a **sample, not a
census** — which changes what an investigation may conclude from an absence.

**Do this:**

1. Confirm it is sustained rather than a burst:
   `rate(trawl_sensor_kernel_drops_total[5m])`.
2. Check the analyzer's CPU against its limit. `sensorAgentResources` in the
   installation ConfigMap is deliberately not a `NetworkTap` field — an
   under-provisioned sensor drops silently, so it is not something a tap author
   can get wrong. Raising it is an installation change.
3. If drops persist at limit, the link is beyond what one sensor can analyze.
   Narrow what is analyzed rather than accepting a lossy census: disable an
   analyzer you are not using, or tap a more specific interface.

**Record the loss in the investigation.** A capture taken during sustained drops
is still evidence, but its gaps are the sensor's, not the network's.

**Duplication** is reported rather than deduplicated. `status.duplication` on a
tap carries `Unknown` until Trawl can assign a state, and `Unknown` is a real
answer — two records describing one packet may be a mirrored path or may be two
genuine transmissions, and Trawl does not guess. Treat a duplicated flow as one
event only after confirming the topology.

---

## Malformed or missing observation records

**Signal:** `trawl_alloy_delivery_failures_total` rising; observations visible
in sensor logs but absent from Loki.

The pipeline is sensor → stdout → Alloy → Loki. Each hop drops different things.

**Check in order:**

1. Is the sensor emitting? `kubectl logs <sensor-pod> -c sensor-agent` should
   show JSON envelopes.
2. Is Alloy shipping them? Its own logs report delivery failures.
3. Is Loki holding them? Query by the contract labels, never by pod or
   namespace:

```logql
{service_name="trawl-observation", source_kind="Suricata"}
```

**The label mistake is the common one.** `namespace` and `pod` are exactly the
high-cardinality labels the telemetry contract forbids, so a query using them
matches nothing and looks like an outage. An earlier investigation lost time to
this and concluded Loki was empty when it was not.

**A known gap:** Alloy intermittently logs `entry too far behind` and Loki
rejects those entries with a 400. The Loki copy therefore has holes. Do not
assert exact observation counts from Loki, and prefer the sensor's own records
when a count has to be exact. The cause is still unexplained.

**Schema-version drops are deliberate.** The pipeline discards envelopes whose
`schemaVersion` it does not recognize rather than storing records it cannot
interpret. If observations vanish immediately after an upgrade, compare the
sensor image against the control-plane image — a sensor newer than the pipeline
produces records the pipeline refuses.

---

## Trigger gaps and policies that are not firing

**Signal:** `trawl_trigger_gap_total` rising; `trawl_trigger_source_connected`
at 0; `trawl_trigger_lag_seconds` climbing; a policy that should have captured
and did not.

Start with the policy's own account of itself:

```bash
kubectl get capturepolicy <name> -n trawl-system -o jsonpath='{.status}' | jq
```

| Phase | Means |
|---|---|
| `Disarmed` | it is evaluating and reporting, but will not capture. This is the default on create, deliberately |
| `Armed` | evaluating and able to capture |
| `Degraded` | its tap is gone, or its event source is disconnected |
| `RateLimited` | it hit `maxCapturesPerHour` |

Then the decision counters, which say what it did with what it saw:

- `matched` — produced a capture request
- `notMatched` — evaluated and declined
- `duplicate` — collapsed into an existing capture
- `rateLimited` — refused by the hourly ceiling
- `failed` — qualified, and the capture could not be created

**`failed` is the one to escalate.** It means the policy did its job and
something downstream refused. **The worker logs nothing for it** — the counter
and the audit ledger are the only evidence — so go to the ledger:

```logql
{service_name="trawl-audit"} |= "capturejob.policy_create" |= "failed"
```

The record's `message` carries the refusal verbatim. An admission rejection here
usually means the installation's `capture.eventWorkerServiceAccount` does not
match the identity the worker actually runs as.

**`trigger_source_connected=0` means the worker lost its event source.** Suricata
alerts arrive by polling Loki; Hubble drops arrive on a live gRPC stream. The
stream is the fragile one — check the worker's egress to Hubble Relay and its
client certificate:

```bash
kubectl get certificate trawl-hubble-client -n trawl-system
kubectl logs deploy/trawl-event-worker -n trawl-system | grep -iv schema_version
```

**Two known blind spots when reading policy status:**

- A thresholded drop policy **cannot tell you it is counting**. A flow held
  below its threshold is recorded as `notMatched`, the same counter every
  forwarded flow in the cluster increments — so `notMatched` is dominated by
  background traffic and "accumulating toward five" looks identical to "seeing
  nothing". To tell them apart, arm an unthresholded copy of the policy
  temporarily and see whether it fires.
- The event worker logs every normalized Hubble observation to stdout. Its own
  diagnostics are in there, but drowned. Filter them out with
  `grep -v schema_version` as above.

---

## Audit ledger backlog and replay

**Signal:** `trawl_audit_backlog_objects` rising;
`trawl_audit_oldest_unforwarded_seconds` climbing;
`trawl_audit_commit_total{result="unavailable"}` non-zero.

**Committing and forwarding are different problems.** Committing writes the
record to the object-locked bucket; forwarding replays committed records into
Loki so they are searchable. A forwarding backlog is a *searchability* problem —
the records are durable and nothing is lost. A commit failure is a
*correctness* problem, because Trawl fails closed.

**Commit failures (`result="unavailable"`) mean mutations are being refused
installation-wide.** This is intended: FR-036 makes an action that cannot be
recorded an action that must not happen. Users will see their tap and capture
requests rejected. Restore the ledger bucket; nothing else will clear it.

```bash
kubectl get deploy minio -n trawl-system
kubectl logs deploy/trawl-controller-manager -n trawl-system | grep -i audit
```

**`trawl_audit_conflict_total` rising is different and worse.** A conflict means
two records claimed one stable key with different content. Retries are expected
and collapse silently; a genuine conflict means something is generating records
that disagree about the same event. Escalate rather than clearing it.

**A forwarding backlog** drains on its own once Loki accepts writes again. The
replayer runs only on the leader, so if the backlog is static rather than
draining, check that a leader exists:

```bash
kubectl get lease -n trawl-system
```

---

## Storage and retention failures

**Signal:** `trawl_artifact_operations_total{result="failure"}` rising;
captures stuck in `Storing`; `trawl_artifact_expiry_lag_seconds` climbing;
`RetentionEnforced=False`.

**A capture stuck in `Storing`** has recorded packets it cannot upload. The
packets are still on the runner pod, and the pod's lifetime is the deadline —
this is recoverable for as long as it lives and not afterwards. Treat it as
urgent.

1. `kubectl get capturejob <name> -n trawl-system -o jsonpath='{.status}' | jq`
2. `kubectl logs <capture-pod> -n trawl-system -c reporter`
3. Check the bucket is reachable and the credential secret is present:
   `kubectl get secret trawl-artifact-storage -n trawl-system`

**`Downloadable=False` on a Completed capture** means the artifact exists but
failed verification against its recorded checksum. Do not hand it to an
investigator: it is either corrupt or not the object the record describes.

**Expiry lag** means the retention sweeper is behind. Artifacts are being kept
past their deadline, which is a compliance question rather than an availability
one — evidence held longer than its policy allows. It is not urgent in the
paging sense and must not be ignored.

**A known asymmetry:** a `CapturePolicy` silently clamps an over-ceiling
retention to the installation maximum, while a `CaptureJob` update rejects the
same value. In a GitOps-managed installation this shows as permanent drift on
the policy manifest, with nothing telling the operator their evidence is being
deleted earlier than the manifest says. If a manifest keeps reverting its
`retention` field, this is why — and the retention actually in force is the
installation ceiling, not what the file says.

---

## Restart and recovery

Trawl is built so that a restart costs continuity, never evidence. What each
component does on restart:

| Component | On restart |
|---|---|
| Controller manager | re-reconciles every object from cluster state; no local state |
| Event worker | resumes from its persisted alert cursor, replaying an overlap so nothing between the last write and the crash is missed |
| Sensor | restarts capture; packets in flight during the gap are not recorded |
| Capture runner | does not resume — a capture interrupted mid-run is `Failed`, never partial |

**A capture interrupted by a restart is `Failed`, not partial.** This is
deliberate: a truncated pcap presented as a complete one is worse than no pcap.
Re-request the capture; the original request's record remains in the ledger.

**The worker's overlap replay may redeliver events.** Deduplication collapses
them downstream, so a redelivered alert does not produce a second capture. If
you see `duplicate` counters rise after a worker restart, that is the mechanism
working.

**After any restart, verify the worker actually reconnected** rather than
assuming it did — `trawl_trigger_source_connected` should return to 1, and a
worker that starts cleanly but never reconnects looks exactly like a quiet
network.

**If the event worker cannot read its cursor**, it says so rather than silently
starting from now. Starting from now would mean every event during the outage
was never evaluated, with nothing recording that.

---

## What to do when the cluster and the status disagree

Believe, in this order: the audit ledger, then the artifact bucket, then live
`kubectl` output, then status fields, then dashboards.

Status is batched and always slightly behind the object it describes.
Dashboards are further behind still and are drawn from Loki, which has known
holes. Neither is wrong to consult; both are wrong to conclude from when the
question is what actually happened.
