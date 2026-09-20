---
title: T126 reference load evidence
---

# T126: reference load acceptance

Measured 2026-09-11 against `admin@talos-cluster` (single node `talos-node`,
Kubernetes v1.35.5), on the build merged as `96ec4f1`. Tap `node-eno1`,
`NodeInterface` on `eno1`.

Produced by `test/e2e/reference_load_test.go` under the `acceptance` tag, gated
behind `TRAWL_E2E_REFERENCE_LOAD=1`.

## SC-002 — traffic-source changes reach an actionable state

> At least 95% of valid traffic-source creations and updates reach `Active` or
> an actionable non-active state within 2 minutes.

`TestReferenceLoadSC002TapTrialsReachActiveWithinTwoMinutes`, 20 trials: one
create and nineteen updates, each alternating an analyzer so every update is a
real generation bump rather than a write the controller can skip.

| measure | value |
|---|---|
| trials | 20 |
| passed | **20 (100.0%)** |
| budget | 2m0s |
| p50 | 17.596s |
| p95 | 39.562s |
| max | 39.562s |

**PASS.** The p95 is the figure worth keeping: it covers an update that toggles
an analyzer, which restarts the sensor DaemonSet. A change that only edits
metadata settles in seconds; a change that reschedules a workload takes most of
the forty.

## SC-003 — sustained observation, loss and availability

> During a 60-minute test at whatever sustained traffic rate the installation
> produces, active sources remain available and report less than 1% packet loss
> at the capture boundary; the evidence reports the measured rate.

`TestReferenceLoadSC003LossStaysUnderOnePercent`, one 60-minute window,
counters read from the sensor's own `/metrics` over a port-forward.

| measure | value |
|---|---|
| window | 1h0m0s |
| packets observed | 260,034 |
| measured packet rate | **approximately 72 packets/s** |
| dropped at the capture boundary | **29** |
| loss | **0.0112%** |
| budget | 1.00% |
| tap availability | held for the full hour |

**PASS at the measured produced rate.**

### Scope of the measured rate

This run was performed before Trawl exported its observed-byte counter, and the
tap observes a physical node interface that in-cluster load does not traverse.
The only measured rate supported by this historical evidence is therefore the
packet rate above. No bit rate is inferred.

1. **This build exported no observed-byte counter.** Its telemetry contract had
   `trawl_sensor_packets_total` and no bytes equivalent; the only byte metric
   was `trawl_capture_size_bytes`, which is artifact size. A bit rate cannot be
   reconstructed from this historical run.

2. **The tap observes a physical node interface.** In-cluster load traverses
   Cilium's veth path and never appears on `eno1`, so an in-cluster generator
   measures nothing. Reaching 100 Mb/s needs the external, isolated traffic
   source the quickstart calls for, which this installation does not have.

260,034 packets in an hour is roughly 72 packets per second — ordinary homelab
background traffic, not a 100 Mb/s load. **The evidence is a claim that the
capture boundary held at this ambient produced rate and nothing more.** The
amended SC-003 makes that scope the criterion instead of silently attaching an
unmeasured reference rate to the run.

The test states this in its own output, so evidence transcribed from a run
cannot silently become a claim the run does not support.

Current release candidates export `trawl_sensor_bytes_total`; future executions
of the acceptance test report both packets/s and decoder-accepted bit/s. The
latter remains an analyzer counter rather than a wire counter and is always read
beside kernel drops.

## A note on the counters

The sensor's lifetime totals at the start of the window were 4,266,793 packets
against 13,757 drops — 0.32% cumulative. That is *not* evidence for SC-003: it
spans an unknown period including the sensor's startup and any earlier load,
and it is recorded here only so the window's own figures are not mistaken for
the sensor's whole history.

Both figures are read from `trawl_sensor_packets_total` and
`trawl_sensor_kernel_drops_total`, which are the counters the criterion's
phrase "at the capture boundary" names: drops counted by the kernel when the
capture ring filled before userspace drained it.
