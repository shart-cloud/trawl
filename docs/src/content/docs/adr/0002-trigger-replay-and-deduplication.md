---
title: "ADR-0002: Trigger replay and deduplication"
description: Persistent cursors, direction-neutral flow keys, and cooldown buckets make automatic capture restart-safe and exactly-once within a window.
---

**Status**: Accepted · **Date**: 2026-08-29 · **Requirements**: FR-026–FR-034

## Context

Automatic capture reads two event sources with different delivery semantics:
Loki range queries over Suricata alerts (pull, repeatable, timestamp-ordered
with ties) and a Hubble `GetFlows` gRPC stream (push, lossy across reconnects).

The event worker restarts — on rollout, leader handoff, or node drain. Without
persistent position and identity, a restart either replays events and creates
duplicate captures, or skips the gap and loses evidence. Several policies can
also match one event, and a burst of near-identical alerts describes one
incident, not fifty.

## Decision

**Cursors.** The worker persists a Loki cursor in a ConfigMap and re-queries a
deliberate overlap window on resume. Overlap guarantees no gap; a per-event
fingerprint suppresses the re-delivered records inside it. Timestamp ties are
resolved by fingerprint, not by ordering assumptions. Hubble reconnects use an
event-time watermark and report unrecoverable loss explicitly rather than
pretending continuity.

**Deduplication identity is the traffic, not the policy.** The key is a
canonical direction-neutral five-tuple plus the tap, hashed into a cooldown
bucket. Two policies matching the same flow collapse to one execution: the
first creates it, the rest record a suppression reference. This is deliberate —
the analyst wants one pcap of the incident, not one per matching rule.

**Deterministic names.** The CaptureJob name derives from that key and bucket,
so a create-or-get against the API server is the deduplication primitive. etcd
does the mutual exclusion, not in-process state.

**Rate accounting rebuilds from the API.** Hourly counts and active-capture
counts are reconstructed by listing CaptureJobs at startup, so limits survive
restarts without a separate store.

## Alternatives considered

- **In-memory dedupe cache.** Simple. Rejected: a restart inside the cooldown
  window creates duplicate captures, and there is no leader-handoff safety.
- **Policy-scoped dedupe key.** Matches the mental model "one policy, one
  capture". Rejected: N policies on one alert produce N near-identical pcaps of
  the same packets.
- **Consuming Suricata alerts directly from the sensor rather than Loki.**
  Lower latency. Rejected: it couples trigger evaluation to every tap pod and
  loses the replay property that makes restarts safe.
- **Exactly-once via a distributed lock or lease.** Rejected: deterministic
  names plus create-or-get already give exactly-once within a bucket, with less
  machinery and no lock to leak.

## Consequences

- Automatic captures are exactly-once per (traffic, tap, cooldown bucket) and
  at-least-considered across restarts.
- A cooldown bucket boundary can admit a second capture for continuing traffic.
  That is intended: a long incident should produce periodic evidence.
- Cursor loss degrades to the overlap window, which is bounded and observable
  as a known gap rather than silent loss.
- The worker needs ConfigMap write access for the cursor — a narrow grant, but
  it must be scoped by resource name.

## Rollback

Cursors are data, not schema. Deleting the cursor ConfigMap makes the worker
resume from now, losing backlog but never creating duplicates. Rolling back the
worker image is safe because dedupe identity lives in CaptureJob names already
persisted in the cluster.
