---
title: "ADR-0001: Normalized observation envelope"
description: Suricata and Zeek records are normalized into one versioned envelope by a sensor sidecar before reaching Alloy.
---

**Status**: Accepted · **Date**: 2026-08-29 · **Requirements**: FR-009–FR-016

## Context

Suricata EVE JSON and Zeek JSON describe the same traffic with different field
names, nesting, and timestamp conventions. Analysts must correlate across both
and pivot in a single Grafana view.

Shipping raw analyzer JSON to Loki and reconciling the shapes at query time was
the obvious cheap option, and is what the root architecture document sketched.
It pushes the difference onto every dashboard query, means each new analyzer
version can silently change the query contract, and gives no place to redact
sensitive fields or mark suspected duplicates before storage.

## Decision

A `trawl-sensor-agent` sidecar in every analyzer pod normalizes records into a
single versioned envelope, `trawl.observation/v1alpha1`, defined normatively by
`contracts/observation.schema.json` and embedded in the binary.

The envelope fixes a common source, target, timestamp, and flow shape and
carries analyzer-native detail in a subtype-specific body. It preserves both
the analyzer's event time and Trawl's observation time so clock skew stays
visible. Community ID is preserved wherever the analyzer derives it, which is
what makes exact cross-analyzer pivots possible.

Normalization happens before Alloy. That placement is the point: it is the only
stage that sees the record while it still has pod context, so it is where
redaction, duplicate-fingerprint marking, and per-target health counters belong.

## Alternatives considered

- **Raw analyzer JSON, reconcile at query time.** Cheapest to build. Rejected:
  the correlation contract would live in dashboard queries rather than a tested
  schema, and there would be no pre-storage redaction point.
- **Normalize in Alloy with river/OTTL stages.** No extra binary. Rejected:
  the transformation is complex and version-dependent, Alloy config is far
  harder to unit-test than Go, and Alloy has no access to per-target health.
- **Normalize in a central service after Loki.** Rejected: it would need to
  re-read everything already stored, and a central component failure would take
  down ingestion for every tap, violating the failure-isolation constraint.

## Consequences

- Every analyzer pod carries a sidecar. Its resources come from installation
  config, not the NetworkTap CRD, so operators cannot under-provision it per tap.
- The schema is a compatibility commitment within `v1alpha1`. Additive fields
  need defaulting plus old-record tests; a breaking shape needs a new version.
- Dashboards and LogQL templates depend on the envelope, so schema changes and
  dashboard changes must land together and are drift-checked (T027).
- Malformed analyzer records are rejected at this boundary with a sanitized
  diagnostic hash and a counter, never by dropping the whole stream.

## Rollback

The envelope version is explicit in every stored record, so a rollback to a
previous sensor-agent digest leaves already-stored observations readable. Roll
back by restoring the prior image digest through the NetworkTap generation. Do
not remove envelope fields in place — supersede the version instead.
