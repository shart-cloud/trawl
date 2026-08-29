---
title: "ADR-0005: Analyzer content management"
description: Upstream rules refresh via init containers; site-specific content ships as a versioned OCI artifact overlaid at startup.
---

**Status**: Accepted · **Date**: 2026-08-29 · **Requirements**: FR-041–FR-045

## Context

Suricata rules and Zeek scripts change on a different clock from the analyzer
binaries. ET Open publishes daily; Zeek script packages move independently;
site-specific detection content changes whenever an operator writes a rule.
Rebuilding and redeploying an analyzer image for a rule update is the wrong
granularity.

Talos is immutable and the deployment model is gitops, so anything that mutates
content in place on a node is unavailable. Whatever runs must be reproducible
from declared inputs.

## Decision

Two layers, both resolved at pod startup, neither baked into the analyzer image.

**Layer 1 — upstream, via init container.** A `content-init` container runs
`suricata-update` and the Zeek base script checkout, writing to an `emptyDir`
the analyzer containers mount. Analyzer images ship with no rules or scripts
baked in. The init container records the feed timestamp it fetched.

**Layer 2 — custom, via OCI artifact.** When a NetworkTap declares a custom
content reference, a second init container pulls that OCI artifact by digest
and overlays it onto the upstream content. Custom content is authored in git,
syntax-checked and packaged by CI (`hack/build-custom-content.sh`), and pushed
to a cluster-accessible registry. The digest is the version.

**Merge is ordered and reported.** Custom overlays upstream, never the reverse.
The resolved feed timestamp and custom digest surface in NetworkTap target
health so an operator can see content currency without exec'ing into a pod.

**Failure is asymmetric on purpose.** A missing or corrupt custom artifact must
not stop the analyzer — it starts with upstream-only content and reports the
degradation. A detection gap is bad; a monitoring outage is worse.

**Refresh is a rolling restart.** The operator restarts analyzer workloads on a
configurable schedule to pick up upstream changes. Content is only ever read at
startup, so there is no live-reload path to get wrong.

## Alternatives considered

- **Bake rules into the analyzer image (CI-only).** Fully reproducible and what
  the first draft assumed. Rejected: every ET Open update becomes an image
  build and a cluster rollout, and the image digest stops meaning "this
  software" and starts meaning "this software and that day's rules".
- **A `suricata-update` CronJob, as the architecture doc sketched.** Rejected:
  it needs somewhere mutable and shared to write, which on Talos means either a
  PVC that every analyzer pod contends on or a hostPath the immutable model
  forbids. It also decouples content from pod lifecycle, so a pod can start
  against content that is mid-update.
- **Rules in a ConfigMap.** Native and versioned. Rejected: ET Open is well
  past the 1 MiB object limit, and it makes the API server a content
  distribution system.
- **A CRD for detection content.** The eventual right answer for user-authored
  content lifecycle, and explicitly deferred by the feature spec. Building it
  now would be speculative scaffolding ahead of a demonstrated need.

## Consequences

- Analyzer pods need outbound network access to upstream feeds at startup only.
  After init completes, no runtime internet access is required.
- Pod startup gains a fetch step, so start time depends on feed reachability.
  A feed outage degrades to the previously fetched content in the image layer
  cache where available, and is reported rather than hidden.
- Content currency becomes an observable property of a tap, not a deployment
  assumption.
- Custom content correctness is CI's responsibility. An artifact that fails
  syntax checks is never published, so a broken rule cannot reach a sensor.

## Rollback

Pin the custom content OCI reference to a previous digest and let the next
rolling restart pick it up; the NetworkTap spec change is the rollback. To drop
custom content entirely, remove the reference and the analyzer runs
upstream-only. Rolling back the `content-init` image restores the previous
fetch behavior without touching analyzer binaries.
