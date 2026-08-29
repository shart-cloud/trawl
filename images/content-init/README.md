# content-init

Resolves analyzer detection content at pod startup (ADR-0005).

## Why an init container rather than a CronJob

The architecture sketch used a `suricata-update` CronJob. On Talos that needs
somewhere mutable and shared to write: either a PVC every analyzer pod contends
on, or a hostPath the immutable-host model forbids. It also decouples content
from pod lifecycle, so a pod can start against content that is mid-update.

Running as an init container ties content resolution to the pod that consumes
it. The analyzer cannot start against half-written rules, and the content a pod
is running is a property of that pod rather than of the cluster's history.

## Layers

1. **Upstream** — `suricata-update` for Suricata rules, a pinned git checkout for
   Zeek base scripts. Always runs. Records the feed timestamp.
2. **Custom** — an OCI artifact pulled by digest with `oras`, overlaid on top.
   Only runs when the NetworkTap declares a reference.

Custom overlays upstream, never the reverse, so a site can suppress a noisy
upstream rule.

## Failure behaviour

A missing or corrupt custom artifact does not fail the pod. The analyzer starts
with upstream-only content and the degradation is reported through NetworkTap
target status (FR-043). A detection gap is bad; a monitoring outage is worse.

An empty upstream layer *does* fail. An analyzer with no rules looks healthy
while detecting nothing, which is the worse failure mode.

## Build

The image expects a `trawl-build` stage supplying `/workspace/trawl-content`.
It is built by `make docker-build-content-init`, which supplies that stage from
the root `Dockerfile`.
