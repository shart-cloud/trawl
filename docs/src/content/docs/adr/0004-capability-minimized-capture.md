---
title: "ADR-0004: Capability-minimized packet capture"
description: Capture runs in short-lived node-pinned Jobs with two Linux capabilities, no API token, and an unprivileged reporter sidecar.
---

**Status**: Accepted · **Date**: 2026-08-29 · **Requirements**: FR-017–FR-024, FR-035, FR-037

## Context

Packet capture needs privileges that most workloads never get. On Talos there
is no host shell to fall back on, so whatever the pod is granted is the whole
story. The temptation is `privileged: true` plus `hostNetwork` — it always
works, and it grants far more than capture requires.

## Decision

Capture runs as a short-lived Kubernetes Job pinned to the node whose tap
target can observe the traffic. The capture container receives only
`CAP_NET_RAW` and `CAP_NET_ADMIN` — enough to open an AF_PACKET socket and set
promiscuous mode, and nothing else. No `privileged`, no hostPath for artifacts,
no blanket host namespace access beyond what the declared source type requires.

**The capture container gets no Kubernetes API credentials at all.** Its service
account token is suppressed. It cannot patch its own status, which is exactly
the point: the privileged process is not also an API client.

Status flows instead through `trawl-capture-reporter`, an unprivileged sidecar
sharing a bounded `emptyDir`. The runner writes atomic progress records; the
reporter validates them against a versioned protocol and patches only its own
CaptureJob status, using a generated Role restricted by `resourceNames` to that
single object.

Capture is passive throughout. The socket observes; it never injects, blocks,
or redirects. A failed capture leaves monitored traffic untouched.

## Alternatives considered

- **`privileged: true` with hostNetwork.** Universally works. Rejected: it
  grants kernel-module loading, arbitrary device access, and full host network
  control to obtain a packet socket.
- **A long-lived privileged capture DaemonSet.** Fewer pod creations. Rejected:
  it keeps capability-bearing pods running when nothing is being captured, and
  couples unrelated captures into one blast radius.
- **Runner patches its own status directly.** One less container. Rejected: it
  hands an API token to the most privileged process in the system.
- **hostPath for capture files.** Simplest handoff. Rejected: it writes evidence
  to a node the operator cannot audit and breaks the immutable-host model.

## Consequences

- Two containers per capture and a bounded shared volume, in exchange for a
  privileged process with no API reach.
- Job and object names derive from the CaptureJob UID, so restart retries
  converge on one execution and one artifact rather than duplicating either.
- Ephemeral storage is bounded; a capture cannot fill a node's disk.
- The reporter's Role is generated per capture and must be cleaned up with it.

## Rollback

Capabilities are pod-spec fields, so rolling back the operator image restores
the previous capture pod shape on the next reconcile. Already-completed
artifacts are unaffected. Any change that widens privileges requires the
security review named in the constitution before merge.
