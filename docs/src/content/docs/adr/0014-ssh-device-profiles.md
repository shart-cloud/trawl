---
title: "ADR-0014: SSH device profiles keep commands in reviewed code"
description: A pinned SSH transport can manage a switch only through a model-specific mirroring profile.
---

**Status**: Proposed pending a CRS328 hardware acceptance run · **Date**: 2026-09-24 · **Requirements**: FR-057 through FR-060

## Context

The existing MikroTik provider uses RouterOS 7 HTTPS REST. Some deployments
cannot expose that service but can reach the switch through SSH. SSH is a
transport, not a common switch mirroring API: command syntax and mirror
capabilities differ by device family. PortMirror remains the one resource
authorized to make these changes.

The reference CRS328 has one switch chip, a global mirror target, and per-port
ingress and egress flags. RouterOS CLI can serialize print-as-value output to
JSON. These are the assumptions of the first SSH profile, not claims about all
SSH-capable switches.

## Decision

1. Register MikroTikRouterOS7SSH as a separate provider. Its first profile
   accepts only the reference CRS328 model on RouterOS 7 with one switch chip
   and the required mirroring fields. A new device family needs another
   reviewed profile and acceptance test.
2. Keep transport and command semantics separate. The shared SSH transport
   verifies a host public key pinned in the device Secret and bounds connection,
   command time, and output size. Commands are compiled in the profile. No
   command text or template comes from a PortMirror or Secret.
3. Keep the existing Configure, Observe, Revert, finalizer, device contention,
   and audit path. Active requires readback of each source's direction as well
   as the target. Unknown hardware and incomplete capabilities are refused
   before writing.
4. Do not open controller SSH egress by default. An installation that enables
   the provider applies an explicit egress policy for the device management
   address. The sample uses a documentation address and is not deployed by
   the base kustomization.
5. Require a disposable hardware acceptance run before moving this ADR to
   Accepted. The run must show real copied packets, direction changes,
   idempotent reconcile, host-key refusal, and verified revert.

## Consequences

A reusable connection method does not imply support for every SSH switch.
The pinned key and the fixed command profile narrow who the controller talks
to and what it asks, although the RouterOS account still has more authority
than a mirror-only role could express. Failure to read back or revert holds
the PortMirror in a non-active state or keeps its finalizer.

The static network policy cannot derive a destination from a Secret. Each
deployment must add a narrow, reviewed egress rule for its device address.
