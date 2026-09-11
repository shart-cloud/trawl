---
title: "ADR-0007: Trawl configures port mirroring on network devices"
description: A separate PortMirror resource lets Trawl configure SPAN on switches, with the blast-radius controls that earn it under Principle I.
---

**Status**: Accepted · **Date**: 2026-09-11 · **Requirements**: Principle I, Principle II, FR-036

## Context

`NetworkTap` has always had a `MirrorInterface` source type, and it has always
assumed somebody configured the mirror by hand on the switch upstream. That is
the gap this closes: Trawl reaches the device over its API and configures the
SPAN session itself.

The first supported device is a MikroTik CRS328-24P-4S+ on RouterOS 7.24.

It engages Principle I, which says monitoring "MUST NOT modify, block, delay,
or redirect observed traffic" and that "passive capture privileges MUST never
be reused for traffic enforcement".

**On the traffic itself, the principle is satisfied.** A SPAN session copies
frames to an additional port and leaves the forwarding path alone. On this
hardware the copy is performed by the switch chip (Marvell-98DX3236), so it is
not even contending for the control-plane CPU. Nothing observed is modified,
blocked, delayed or redirected.

**On privileges, it is not, and that is the real decision.** RouterOS group
policies are coarse. There is no "may only set a mirror" policy; a user that
can write `mirror-target` holds `write`, which also permits firewall rules,
port states and routing. So the credential Trawl stores is capable of traffic
enforcement even though Trawl never performs any. Compromise of Trawl becomes
the ability to change the network fabric.

That cannot be fixed on the device. It can only be bounded.

## Decision

**Trawl may configure port mirroring, through a separate `PortMirror` resource
with the controls below.**

**1. A distinct kind, separately authorizable.** `PortMirror` is not a
`NetworkTap` source type. The device credential cannot be narrowed, so the
place the gap is actually controllable is Kubernetes RBAC: `port-mirror-admin`
is its own ClusterRole, bound separately, and no capture or policy role grants
`portmirrors`. An installation that never binds it has a Trawl that cannot
reconfigure anything, whatever its device credential permits.

**2. Providers touch nothing but mirroring.** The `fabric.Provider` interface
has three methods - Configure, Observe, Revert - and a driver that also changed
a VLAN, a firewall rule or a port state would be reusing a monitoring
credential for something that is not monitoring. The restraint cannot be
expressed as a device permission, so it lives in code that can be read and in
review.

**3. Status comes from the device, never from the write.** A mirror is `Active`
because the device was read back and reports what was asked for. Principle II
requires it, and the mechanics demand it: on RouterOS a mirror with four
sources is five separate writes with no transaction, so `Configure` returning
success means every request was accepted, not that the device is in the state
requested.

**4. Revert is a precondition of configure.** Deleting a `PortMirror` removes
the mirroring, behind a finalizer. When revert fails the finalizer is *held*:
releasing it would destroy the only record that a switch is still mirroring.

**5. Every device change is audited**, as an intent and an outcome, including
refusals. `portmirror.configure` and `portmirror.revert` are in the telemetry
contract, so the ledger-completeness test covers them like any other action.

**6. Explicit provider registration.** Drivers are constructed in
`cmd/controller-manager` rather than registering themselves on import, so
"which binaries can reconfigure a switch" has an answer somebody can read.

## Consequences

**Trawl now holds a credential that can change network hardware.** That is the
cost, and it is accepted for a homelab where the alternative is configuring
mirrors by hand. An installation unwilling to accept it does not bind
`port-mirror-admin` and does not create the device Secret; nothing else
changes.

**The blast radius is a switch, not a cluster.** A wrong `PortMirror` copies
the wrong traffic to a port, or copies too much to a port that cannot carry it.
It does not interrupt forwarding. The worst realistic outcome is a mirror
target flooded with more than it can take, which affects what is plugged into
that port and nothing else.

**A dead switch leaves an undeletable resource.** Holding the finalizer when
revert fails means a `PortMirror` for a device that has been unplugged cannot
be deleted until the device answers or an operator removes the finalizer by
hand. That is deliberate: the alternative is silently forgetting that a switch
somewhere is still copying traffic.

**Mirroring is not continuously enforced, only periodically observed.** The
controller re-reads every five minutes. Between reads, a hand edit on the
device is neither noticed nor corrected, and captures taken in that window may
be of traffic nobody intended to collect. Reducing the interval narrows the
window; it does not close it, because nothing on a switch sends an event.

**This does not authorize inline prevention.** Principle I's requirement for a
separate specification, blast-radius controls and a tested kill switch applies
to modifying traffic. Copying it is not that, and this ADR does not extend to
anything that is.
