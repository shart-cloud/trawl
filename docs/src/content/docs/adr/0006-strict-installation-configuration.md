---
title: "ADR-0006: Installation configuration is decoded strictly"
description: An unrecognised field in the installation ConfigMap is a startup error, which makes a config schema addition a breaking change for any component not yet upgraded.
---

**Status**: Accepted · **Date**: 2026-09-11 · **Requirements**: FR-036, constitution "Fail closed"

## Context

Three binaries read the installation ConfigMap: the controller manager, the
event worker and the artifact gateway. `config.Load` decodes it with
`yaml.UnmarshalStrict`, so a field none of them recognises is a hard startup
error rather than a warning.

This was not a decision anyone had written down, and in September 2026 it cost
a day of silent breakage. US4 added `eventWorker` to the ConfigMap and rolled
the two components whose *code* had changed. The artifact gateway's code had
not changed, so it stayed on its previous image — and from the moment the
ConfigMap was applied, that image could no longer parse its own configuration.

Nothing showed it. A running pod never re-reads its config, so the gateway
carried on serving from memory. The fault only appeared days later when a
failure-injection test restarted the pods and they came back crash-looping on
`unknown field "eventWorker"`. Had that test not existed, the next trigger
would have been an eviction or a node drain, at an arbitrary hour, with nothing
connecting the symptom to the change that caused it.

That raised the question this ADR settles: should decoding stay strict?

The case for relaxing it is real. Additive config changes are the common kind,
and under strict decoding each one is a breaking change for any component
lagging a rollout — a self-inflicted outage triggered not by the change but by
an unrelated restart, which is the worst shape of failure this project knows.

## Decision

**Decoding stays strict. An unrecognised field remains a startup error.**

The alternative — ignore unknown fields, perhaps with a warning — trades a loud
failure for a silent one. An operator who writes `suricta: true`, or indents a
key one level too far, gets a component that starts cleanly and does something
other than what they configured. For a system whose output is evidence, a
sensor quietly running with a setting nobody chose is worse than a sensor that
refuses to start: the first produces captures an investigation will trust and
should not, the second produces an error somebody fixes in a minute.

That is the same reasoning ADR-0003 applies to the audit ledger and the
constitution applies generally. Trawl prefers failures that announce
themselves.

The rolling-upgrade hazard is answered operationally rather than by weakening
the check:

- **A config schema change requires rolling every component that parses the
  config**, not only the ones whose own code changed.
- **Apply the ConfigMap with or after the images, never before.**
- The procedure and its symptom are written up in the runbook under "A
  component crash-loops on `unknown field` after a config change".

## Consequences

**A config addition is a coordinated release, not a config edit.** Adding a
field means building and rolling three images even when two of them do not read
it. That is the cost, and it is accepted.

**The failure is delayed, not prevented.** Strict decoding does not stop a
mis-ordered rollout; it stops the *consequences* of one from being silent, but
only at the next restart of the lagging component. The gap between a
mis-ordered apply and its symptom can still be days. Operators are told to
restart config-parsing components deliberately during the maintenance window
rather than discovering it later — a crash-loop caused on purpose at 10am is
far cheaper than the same crash-loop during an eviction at 3am.

**Nothing enforces the ordering automatically.** The rule lives in the runbook
and in this ADR. A static check cannot see whether a deployed image predates a
config field, because the image digest does not carry the config schema it
understands. Closing that gap would need each binary to publish the config
version it accepts and the rollout to compare them — worth doing if this bites
a second time, and not worth the machinery before then.

**A typo in the reference ConfigMap is caught by
`TestDevConfigMapValidates`**, which loads `config/dev/trawl-config.yaml`
through the same strict loader. The worked example an operator copies cannot
itself contain an unrecognised field.
