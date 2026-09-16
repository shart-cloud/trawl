---
title: Evidence handling
description: Who can see captured traffic, what Trawl trusts, and how evidence is reviewed and destroyed.
---

A packet capture is the most sensitive artifact a network tool produces. It
contains whatever was on the wire — credentials in plaintext protocols, session
tokens, personal data, the contents of internal APIs — and unlike a log line
nobody chose what went into it.

Trawl is built on the assumption that collecting such a thing must be
deliberate, bounded, attributable, and reversible. This page describes the
controls that make it so, and the places where they stop.

## The privileges Trawl holds

Trawl runs privileged workloads, and confining them is the central design
constraint (ADR-0004).

**Only the sensor and the capture runner touch packets.** Both are rendered by
the operator with a reviewed exception: `CAP_NET_RAW` and `CAP_NET_ADMIN`, and
nothing else. Neither is ever `privileged: true`, neither uses a host namespace,
and neither writes to a `hostPath`. Static checks in
`test/contract/security_manifests_test.go` and
`hack/verify-manifests.sh` fail the build if a manifest acquires any of those,
including a single added capability.

**Nothing else in the installation is privileged.** The controller manager, the
event worker and the artifact gateway drop all capabilities, run as non-root
with a read-only root filesystem, and hold no capture path at all.

**The namespace is a boundary, not a convention.** Trawl resources are accepted
only in the installation namespace, and admission rejects them anywhere else.
That rejection depends on the webhook seeing the request in the first place — a
`namespaceSelector` on the webhook configuration would make an off-namespace
resource skip validation rather than be refused by it, so the absence of one is
asserted as a test.

**One credential is more capable than what Trawl does with it.** An installation
that uses `PortMirror` stores device credentials in the namespace, and they
cannot be narrowed: RouterOS group policies have no "may only set a mirror", so a
user that can write `mirror-target` can usually also change a firewall rule or
shut a port. Trawl never does either, and the drivers have three methods -
Configure, Observe, Revert - with nothing else in them. But the credential's
capability is real, and compromise of the namespace becomes the ability to change
the network fabric. It is bounded by who may create a `PortMirror` at all
(below), by the audit ledger recording every device change and refusal, and by
nothing else. See ADR-0007; an installation unwilling to accept it creates no
device Secret and binds no mirror role.

**Every workload's network egress is allowlisted.** A default-deny
`NetworkPolicy` covers the namespace and each component is granted only the
destinations it needs: the worker reaches Loki, Hubble Relay, the audit sink and
the API server, and nothing else. The namespace holds ledger and bucket
credentials, so an open namespace would put those within reach of any pod
scheduled beside them.

## Who can do what

Seven roles ship with the installation. They exist because "can see a capture
exists" and "can read the packets in it" are different permissions, and
collapsing them is the mistake this model is designed to prevent.

| Role | Can | Notably cannot |
|---|---|---|
| `trawl-capture-viewer` | see that captures and taps exist, and their status | read any packets |
| `trawl-capture-analyst` | everything a viewer can, plus **request** captures and **download** them | change retention; manage policies |
| `trawl-capture-policy-viewer` | see policies, taps and captures | change anything |
| `trawl-capture-policy-admin` | create, arm, disarm and delete policies | download captures |
| `trawl-retention-admin` | change a capture's retention | download captures; create them |
| `port-mirror-viewer` | see which switch ports are being copied, and to where | change any of it |
| `port-mirror-admin` | create, change and delete device mirroring | read any packets; request captures; manage policies |

Four properties of that table are deliberate and worth stating plainly.

**Downloading is a separate subresource.** The analyst and the viewer differ by
exactly one grant, `capturejobs/download`. Reading the bytes is therefore an
authorization decision of its own, made and recorded separately from listing the
object — not a side effect of being able to see it.

**The policy admin cannot read what their policies collect.** Someone who can
arm a rule that captures traffic cannot then read the traffic it captured.
Automating collection and consuming evidence are different jobs, and one person
holding both can quietly turn a detection rule into a wiretap.

**The retention admin cannot download.** Changing how long evidence is kept is a
custody decision, not an investigative one.

**The mirror admin holds no capture path, and no capture role holds mirroring.**
Configuring a switch and reading packets are separate grants in both directions.
This is the only place the device credential's excess capability can actually be
controlled, which is why `port-mirror-admin` is its own binding rather than part
of an operator role: an installation that never binds it has a Trawl that cannot
reconfigure any device, whatever the stored credential permits. What RBAC cannot
express is that anyone who may update a `PortMirror` may repoint it at different
ports; the ledger carries that weight instead.

None of these roles is bound to anything by default. Binding them is an explicit
act by whoever operates the cluster.

## What Trawl trusts, and what it does not

**Evidence content is untrusted, always.** Every field of every observation —
filenames, alert messages, DNS names, HTTP headers, TLS server names — is
attacker-influenced by construction, because an attacker chooses what to put on
the wire. Trawl treats observation content as data end to end. It is never
interpreted as an instruction, never used to build a query without escaping, and
never used to construct a filter without validation.

**BPF filters are a trust boundary and are treated as one.** A filter reaches
the runner from two directions: an analyst types one into a `CaptureJob`, or a
policy renders one from a template into which observation fields are
substituted. The second is the dangerous one, because the substituted values
came off the wire.

The filter is checked structurally at admission and compiled by the runner
before any packet is read, and substituted values are validated rather than
quoted. That distinction was learned the hard way: `netip.ParseAddr` accepts
anything after `%` as an IPv6 zone — spaces, operators, whole clauses — and
re-emits it verbatim, so a crafted source address of `fe80::1%or udp port 53`
became exactly that text in the filter and widened the capture. Parsing looked
like the whole defense and was not it. Zones are now refused outright.

The general rule: **a value that came from the network may narrow a capture, and
may never widen one.** If you extend the template system, that is the property
to preserve.

**Trawl decrypts nothing.** There is no TLS interception, no key escrow, and no
inline path. What is encrypted on the wire is encrypted in the capture.

## Classifying and handling what you collect

Treat every artifact as containing the most sensitive thing that could have been
on that link during that window, because you cannot know that it does not.

**Bound the capture at request time, not afterwards.** Duration, size and filter
are immutable once a `CaptureJob` is created — you cannot broaden a capture
after the fact, and you should not try to collect broadly and narrow later. The
narrow filter is the control.

**A downloaded capture has left Trawl's controls.** This is the boundary that
matters most in practice, and it is worth being blunt: once the file is on a
laptop, no role, retention policy or audit record applies to it. Retention will
expire the copy in the bucket on schedule and will do nothing whatsoever about
the copy in someone's `~/Downloads`.

So:

- Download to managed, encrypted storage, never to personal devices.
- Keep the download inside the investigation's own case system, where it
  inherits that system's retention and access controls.
- Delete local copies when the investigation closes. Nothing will do this for
  you.
- Never attach a capture to a ticket, chat message or email. Those systems have
  their own retention, their own access model, and usually a much wider audience
  than the investigation.

**Downloads are verified, not merely transferred.** `trawlctl capture download`
checks the artifact against the checksum the gateway reports and writes the file
only if it matches; it refuses to overwrite an existing output file. A capture
whose `Downloadable` condition is `False` failed that verification and must not
be handed to an investigator — it is either corrupt or not the object its record
describes.

**Presigned URLs are short-lived and are not links to share.** The gateway
issues one per authorized request. Passing it to someone else passes them the
evidence without an authorization decision being made about them, which defeats
the entire download-authorization path.

## Reviewing the audit record

Every mutation, policy decision, capture transition, download decision,
retention change and expiry is recorded. The ledger is write-once with a
retention lock, held in a separate bucket from the artifacts, and Trawl fails
closed: an action that cannot be recorded is refused rather than performed.

A fallible action leaves **two** records — an `allowed` intent before the work
and a `succeeded` or `failed` outcome after it. When reviewing, read them as a
pair. An intent with no outcome means the work was authorized and then
interrupted, which is a different event from an authorized action that failed.

**Questions the ledger answers directly:**

```logql
# Who read this capture, and when?
{service_name="trawl-audit"} |= "artifact.download" |= "<capture-name>"

# Everything one person did
{service_name="trawl-audit"} |= "<username>"

# Refused attempts
{service_name="trawl-audit"} |= "denied"

# Who changed how long evidence is kept?
{service_name="trawl-audit"} |= "retention.change"
```

Loki is the searchable copy, and it is a copy. The bucket is the record. For
anything that has to be exact — a compliance answer, a dispute about who
accessed what — read the bucket, because the Loki stream has known gaps.

**A capture created by a policy names both.** The `actor` is the event worker's
workload identity, because the act was the worker's; `initiatedBy` names the
policy it acted for. Neither alone answers "on whose behalf", which is why both
are recorded.

## Destroying evidence

**Retention is enforced automatically.** Every capture carries a deadline and
the sweeper deletes the artifact when it passes. The default and the ceiling are
installation settings; the ceiling is the real control, because it bounds what
any individual request can ask for.

**Extending retention is a privileged, recorded act.** Only a subject holding
`trawl-retention-admin` can change a deadline, the webhook checks that at
admission, and the change is committed to the ledger with the identity behind
it. Retention is the one field of a `CaptureJob` that is not immutable, and it
is gated precisely because it is the one that decides how long sensitive data
lives.

**Deleting a policy does not delete what it collected.** A policy-created
capture carries no owner reference, deliberately: deleting a rule must not
collect back the evidence gathered under it. Removing evidence is always its own
decision.

**Uninstalling is not a purge, and a purge is not `undeploy`.** `make undeploy`
removes the operator and leaves the CRDs and every capture record standing.
`make uninstall` removes the CRDs — and deleting a CRD deletes every object of
that kind, including every record of where collected evidence is stored. The
artifacts remain in the bucket with nothing left in the cluster describing them.
Treat `make uninstall` as destructive and run it deliberately.

**A real purge is two acts,** because the metadata and the bytes live in
different places:

1. Delete the `CaptureJob` objects, which removes the records and the
   retention deadlines.
2. Delete the objects from the artifact bucket.

Do them in that order and record the approval for both. The audit ledger is in a
third, object-locked bucket and is deliberately not purgeable by this path —
destroying the record of who accessed evidence is not something an evidence
purge should be able to do as a side effect.

## Where these controls stop

Stated explicitly, because a control you believe in and do not have is worse
than one you know you lack.

- **A downloaded file is outside every control on this page.** Trawl cannot
  expire it, cannot record who opened it, and cannot take it back.
- **A cluster administrator can bypass the role model.** Anyone who can read
  Secrets in the installation namespace holds the bucket credentials and can
  read artifacts directly, without the gateway and without an audit record.
  Trawl's authorization applies to Trawl's paths; it does not confine someone
  who already owns the namespace.
- **Trawl does not classify content.** It does not detect credentials or
  personal data in a capture, and it applies no handling rules based on what a
  capture turned out to contain. Classification is the investigator's judgement.
- **A reverted mirror is the device's state, not Trawl's record of it.** If a
  `PortMirror` is force-deleted by removing its finalizer while the device is
  unreachable, the switch keeps mirroring and nothing in the cluster says so. The
  ledger holds the `portmirror.delete` and the absence of a matching
  `portmirror.revert`, which is the only signal there is.
- **Retention bounds the artifact, not the analysis.** Notes, extracted
  indicators and screenshots taken from a capture outlive it, and Trawl knows
  nothing about them.
