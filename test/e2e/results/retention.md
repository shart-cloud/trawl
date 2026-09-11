---
title: T127 retention evidence
---

# T127: retention enforced against a deployed cluster

Measured 2026-09-11 against `admin@talos-cluster` (single node `talos-node`,
Kubernetes v1.35.5), running the build merged as `96ec4f1` — controller-manager
`sha256:35a32745…`, event-worker `sha256:20f6a909…`, artifact-gateway
`sha256:2639dfde…`.

Produced by `test/e2e/manual_capture_test.go` and `test/e2e/retention_test.go`
under the `acceptance` tag. Every figure comes from a spec that ran.

Both expiry specs had **never been executed before this run**. They are gated
behind `TRAWL_E2E_EXPIRY=1` because each waits out a real retention deadline,
and they additionally require the artifact endpoint to resolve locally — which
is why they had been skipping silently rather than failing (see "What had been
hiding this" below).

## Results

| spec | result | wall clock |
|---|---|---|
| `TestShorteningRetentionMovesTheDeadlineFromCompletion` | **PASS** | 23.7s |
| `TestAnExpiredCaptureIsDeletedAndRefused` | **PASS** | 3769.5s (62m 49s) |
| `TestAShortenedRetentionIsEnforcedAndNotMerelyRecorded` | **PASS** | 3769.7s (62m 50s) |

## Expiry happened at the deadline, not near it

Both figures are taken from the audit ledger, which is write-once and outlives
the CaptureJobs the specs clean up.

| capture | deadline | expiry recorded | latency |
|---|---|---|---|
| `accept-expiry-366943635` | 2026-09-11T15:24:08Z | 2026-09-11T15:24:17Z | **+9s** |
| `accept-shorten-expiry-366943635` | 2026-09-11T16:24:31Z | 2026-09-11T16:24:31Z | **<1s** |

The specs allow the deadline plus three minutes. Nine seconds and under one
second are both comfortably inside it, and neither capture's deadline moved
while it was being waited on — `waitForExpiry` logs a deadline that shifts, and
neither run logged one.

## The 24-hour period, validated in an hour

The CRD floors retention at 1h and there is no clock hook, so a 24-hour
retention cannot be validated honestly by waiting. `TestAShortenedRetentionIsEnforcedAndNotMerelyRecorded`
accelerates it with a real operator action rather than a test seam: collect
under the long period, shorten it the way a retention admin would, and hold the
installation to the shorter one.

```
retention shortened 24h -> 1h
deadline moved from 2026-09-12T10:24:31-05:00 to 2026-09-11T11:24:31-05:00
```

Completion was 10:24:31. The shortened deadline is **an hour after completion**,
not an hour after the admin's change — which is the property that matters. Had
it been measured from "now", the artifact would have outlived what the admin
asked for. 24× acceleration, which is as much as the API permits.

## What each spec establishes

**Exact deadline denial** — the artifact is refused with **HTTP 410**, not 404
and not a transport error. The distinction is deliberate: an analyst told "no
such capture" hunts for a typo instead of reading the retention policy.

**Deletion is real** — the artifact is asserted present in the MinIO bucket
before the deadline and absent after, so its absence means something. A spec
that only checked the status field would pass against a controller that marked
captures Expired and deleted nothing.

**Metadata survives the bytes** — `sha256` and `completedAt` are still on the
record after expiry, along with the deadline the capture was held to. This is
what lets an investigation say what was collected, and that it is gone on
purpose.

**A shortened deadline is enforced, not merely recorded** — the assertion the
new spec exists for. The pre-existing shortening spec checks that the deadline
field moves and that the capture stays downloadable while the new deadline is
ahead, then stops. A controller that wrote the new date and swept on the old one
would satisfy every one of those assertions while keeping evidence a day longer
than the retention admin asked for.

**The ledger records it** — each expiry appears as an intent/outcome pair, which
is the FR-036 property T120 asserts generally:

| decision | message | ledger object |
|---|---|---|
| `allowed` | the retention deadline passed | `20260911T162431.016166069Z-9b0f75106e66d539.json` |
| `succeeded` | the artifact was deleted and its absence verified | `20260911T162431.046482393Z-3b3aebb82b0ee7f8.json` |

## A defect this run found

Reading those ledger records turned up a second pair written **eight seconds
after** the scheduled expiry, saying:

> the capture was deleted before its retention deadline; its artifact goes with it

That capture had expired exactly on schedule. The cause is a feature working as
intended: normal expiry deletes the bytes and deliberately keeps the artifact
*record*, so `status.artifact` is still set on an Expired capture, and deleting
the CaptureJob afterwards re-enters the finalizer's expiry path with a message
that assumes it got there first.

Operationally this is minor — a redundant, idempotent delete against an object
that is already gone. As evidence it is the wrong shape to leave alone. The
ledger is write-once and is the record of last resort for what happened to
collected traffic; an auditor reconstructing this artifact's history would read
a scheduled expiry as an early purge, which is precisely the accusation the
ledger exists to be able to answer.

Fixed by branching the message on whether the capture had already expired, with
`TestDeletingAnAlreadyExpiredCaptureDoesNotClaimAnEarlyPurge` as the regression
test. Mutation-checked: restoring the fixed message fails it twice, once per
record in the pair.

## What had been hiding this

Five acceptance specs call `requireReachableObjectStore`, which needs
`minio.trawl-system.svc.cluster.local` to resolve to loopback so a presigned URL
can be followed — the signature covers host *and* port, so no substitute port
works. Without that entry the specs **skip**, and `go test` prints nothing for a
skip, so an acceptance run reports success having never exercised the download
path at all.

The affected specs are the primary download spec, the controller-restart spec,
the audit-outage spec, and both expiry specs. This is the same failure family as
the `kustomize` silent skip found in T130's review, and unlike that one it
cannot be closed with a build dependency: it is a host-level change whoever runs
the suite has to make.

## Not covered here, deliberately

**Upload protection** stays at integration level, where
`TestRetentionLeavesAnUnfinishedCaptureAlone` asserts deterministically that the
sweeper leaves an unfinished capture alone. A cluster version would have to
catch the sweeper inside an upload window measured in seconds; a flaky spec
asserting a safety property is worse than a reliable one somewhere else.
