# US3 manual capture: the full lifecycle matrix, authorization and SC-006

Measured 2026-09-08 against the deployed cluster `admin@talos-cluster` (single
node `talos-node`, Kubernetes v1.35.5), running the build of `8814f68` —
controller-manager `sha256:e43e4cec…`, artifact-gateway `sha256:22267684…`,
event-worker `sha256:15af20a9…`.

Produced by `test/e2e/manual_capture_test.go` under the `acceptance` tag. Every
figure below comes from a spec that ran; none was measured by hand.

This run covers the **whole** of T075's matrix, including the five cases that
gate themselves behind environment variables. Those gates exist because each of
those specs disrupts the installation for as long as it runs, not because the
cases are optional — a gated spec that has never been executed is an untested
assertion with a passing colour, and this suite has now produced four of those.
Their windows are given separately below because they cannot share one.

## SC-006 timing

> At least 95% of valid manual capture requests begin packet collection within
> 10 seconds, and their artifact becomes downloadable within 60 seconds after
> collection ends when storage is healthy.

`TestManualCaptureTimingMeetsSC006`, 20 consecutive captures, 10s duration each,
filter `udp port 53 or tcp port 443` on the production tap.
Window 2026-09-08T20:12:10Z–20:19:08Z.

| measure | n | p50 | p95 | max | budget | within |
|---|---:|---:|---:|---:|---:|---:|
| start — `requestedAt` → `startedAt` | 20 | 2s | 3s | 3s | 10s | **100.00%** (20/20) |
| downloadable — `captureEndedAt` → `Downloadable` True | 20 | 0s | 1s | 1s | 60s | **100.00%** (20/20) |

Both measurements are read from the CaptureJob's own status, not from the test's
polling. A figure timed by the test would carry its poll interval and could not
be reproduced from the object afterwards.

Two things the table does not say on its own:

- **The figures are quantized to whole seconds.** `metav1.Time` serializes at
  second precision, so each carries up to a second of rounding either way. The
  `0s` p50 for downloadability means "under a second, not resolvable further",
  not "instantaneous". Against a 10s and a 60s budget the resolution is ample.
- **`startedAt` is the node clock and `requestedAt` the controller's.** On this
  single-node cluster they are the same clock. On a multi-node installation the
  start figure would also carry the skew between them, which is why the cluster
  is named above.

Every capture in the sample recorded packets — 26 to 95 — so no measurement here
is an empty-capture artifact. The empty case is measured deliberately instead,
below.

## Download authorization

The analyst and the viewer differ only by the `capturejobs/download`
subresource, and both decisions are checked against the RBAC installed in the
cluster rather than a fake reviewer.

| spec | actor | decision | ledger object |
|---|---|---|---|
| `TestAManualCaptureCompletesAndIsDownloadedByAnAnalyst` | `…:trawl-acceptance-analyst` | `allowed` | `audit/v1/records/20260908T200458.652183966Z-ba4cc06991445395.json` |
| `TestAViewerIsRefusedTheCaptureBytes` | `…:trawl-acceptance-viewer` | `denied` | `audit/v1/records/20260908T200523.545111042Z-dbcc5ce944e465d2.json` |

Both records carry a request id correlating the ledger entry with the error the
operator saw. The allowed download was verified byte-for-byte: the downloaded
file hashes to the `sha256` in status, matches `sizeBytes`, and begins with the
pcapng magic. The refusal left no file behind, named neither the object, its
size nor its checksum, and the CLI printed no presigned URL.

## Lifecycle matrix

Window 2026-09-08T20:04:36Z–20:12:10Z, with `TRAWL_E2E_FULL_STORAGE=1` and
`TRAWL_E2E_RESTART=1` set.

| spec | result | what it establishes |
|---|---|---|
| `TestAManualCaptureCompletesAndIsDownloadedByAnAnalyst` | pass (28.3s) | request → `Completed`, artifact verified and downloadable, checksum agreement |
| `TestAViewerIsRefusedTheCaptureBytes` | pass (26.4s) | a viewer is refused the bytes and the refusal is recorded |
| `TestAnInvalidFilterFailsWithoutCapturing` | pass (16.1s) | an invalid filter fails without collecting, never a false `Completed` |
| `TestACaptureOnAnUnavailableTargetNeverStarts` | pass (2.8s) | an unavailable target never reaches a false `Active` |
| `TestShorteningRetentionMovesTheDeadlineFromCompletion` | pass (24.0s) | an authorized retention change moves the deadline and leaves the artifact downloadable |
| `TestACaptureThroughAnInactiveTapFailsAsTapInactive` | pass (195.1s) | an inactive source fails as `TapInactive`, and says the tap is the problem |
| `TestACaptureThatMatchesNoTrafficCompletesWithZeroPackets` | pass (26.1s) | an empty capture is a completed, downloadable capture, not a failure |
| `TestAFullArtifactStoreFailsTheCaptureWithoutLeavingAnArtifact` | pass (53.5s) | a capture that cannot be stored fails as `UploadFailed` and leaves no artifact |
| `TestACaptureInFlightSurvivesAControllerRestart` | pass (106.2s) | a capture already collecting completes across a controller restart |

Details worth recording from the three new observations:

- **Empty capture:** 400 bytes, 0 packets, stop reason `Duration`. The 400 bytes
  are pcapng's section and interface headers, which are what make the result a
  file an analyst can open to see that it is empty rather than a zero-byte
  object nothing can read. `packetCount` is present and zero, distinguishable
  from unset, through the manifest, the status write and the download.
- **Full artifact store:** the lever is a bucket quota below what the bucket
  already holds, imposed and cleared through the object store's own admin client
  inside its pod. The capture failed as `UploadFailed` with `CaptureStarted`
  still True — a storage failure reported as a storage failure, not as a capture
  that never ran — and with no artifact reference, no checksum, and
  `Downloadable` not True. A capture taken after the quota was cleared completed
  normally, which is what separates "storage was full" from "captures stopped
  working".
- **Controller restart:** `trawl-controller-manager-7888944df8-npmh9` →
  `…-zzvvt`, taken while packets were being collected on a 90s capture. The
  capture completed with a verified artifact, kept the `startedAt` written by
  the process that was killed, and the bytes the replacement verified were
  downloaded and hashed to the recorded `sha256`.

The retention spec failed against the previous build by design — it is the spec
that found the retention-download defect fixed in `8814f68`, where an authorized
retention change permanently stopped a capture being downloadable and the status
blamed expiry for it. Its passing here is the live verification of that fix.

## Audit outage

`TestAnAuditOutageRefusesCapturesAndServesNothingUnrecorded`, pass (91.6s),
window 2026-09-08T20:01:57Z–20:03:27Z, `TRAWL_E2E_LEDGER_OUTAGE=1`. Run in a
window of its own because it stops the object store for the whole installation.

Nothing happened unrecorded. With the ledger unreachable:

- a capture request was refused by the admission server's own audit gate —
  `admission webhook "vcapturejob.trawl.cloud" denied the request: audit ledger
  unavailable; mutation refused` — asserted on that text rather than on "the
  request failed", because the same outage also removes the manager from the
  webhook Service's endpoints and a spec that accepted any error would pass
  against an audit gate that had been made fail-open;
- the gateway answered the analyst `HTTP 503` and served no bytes, reached by
  forwarding a gateway pod directly, since the outage takes every gateway pod
  out of the Service's endpoints;
- the completed capture's record was unchanged by the outage;
- and after the ledger returned, the same download succeeded and was recorded at
  `audit/v1/records/20260908T200319.677649491Z-4b3646dbbfef7d8e.json`.

One honest limit: this installation keeps the ledger and the artifact bucket in
the same object store, so stopping the ledger stops both and the `503` does not
name which dependency was missing. What it does establish is that the gateway
refused rather than served. An installation with separate stores could tell the
two apart; this one cannot.

## Retention expiry (SC-010)

`TestAnExpiredCaptureIsDeletedAndRefused`, `TRAWL_E2E_EXPIRY=1`, run in its own
window because it waits a real hour: the shortest retention the API accepts is
1h, the deadline runs from completion, and the floor was not weakened to suit a
test.

**Pass (3849.6s), window 2026-09-08T20:03:45Z–21:04:17Z.** The capture completed
at 20:04:07 with a verified artifact present in the bucket, its deadline was
21:04:07, and it reached `Expired` within about fifteen seconds of that deadline.
At that point the object was gone from the artifact bucket — checked with the
artifact credential, not the audit one, so the check says something about the
separation ADR-0003 draws between them — `Downloadable` was no longer True,
`RetentionEnforced` was True, the capture record (`sha256`, `completedAt`)
survived the collection it described, and the analyst who could read it an hour
earlier was refused with the gateway's `HTTP 410`. The ledger carried both an
intent before the delete and an outcome after it, so an expiry that happened and
lost its acknowledgement would still be visible.

`410` and not `404` is the shipped contract: the artifact API distinguishes a
capture whose retention ended from one that never existed, because an analyst
told "no such capture" goes looking for a typo instead of for the retention
policy.

**This spec had never been executed before 2026-09-08.** Its first real
execution failed — not on the property, but on the spec: it computed one
absolute timeout from the retention deadline it read at completion and gave up
twenty-two seconds short of the deadline the object was actually carrying. The
retention reconciler recomputes `completedAt + retention` and writes the answer
back whenever status disagrees, so that first reading is not the one enforcement
acts on. The spec now re-reads the deadline as it waits and logs any movement.

That failure is the point of running gated specs rather than trusting them. Two
assertions in this same spec had already been corrected by review — a `404` that
should have been `410`, and a bare `"410"` that a nine-digit run id could
satisfy — and it still did not pass the first time it ran. The deadline was
separately confirmed not to drift on an idle cluster, so the fault was the
spec's and not the installation's.

## Not covered by this run

Nothing in T075's matrix. Every case the task names — reporter-driven progress,
successful CLI download, invalid filter, inactive source, unavailable target,
zero packet, full storage, audit outage, restart, unauthorized download and
expiry — has a spec, and every spec has been executed against this deployment.
