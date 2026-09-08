# US3 manual capture: lifecycle, authorization and SC-006

Measured 2026-09-08T17:41:27Z–17:51:08Z against the deployed cluster
`admin@talos-cluster` (single node `talos-node`, Kubernetes v1.35.5), running
the build of `8814f68` — controller-manager
`sha256:e43e4cec…`, artifact-gateway `sha256:22267684…`, event-worker
`sha256:15af20a9…`.

Produced by `test/e2e/manual_capture_test.go` under the `acceptance` tag. Every
figure below comes from a spec that ran; none was measured by hand.

## SC-006 timing

> At least 95% of valid manual capture requests begin packet collection within
> 10 seconds, and their artifact becomes downloadable within 60 seconds after
> collection ends when storage is healthy.

`TestManualCaptureTimingMeetsSC006`, 20 consecutive captures, 10s duration each,
filter `udp port 53 or tcp port 443` on the production tap.

| measure | n | p50 | p95 | max | budget | within |
|---|---:|---:|---:|---:|---:|---:|
| start — `requestedAt` → `startedAt` | 20 | 2s | 3s | 3s | 10s | **100.00%** (20/20) |
| downloadable — `captureEndedAt` → `Downloadable` True | 20 | 0s | 1s | 1s | 60s | **100.00%** (20/20) |

Both measurements are read from the CaptureJob's own status, not from the
test's polling. A figure timed by the test would carry its poll interval and
could not be reproduced from the object afterwards.

Two things the table does not say on its own:

- **The figures are quantized to whole seconds.** `metav1.Time` serializes at
  second precision, so each carries up to a second of rounding either way. The
  `0s` p50 for downloadability means "under a second, not resolvable further",
  not "instantaneous". Against a 10s and a 60s budget the resolution is ample.
- **`startedAt` is the node clock and `requestedAt` the controller's.** On this
  single-node cluster they are the same clock. On a multi-node installation the
  start figure would also carry the skew between them, which is why the cluster
  is named above.

Every capture in the sample recorded packets — 26 to 90, and one of 6570 — so
no measurement is an empty-capture artifact.

## Download authorization

The analyst and the viewer differ only by the `capturejobs/download`
subresource, and both decisions are checked against the RBAC installed in the
cluster rather than a fake reviewer.

| spec | actor | decision | ledger object |
|---|---|---|---|
| `TestAManualCaptureCompletesAndIsDownloadedByAnAnalyst` | `…:trawl-acceptance-analyst` | `allowed` | `audit/v1/records/20260908T174955.052306273Z-bf0b8c6f9f4f324c.json` |
| `TestAViewerIsRefusedTheCaptureBytes` | `…:trawl-acceptance-viewer` | `denied` | `audit/v1/records/20260908T175019.187676944Z-2fa2fefa7b3aafc4.json` |

Both records carry a request id correlating the ledger entry with the error the
operator saw. The allowed download was verified byte-for-byte: the downloaded
file hashes to the `sha256` in status, matches `sizeBytes`, and begins with the
pcapng magic. The refusal left no file behind, named neither the object, its
size nor its checksum, and the CLI printed no presigned URL.

## Lifecycle and refusals

| spec | result | what it establishes |
|---|---|---|
| `TestAManualCaptureCompletesAndIsDownloadedByAnAnalyst` | pass (28.8s) | request → `Completed`, artifact verified and downloadable, checksum agreement |
| `TestAViewerIsRefusedTheCaptureBytes` | pass (25.5s) | a viewer is refused the bytes and the refusal is recorded |
| `TestAnInvalidFilterFailsWithoutCapturing` | pass (18.1s) | an invalid filter fails without collecting, never a false `Completed` |
| `TestACaptureOnAnUnavailableTargetNeverStarts` | pass (2.3s) | an unavailable target never reaches a false `Active` |
| `TestShorteningRetentionMovesTheDeadlineFromCompletion` | pass (25.7s) | an authorized retention change moves the deadline and leaves the artifact downloadable |

The last of these failed against the previous build by design — it is the spec
that found the retention-download defect fixed in `8814f68`, where an authorized
retention change permanently stopped a capture being downloadable and the
status blamed expiry for it. Its passing here is the live verification of that
fix.

## Not covered by this run

`TestAnExpiredCaptureIsDeletedAndRefused` is opt-in behind `TRAWL_E2E_EXPIRY=1`
and waits a real hour, because the shortest retention the API accepts is 1h and
the floor was not weakened to suit a test. It is not part of this run and
SC-010 is not evidenced here.

T075's inactive-source, zero-packet, full-storage, audit-outage and restart
cases are not yet written, so this document covers the manual capture matrix as
it stands rather than in full.
