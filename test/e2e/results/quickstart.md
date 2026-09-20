---
title: T131 quickstart execution evidence
---

# T131: executing the validation quickstart

Measured 2026-09-11 against `admin@talos-cluster` (single node `talos-node`,
Kubernetes v1.35.5, Cilium/Hubble 1.18.11), running the build merged as
`96ec4f1`.

Only durations, counts and pass/fail results are recorded here. No record
bodies, per SC-005.

## SC-005 exact-correlation timing

`TestSC005ExactCorrelationTiming`, `test/e2e/correlation_timing_test.go`, under
the `investigation` tag. Each attempt times the pivot from one record in a flow
to its exact-match counterparts: the LogQL round trip an analyst waits on.

| # | session | direction | duration | records | result |
|---:|---|---|---:|---:|---|
| 1 | `tls-session-with-alert` | earliest-record | 1.948s | 3 | pass |
| 2 | `tls-session-with-alert` | latest-record | 1.991s | 3 | pass |
| 3 | `dns-lookup` | earliest-record | 2.169s | 2 | pass |
| 4 | `dns-lookup` | latest-record | 2.129s | 2 | pass |
| 5 | `http-with-token-in-query` | earliest-record | 2.172s | 2 | pass |
| 6 | `http-with-token-in-query` | latest-record | 2.182s | 2 | pass |
| 7 | `tls-session-with-certificate` | earliest-record | 1.999s | 2 | pass |
| 8 | `tls-session-with-certificate` | latest-record | 2.198s | 2 | pass |
| 9 | `file-download-with-anomalies` | earliest-record | 2.272s | 5 | pass |
| 10 | `file-download-with-anomalies` | latest-record | 2.114s | 5 | pass |

**10 of 10 under budget. p50 2.169s, max 2.272s, budget 3m0s** — roughly eighty
times inside it.

Every attempt also returned its session's full expected record count, which is
what stops a fast query that finds nothing being recorded as a fast pivot.
Mutation-checked by pivoting on a Community ID no fixture carries: every attempt
then returns zero records and fails, rather than passing on speed.

### The accepted sample and its limit

**This is the ten-attempt sample SC-005 now names.**

The fixture set's boundary remains part of the evidence:

| | count |
|---|---:|
| fixture sessions | 6 |
| …carrying a Community ID (exactly correlatable) | 5 |
| …**also** carrying a Suricata alert | **1** |

Exactly one session supports a signature-to-protocol round trip; this evidence
does not claim ten such pairs.

Each attempt begins at **one end of the flow** — an
attempt from the earliest record and one from the latest. That is what
`TestExactPivotReachesTheWholeFlowFromEitherEnd` already asserts, and it rests
on the same property: Community ID is symmetric, so the pivot is the same query
whichever record it starts from. The accepted criterion requires all ten to
finish within budget; this run did so.

## Commands that did not exist

Executing the quickstart meant first discovering that **nine of its commands
were not real**. The document had drifted from the Makefile:

| command | resolution |
|---|---|
| `make verify-manifests` | → `make manifest-security` |
| `make query-observations` | → `make test-investigation ARGS=…`, plus a direct `logcli` query |
| `make verify-correlation` | → same investigation suite |
| `make e2e-malformed-observation` | → `go test ./test/contract/ -run 'Schema\|Malformed\|Normalize'` |
| `make e2e-correlation-timing` | → `make test-investigation ARGS='-run TestSC005ExactCorrelationTiming'` |
| `make e2e-traffic` | → the acceptance spec that drives the traffic generator |
| `make e2e-trigger-matrix` | → `make test-acceptance ARGS='-run "Policy\|Drop"'` |
| `make verify-execution-uniqueness` | → `make test-acceptance ARGS='-run "Restart\|Uniqueness"'` |
| `make test-e2e TEST=…` | → the corresponding gated acceptance runs |

The capability existed in every case bar one; only the names were wrong. The
exception is the performance section, which invokes `test-e2e TEST=reference-load`:
that is T126, `test/e2e/reference_load_test.go` does not exist, and the section
is now marked unexecutable rather than given a command that would fail. A
release checklist must not infer those figures from the shorter runs.

`make test-investigation` and `make test-acceptance` now accept `ARGS`, so the
quickstart can narrow a run without a separate target per section.

## What this says about the quickstart as a gate

A validation quickstart whose commands do not run is worse than none: it reads
as a completed checklist while asserting nothing, which is the same failure as
the six contract tests that had been silently skipping in CI and the pinned
`govulncheck` that nothing invoked. The pattern is consistent enough across this
phase to be worth naming — **a gate nobody has executed is not a gate** — and it
is why T131 is an execution task rather than a documentation one.

Nothing in this document is transcribed from a command that was not run.
