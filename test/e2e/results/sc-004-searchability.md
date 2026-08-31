# SC-004 searchability

Measured 2026-08-31T00:31:11Z by `TestObservationsBecomeSearchableWithinThirtySeconds`
against the deployed pipeline. Latency is from `observed_at` - when the
sensor read the analyzer's record - to the first query that returned it,
so each figure includes the one-second poll interval and is an upper bound.

Budget: 95% within 30s.

| source / subtype | n | p50 | p95 | max |
|---|---:|---:|---:|---:|
| Hubble/cluster_flow | 9394 | 1.15s | 2.19s | 2.67s |
| Zeek/connection | 50 | 3.02s | 23.75s | 23.75s |
| Zeek/dns | 47 | 13.82s | 23.85s | 23.85s |
| Zeek/tls | 12 | 2.9s | 23.97s | 23.97s |
| Zeek/weird | 20 | 2.98s | 23.79s | 23.79s |
| **all** | 9523 | 1.2s | 2.24s | 23.97s |

Within budget: 100.00% of 9523 observations.
