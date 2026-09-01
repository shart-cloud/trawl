# SC-004 searchability

Measured 2026-09-01T02:05:10Z by `TestObservationsBecomeSearchableWithinThirtySeconds`
against the deployed pipeline. Latency is from `observed_at` - when the
sensor read the analyzer's record - to the first query that returned it,
so each figure includes the one-second poll interval and is an upper bound.

Budget: 95% within 30s.

| source / subtype | n | p50 | p95 | max |
|---|---:|---:|---:|---:|
| Hubble/cluster_flow | 8019 | 1.54s | 3s | 3.8s |
| Zeek/connection | 43 | 2.65s | 4.29s | 4.79s |
| Zeek/dns | 48 | 2.61s | 4.02s | 4.02s |
| Zeek/tls | 7 | 2.92s | 4.06s | 4.06s |
| Zeek/weird | 6 | 3.54s | 4.54s | 4.54s |
| **all** | 8123 | 1.56s | 3.04s | 4.79s |

Within budget: 100.00% of 8123 observations.
