# SC-004 searchability

Measured 2026-08-31T23:52:40Z by `TestObservationsBecomeSearchableWithinThirtySeconds`
against the deployed pipeline. Latency is from `observed_at` - when the
sensor read the analyzer's record - to the first query that returned it,
so each figure includes the one-second poll interval and is an upper bound.

Budget: 95% within 30s.

| source / subtype | n | p50 | p95 | max |
|---|---:|---:|---:|---:|
| Hubble/cluster_flow | 6651 | 1.89s | 3.54s | 3.82s |
| Zeek/connection | 33 | 2.55s | 2.88s | 3.53s |
| Zeek/dns | 48 | 1.88s | 3.52s | 3.52s |
| Zeek/tls | 7 | 2.72s | 2.99s | 2.99s |
| Zeek/weird | 2 | 3.49s | 3.49s | 3.49s |
| **all** | 6741 | 1.89s | 3.54s | 3.82s |

Within budget: 100.00% of 6741 observations.
