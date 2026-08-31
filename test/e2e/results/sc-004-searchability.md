# SC-004 searchability

Measured 2026-08-31T00:51:55Z by `TestObservationsBecomeSearchableWithinThirtySeconds`
against the deployed pipeline. Latency is from `observed_at` - when the
sensor read the analyzer's record - to the first query that returned it,
so each figure includes the one-second poll interval and is an upper bound.

Budget: 95% within 30s.

| source / subtype | n | p50 | p95 | max |
|---|---:|---:|---:|---:|
| Hubble/cluster_flow | 7181 | 1.28s | 2.59s | 3s |
| Suricata/signature | 1 | 490ms | 490ms | 490ms |
| Zeek/connection | 32 | 1.97s | 4.05s | 4.05s |
| Zeek/dns | 35 | 2.09s | 3.67s | 3.67s |
| Zeek/tls | 12 | 2.23s | 4.1s | 4.1s |
| Zeek/weird | 17 | 3.28s | 3.58s | 3.58s |
| **all** | 7278 | 1.28s | 2.61s | 4.1s |

Within budget: 100.00% of 7278 observations.
