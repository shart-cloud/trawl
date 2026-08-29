# Trawl MVP Validation Quickstart

This guide is the release-candidate acceptance path. It assumes the implementation
artifacts described by `plan.md` exist; it does not substitute for the generated
CRD/RBAC, integration, or security tests.

## 1. Prerequisites

- A disposable or approved Talos Kubernetes 1.35-1.37 cluster.
- Cilium with Hubble Relay, Grafana Alloy, Loki TSDB schema v13+, Grafana, and a
  private MinIO-compatible endpoint.
- One node labeled `trawl.cloud/sensor=eligible`.
- For physical testing, a dedicated mirror NIC and externally configured MikroTik
  SPAN source. Never use the cluster's only management interface.
- `kubectl`, the release-matched `trawlctl`, Go 1.26.7, container build tooling, and
  the repository's pinned test tools.
- Reviewed image references expressed by digest, separately authorized artifact and
  audit-ledger credentials in pre-created Secrets, audit mTLS material, and no real
  credentials or personal traffic in CI fixtures.

Confirm cluster context before making changes:

```bash
kubectl config current-context
kubectl version
kubectl get nodes -o wide
kubectl -n kube-system get deploy hubble-relay
kubectl -n trawl-system get secret trawl-artifact-storage
kubectl -n trawl-system get secret trawl-audit-ledger trawl-audit-client-tls
```

Expected: the intended non-production context is selected; supported nodes are
Ready; Hubble Relay is available; the storage Secret exists but its values are not
printed.

## 2. Run local and boundary gates

```bash
make verify
make test
make test-integration
```

Expected:

- Formatting, static analysis, generated-file drift, schemas, OpenAPI, examples,
  and dashboards pass.
- Unit tests pass for API validation, normalization, Community ID preservation,
  matching, threshold windows, canonical deduplication, rate limits, state
  transitions, authorization decisions, and sanitization.
- Real-boundary tests pass for Suricata, Zeek, dumpcap bounds/filter rejection,
  capture reporting, Hubble gRPC replay, Loki ingestion/query, immutable audit-ledger
  commit/replay, MinIO verification/presign/delete, and TokenReview/
  SubjectAccessReview behavior.

## 3. Install Trawl

Build the release bundle with immutable image references, inspect it, then install:

```bash
make build-installer
kubectl apply --server-side -f dist/install.yaml
kubectl -n trawl-system rollout status deployment/trawl-controller-manager --timeout=2m
kubectl -n trawl-system rollout status deployment/trawl-event-worker --timeout=2m
kubectl -n trawl-system rollout status deployment/trawl-artifact-gateway --timeout=2m
```

Verify that no release workload uses a floating tag or blanket privilege:

```bash
make verify-manifests
kubectl -n trawl-system get pods
kubectl get crd networktaps.trawl.cloud capturepolicies.trawl.cloud capturejobs.trawl.cloud
```

Expected: all three control-plane Deployments are Ready, all three CRDs are served,
and the manifest verifier confirms digest-pinned images plus the reviewed
capability set.

Verify that an off-namespace CR is rejected rather than ignored or reconciled:

```bash
kubectl create namespace trawl-invalid
kubectl apply -f config/samples/invalid/trawl_v1alpha1_networktap_off_namespace.yaml
```

Expected: admission rejects the request with the configured `trawl-system` namespace
in the field-specific message and creates no workload in `trawl-invalid`.

## 4. User Story 1 — Activate passive monitoring

Choose one sample matching the test environment:

```bash
kubectl apply -f config/samples/trawl_v1alpha1_networktap_mirror.yaml
```

or:

```bash
kubectl apply -f config/samples/trawl_v1alpha1_networktap_node.yaml
```

Wait for truthful status:

```bash
kubectl -n trawl-system wait networktap/north-south-mirror \
  --for=jsonpath='{.status.phase}'=Active --timeout=2m
kubectl -n trawl-system get networktap north-south-mirror -o yaml
```

Generate the repository's synthetic DNS, HTTP, TLS, and IDS-signature traffic from
the approved traffic generator:

```bash
make e2e-traffic TAP=north-south-mirror PROFILE=baseline
```

Expected within the acceptance windows:

- The tap reports the selected node/interface, both requested analyzers healthy,
  a recent packet time, and `observedGeneration == metadata.generation`.
- Suricata signature and Zeek connection/DNS/HTTP/TLS records arrive in Loki.
- Packet/drop/rejected counters are visible, and packet loss is not silently
  inferred as zero when the analyzer cannot report it.

Negative path:

```bash
kubectl apply -f config/samples/invalid/trawl_v1alpha1_networktap_missing_interface.yaml
kubectl -n trawl-system get networktap missing-interface -o yaml
```

Expected: admission or status names the invalid/unavailable interface; phase never
becomes `Active`; healthy unrelated taps continue processing.

## 5. User Story 2 — Investigate activity

Open the provisioned **Trawl Overview** and **Alert Investigation** dashboards.
For CLI validation, query the Loki endpoint through the repository test helper:

```bash
make query-observations TAP=north-south-mirror TYPE=signature SINCE=15m
make verify-correlation TAP=north-south-mirror SINCE=15m
```

Expected:

- Overview shows signature trends, protocol activity, Hubble verdicts, tap health,
  and suspected-duplicate observation indicators for the selected range.
- Selecting a signature with `flow.community_id` returns at least one Zeek record
  with the identical value and labels the relationship `exact`.
- A fixture without Community ID can be found by bounded time and normalized flow
  attributes, and the relationship is labeled `attribute-time`.
- DNS, HTTP, TLS, certificate, connection, file, notice, and weird fixtures expose
  their supported structured details without raw packet payloads.

Malformed isolation:

```bash
make e2e-malformed-observation TAP=north-south-mirror
```

Expected: the malformed count increases, no raw malformed record is logged, and a
valid record sent immediately afterward remains searchable.

Run the SC-005 timing protocol with the ten deterministic correlated sessions. For
each session, perform one attempt from its signature record and one from its protocol
record. Start timing when the source record opens and stop when the exact-match
counterpart is displayed:

```bash
make e2e-correlation-timing ATTEMPTS=20 SESSIONS=10
```

Expected: at least 18 of 20 attempts complete in under three minutes. Save only the
attempt number, direction, duration, and pass/fail result; do not save record bodies.

## 6. User Story 3 — Manual bounded capture

Apply the sample manual request after confirming its target is active:

```bash
kubectl apply -f config/samples/trawl_v1alpha1_capturejob_manual.yaml
kubectl -n trawl-system wait capturejob/manual-tls \
  --for=jsonpath='{.status.phase}'=Completed --timeout=5m
kubectl -n trawl-system get capturejob manual-tls -o yaml
```

Generate matching and non-matching fixture traffic while it runs:

```bash
make e2e-traffic TAP=north-south-mirror PROFILE=capture-filter
```

Expected: lifecycle proceeds `Pending → Capturing → Storing → Completed`; actual
times, zero-or-positive packet count, size, SHA-256, verified artifact reference,
and retention deadline are present. Size stops at the first bound and is no more
than 1 MiB over the requested maximum.

Validate authorization through a separate terminal running:

```bash
kubectl -n trawl-system port-forward service/trawl-artifact-gateway 8443:443
```

From the first terminal, pipe a short-lived, explicitly authorized analyst service-
account token to the supported CLI without putting the credential in process
arguments:

```bash
kubectl -n trawl-system create token trawl-acceptance-analyst --duration=10m | \
  trawlctl capture download manual-tls \
  --namespace trawl-system \
  --gateway https://127.0.0.1:8443 \
  --ca test/e2e/certs/gateway-ca.crt \
  --token-stdin \
  --output manual-tls.pcapng
sha256sum manual-tls.pcapng
```

Expected: the checksum equals `status.sha256`; the redirect and credential do not
appear in logs. The Capture Management dashboard shows the same non-secret copyable
`trawlctl` command and the Overview now includes recent capture activity. Repeat
with a token from `trawl-acceptance-viewer`; expect `403` and no evidence that an
artifact exists.

Invalid filter path:

```bash
kubectl apply -f config/samples/invalid/trawl_v1alpha1_capturejob_bad_filter.yaml
kubectl -n trawl-system wait capturejob/bad-filter \
  --for=jsonpath='{.status.phase}'=Failed --timeout=2m
```

Expected: `failure.reason=InvalidFilter`, `FilterValid=False`, no packet socket was
opened, and no artifact/download is reported.

Treat the downloaded pcapng as sensitive evidence and remove it through the
workstation's approved secure-file process after validation.

## 7. User Story 4 — Event-driven capture

Apply one policy of each supported trigger type:

```bash
kubectl apply -f config/samples/trawl_v1alpha1_capturepolicy_suricata.yaml
kubectl apply -f config/samples/trawl_v1alpha1_capturepolicy_hubble_drop.yaml
kubectl -n trawl-system get capturepolicy
```

Run matching, non-matching, duplicate, and rate-limit traffic fixtures:

```bash
make e2e-trigger-matrix TAP=north-south-mirror
```

Expected:

- Each qualifying event creates at most one CaptureJob with immutable policy UID,
  policy generation, trigger fingerprint/timestamps/flow, and resolved bounds.
- Non-matching events create none and increment `notMatched`.
- Equivalent events and cross-policy equivalent requests inside cooldown reference
  the existing job and increment `duplicate`.
- The hourly maximum is never exceeded and suppressed decisions remain visible.
- One failed policy/capture does not stop evaluation of another policy.

Restart the controller and event worker during active work:

```bash
kubectl -n trawl-system rollout restart deployment/trawl-controller-manager
kubectl -n trawl-system rollout restart deployment/trawl-event-worker
kubectl -n trawl-system rollout status deployment/trawl-controller-manager --timeout=2m
kubectl -n trawl-system rollout status deployment/trawl-event-worker --timeout=2m
make verify-execution-uniqueness
```

Expected: existing taps keep observing, every in-flight capture converges to one
terminal CaptureJob, and no CaptureJob UID has multiple runner Jobs or artifacts.

## 8. Retention and failure gates

Run the accelerated retention test, which uses the test-only fake clock and storage
namespace and cannot be enabled in release manifests:

```bash
make test-e2e TEST=retention
```

Expected: download is denied exactly at the retention deadline, upload-in-progress
objects are not deleted, verified deletion occurs within the simulated 24-hour
limit, and non-sensitive execution/audit metadata remains.

Run component and dependency failure injection:

```bash
make test-e2e TEST=failure-isolation
```

Expected: analyzer, Hubble, Loki, MinIO, audit sink/replay, gateway, and controller
failures produce the documented conditions/metrics. Loki outage accumulates a
durable audit backlog and later replays it; audit-ledger outage fails user mutations
and successful downloads closed. Unaffected taps/modes/policies remain active and
monitoring never modifies or interrupts the test traffic path.

## 9. Performance acceptance

Run only on the approved representative cluster and isolated traffic source:

```bash
make test-e2e TEST=reference-load RATE=100mbit DURATION=60m
```

Expected:

- Active sources stay available for the full hour.
- The first structured observation arrives within 15 minutes, and at least 19 of 20
  valid tap creation/update trials reach `Active` or an actionable non-active state
  within two minutes.
- Capture-boundary packet loss is below 1%.
- At least 95% of valid observations are searchable within 30 seconds.
- At least 95% of manual captures start within 10 seconds and become downloadable
  within 60 seconds after capture ends with healthy storage.
- Trigger deduplication and hourly limits remain exact under the load.

Archive the sanitized acceptance summary, not pcaps or raw traffic, as release
evidence.

## 10. Safe cleanup

Delete only the acceptance resources by exact name:

```bash
kubectl -n trawl-system delete capturepolicy on-high-severity-alert repeated-policy-denial
kubectl -n trawl-system delete networktap north-south-mirror
kubectl delete namespace trawl-invalid
```

Confirm that owned analyzer workloads stop while historical CaptureJobs remain:

```bash
kubectl -n trawl-system get networktap,capturepolicy,capturejob
kubectl -n trawl-system get pods
```

Do not delete CRDs, the artifact bucket, Loki data, or `trawl-system` as ordinary
quickstart cleanup. Those operations require the separate audited purge procedure
because they can destroy retained evidence.
