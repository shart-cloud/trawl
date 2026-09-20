---
description: "Dependency-ordered implementation tasks for the Trawl MVP"
---

# Tasks: Trawl MVP

**Input**: Design documents from `specs/001-cloud-native-nsm/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`,
`contracts/`, and `quickstart.md`

**Tests**: Required by the Trawl constitution. In every user-story phase, create
the listed tests first, confirm that they fail for the missing behavior, then
implement until they pass.

**Organization**: Setup and foundational work precede four phases matching the
prioritized user stories. A task marked `[P]` changes a distinct file or subsystem
and can run concurrently once its phase prerequisites are satisfied.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Parallelizable after the phase's prerequisites
- **[US1]–[US4]**: User-story traceability labels
- Every task names the exact file or directory it changes

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Establish a reproducible Go/Kubebuilder project and record the
significant design decisions before code depends on them.

- [X] T001 Scaffold the Kubebuilder 4.15.0 Go v4 project for module `trawl.cloud/trawl` and the `trawl.cloud` API group in `PROJECT`, `go.mod`, `go.sum`, `Makefile`, and `cmd/controller-manager/main.go`
- [X] T002 Pin Go 1.26.7, controller-runtime 0.24.1, Kubernetes libraries 0.36.0, MinIO v7, Cilium/Hubble, gRPC, Prometheus, and test dependencies in `go.mod` and `go.sum`
- [X] T003 Pin controller-gen, setup-envtest, kustomize, golangci-lint, and vulnerability-scanner versions in `hack/tools.mk` and implement checksum/version verification in `hack/verify-tools.sh`
- [X] T004 [P] Configure Go formatting, vet, static analysis, import boundaries, and no-floating-dependency checks in `.golangci.yml`
- [X] T005 [P] Record the versioned normalized observation envelope, compatibility rules, and rollback consequences in `docs/src/content/docs/adr/0001-normalized-observation-envelope.md`
- [X] T006 [P] Record Loki/Hubble replay cursors, deterministic names, cooldown buckets, and restart-safe deduplication in `docs/src/content/docs/adr/0002-trigger-replay-and-deduplication.md`
- [X] T007 [P] Record separate private artifact/audit buckets and credentials, audit-ledger versioning/write-once retention and sink, retention authority, Kubernetes authorization, CLI-only MVP download, and rollback behavior in `docs/src/content/docs/adr/0003-artifact-storage-and-gateway.md`
- [X] T008 [P] Record direct-interface capture, required Linux capabilities, rejected blanket privilege, and passive rollback behavior in `docs/src/content/docs/adr/0004-capability-minimized-capture.md`
- [X] T009 Add pull-request jobs for tool verification, generated-artifact drift, unit tests, envtest, contract tests, and container integration tests in `.github/workflows/ci.yml`
- [X] T009a [P] Record the two-layer analyzer content model (upstream init-container refresh plus optional OCI custom overlay), the rejected alternatives (CI-only, CronJob, ConfigMap), and rollback behavior in `docs/src/content/docs/adr/0005-analyzer-content-management.md`

**Checkpoint**: The repository has a pinned, buildable scaffold and approved ADRs.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Implement the process, configuration, status, telemetry, admission,
test, and deployment primitives shared by all user stories.

**⚠️ CRITICAL**: No user-story implementation begins until this phase passes.

### Foundational tests

- [X] T010 [P] Add table-driven tests for the configured system namespace, separate artifact/audit bucket profiles and credentials, 90–730d audit retention, audit mTLS identities, duration/quantity parsing, secret-safe validation errors, and immutable image references in `internal/config/config_test.go`
- [X] T011 [P] Add regression and fuzz tests that reject tokens, URLs, credentials, packet bytes, query strings, and raw dependency output from errors in `internal/sanitize/sanitize_test.go`
- [X] T012 [P] Add tests for observed-generation handling, stable reasons, transition times, and associative condition updates in `internal/status/conditions_test.go`
- [X] T013 [P] Add contract/unit tests for allowed metric labels, versioned audit intent/outcome fields, stable keys, idempotent/conflicting commits, replay cursors, bounded retention, backlog metrics, health endpoints, and high-cardinality rejection in `internal/telemetry/contract_test.go` and `internal/audit/sink_test.go`

### Foundational implementation

- [X] T014 Implement typed installation configuration for cluster identity, enforced system namespace, Loki, Hubble TLS, separate artifact/audit buckets and credentials, 90–730d audit retention, audit mTLS identities, capture retention ceiling, sensor-agent resource requests/limits defaults, upstream content feed URLs and analyzer refresh schedule, and service-account identities in `internal/config/config.go`
- [X] T015 Implement bounded error and audit-field sanitization used at every external boundary in `internal/sanitize/sanitize.go`
- [X] T016 Implement standard condition constructors, observed-generation checks, stable-reason enums, and merge helpers in `internal/status/conditions.go`
- [X] T017 Implement structured logging, health/readiness registration, build information, and bounded Prometheus collectors in `internal/telemetry/telemetry.go`
- [X] T018 Implement shared private-S3 put/head/list primitives plus versioned sanitized intent/outcome audit records, stable idempotency keys, the mTLS audit client/sink, conditional put plus HEAD/version/write-once verification, conflict detection, persisted replay cursor/overlap, bounded ledger retention, and ledger-to-stdout replay in `internal/storage/s3.go`, `internal/audit/model.go`, `internal/audit/client.go`, and `internal/audit/sink.go`
- [X] T019 Create the shared controller-runtime envtest bootstrap, API scheme registration, fake clock, and isolated namespace lifecycle in `test/integration/suite_test.go`
- [X] T020 [P] Create reusable process, separate MinIO artifact/audit buckets with ledger write-once retention, audit mTLS sink, Loki, Hubble gRPC, and packet-fixture lifecycle helpers in `test/integration/harness/harness.go`
- [X] T020a [P] Add table-driven tests for upstream feed configuration, OCI reference parsing, digest validation, merge-order precedence, and corrupt/missing custom artifact fallback in `internal/content/content_test.go`
- [X] T021 Implement the admission webhook server, caller identity extraction, configured-namespace enforcement, durable-audit acknowledgement middleware, readiness, and fail-closed failure-policy wiring in `internal/admission/server.go`
- [X] T022 Wire scheme registration, namespaced manager cache, leader election, probes, metrics, webhook startup, mTLS audit sink/replay/retention runnable and cursor ConfigMap, graceful shutdown, and separate controller runnables in `cmd/controller-manager/main.go`
- [X] T023 [P] Define the configured `trawl-system` namespace, Pod Security labels, common ConfigMaps, separately authorized artifact/audit Secret references, audit mTLS service/material and retention configuration, and base Kustomization in `config/default/kustomization.yaml`, `config/namespace/namespace.yaml`, and `config/audit/service.yaml`
- [X] T024 [P] Define namespaced least-privilege controller/webhook ServiceAccounts, Roles, RoleBindings, audit-sink client identities, and default-deny/allowlist NetworkPolicies in `config/rbac/controller-role.yaml` and `config/networkpolicy/control-plane.yaml`
- [X] T025 Create reproducible multi-stage build targets for all Trawl Go binaries with non-root runtime images and immutable build metadata in `Dockerfile`
- [X] T025a [P] Build the content-init image with suricata-update, Zeek package tooling, OCI pull capability, merge logic, and feed-timestamp/digest reporting, with no runtime Kubernetes API access in `images/content-init/Containerfile`
- [X] T026 Add `generate`, `manifests`, `verify`, `test`, `test-integration`, `build-installer`, and manifest-security targets in `Makefile`
- [X] T027 Add generated CRD/RBAC/example/dashboard drift, observation-schema embedding, and audit-ledger/telemetry contract synchronization checks in `test/contract/generated_artifacts_test.go`

**Checkpoint**: Shared tests pass, the controller skeleton starts under the
Restricted profile, and user-story code can be added without redefining common
security or observability behavior.

---

## Phase 3: User Story 1 — Activate Passive Network Monitoring (Priority: P1) 🎯 MVP

**Goal**: An operator declares a mirror or node interface, enables Suricata and/or
Zeek with resource bounds, and receives truthful source/target/analyzer health plus
structured observations without modifying Talos or the monitored traffic path.

**Independent Test**: Apply one valid NetworkTap, generate known DNS/HTTP/TLS/IDS
traffic, and verify `Active` status and normalized Suricata/Zeek records; apply a
missing-interface tap and verify an actionable non-active status while the healthy
tap continues.

### Tests for User Story 1

- [X] T028 [P] [US1] Add failing NetworkTap configured-namespace, defaulting, closed-union, interface-name, analyzer-selection, resource-bound, and passive-only API tests in `api/v1alpha1/networktap_types_test.go`
- [X] T029 [P] [US1] Add failing golden tests for mirror Deployment, node DaemonSet, direct interface binding, explicit capabilities, projected sensor token, owner references, and resource limits in `internal/controller/networktap_workload_test.go`
- [X] T030 [P] [US1] Add failing envtest cases for create/update/delete, zero/one/many target resolution, partial analyzer health, stale generations, finalizer cleanup, and restart convergence in `internal/controller/networktap_controller_test.go`
- [X] T031 [P] [US1] Add failing Suricata EVE normalization and normative-schema tests for signature/common-flow fields, Community ID preservation, stats counters, suspected-duplicate marking, and safe rejection in `internal/observation/suricata_test.go`
- [X] T032 [P] [US1] Add failing Zeek normalization and normative-schema tests for connection/DNS/HTTP/TLS/x509/file/notice/weird fields, Community ID preservation, suspected-duplicate marking, redaction, and malformed-neighbor isolation in `internal/observation/zeek_test.go`
- [X] T033 [P] [US1] Add failing bounded duplicate-fingerprint window, sensor heartbeat, counter-reset, per-analyzer degradation, last-packet, associative target-status patch, and API outage tests in `internal/sensor/status_reporter_test.go`
- [X] T033a [P] [US1] Add failing content init tests for upstream fetch success/failure, OCI pull success/corrupt/missing, merge precedence, fallback to upstream-only, and reported feed timestamp and custom digest in `internal/content/content_test.go` and `test/integration/content_init_test.go`
- [X] T034 [US1] Add a failing cluster acceptance test for active, updated, deleted, durable mutation audit, audit-ledger outage fail-closed behavior, missing-interface, disappearing-target, analyzer-failure, and recovery scenarios in `test/e2e/networktap_test.go`

### Implementation for User Story 1

- [X] T035 [US1] Define NetworkTap spec/status types, enums, list-map markers, print columns, status subresource, defaults, optional custom-content OCI reference, analyzer content status fields, and structural/CEL validation markers in `api/v1alpha1/networktap_types.go`; sensor-agent resources are not user-configurable here and come from installation config (T014)
- [X] T036 [US1] Implement identity-aware NetworkTap validation/defaulting for configured-namespace enforcement, source unions, live selector rules, passive mode, resources, durable audit acknowledgement, and immutable forbidden fields in `internal/admission/networktap_webhook.go`
- [X] T037 [US1] Implement and embed the normative `trawl.observation/v1alpha1` schema plus its Go envelope, source/tap/target/flow types, subtype enums, and bounded validation errors in `internal/observation/model.go` and `internal/observation/schema.go`
- [X] T038 [P] [US1] Implement Suricata EVE signature/stats normalization and Community ID mapping in `internal/observation/suricata.go`
- [X] T039 [P] [US1] Implement Zeek connection/DNS/HTTP/TLS/x509/file/notice/weird normalization and sensitive-field redaction in `internal/observation/zeek.go`
- [X] T040 [US1] Implement rotation-safe analyzer file tailing, bounded record parsing, diagnostic fingerprints, a bounded rolling duplicate-fingerprint cache that marks without dropping records, and valid-record continuation in `internal/sensor/tailer.go`
- [X] T041 [US1] Implement heartbeat collection, Suricata kernel-drop/packet/duplicate counters, Zeek health, duplication state, upstream feed timestamps, custom content digest, reporter instance IDs, and field-owned status patches in `internal/sensor/status_reporter.go`
- [X] T042 [US1] Wire analyzer tailers, stdout observation emission, health probes, metrics, and status reporting in `cmd/sensor-agent/main.go`
- [X] T043 [US1] Render deterministic per-tap ConfigMaps, ServiceAccounts, Roles, RoleBindings, mirror Deployments, node DaemonSets, analyzer containers, sensor sidecar with installation-configured resources, content init containers (upstream fetch and optional custom OCI overlay), shared content volume, security contexts, and readiness probes in `internal/controller/networktap_workload.go`
- [X] T044 [US1] Implement idempotent NetworkTap reconciliation, node watches, generation rollout, scheduled analyzer rolling restarts for upstream content refresh, aggregate phase derivation, ownership-safe finalization, and dependency recovery in `internal/controller/networktap_controller.go`
- [X] T045 [US1] Restrict each generated sensor ServiceAccount to patch only its owning NetworkTap status by resource name in `internal/controller/networktap_rbac.go`
- [X] T046 [P] [US1] Build the Suricata 8.0.6 image from verified source with AF_PACKET/EVE/stats configuration, checksums, no baked-in rules (rules loaded from shared volume at startup), and no conditional pcap logging in `images/suricata/Containerfile`, `images/suricata/suricata.yaml`, and `images/suricata/SOURCES.lock`
- [X] T047 [P] [US1] Build the Zeek 8.0.10 LTS image from verified source with JSON logs, Community ID seed 0/base64, checksums, no baked-in scripts (scripts loaded from shared volume at startup), and direct-interface capture in `images/zeek/Containerfile`, `images/zeek/local.zeek`, and `images/zeek/SOURCES.lock`
- [X] T047a [P] [US1] Implement upstream feed fetch logic (suricata-update for Suricata, base script checkout for Zeek), OCI artifact pull and overlay merge, feed-timestamp/digest output for status reporting, and graceful fallback when custom content is absent or corrupt in `internal/content/fetch.go` and `internal/content/merge.go`
- [X] T047b [P] [US1] Add a CI pipeline definition or Makefile target that validates custom Suricata rules (syntax check) and Zeek scripts (parse check), packages them as an OCI artifact, and pushes to a configurable registry in `hack/build-custom-content.sh`
- [X] T048 [US1] Configure Alloy discovery, normative-schema JSON parsing, four bounded observation labels, duplicate-suspected structured fields, durable-ledger audit parsing with stable keys, structured metadata promotion, rejection metrics, and separate Loki write routing in `config/alloy/trawl-observations.alloy` and `config/alloy/trawl-audit.alloy`
- [X] T049 [US1] Generate and review the NetworkTap CRD, cluster-wide admission rule that rejects outside the configured namespace, namespaced RBAC/manager watches, immutable image-digest patches, default upstream feed URLs and refresh schedule in `config/content/`, and valid/invalid/off-namespace samples in `config/crd/bases/trawl.cloud_networktaps.yaml`, `config/webhook/manifests.yaml`, and `config/samples/invalid/trawl_v1alpha1_networktap_off_namespace.yaml`
- [X] T050 [US1] Implement synthetic baseline/duplicate traffic fixtures and make the NetworkTap acceptance test prove schema conformance, duplicate visibility, verified durable mutation audit, audit-outage fail-closed control with unaffected monitoring, and first structured observation within 15 minutes without host installation or packet-path mutation in `test/e2e/traffic/baseline.go` and `test/e2e/networktap_test.go`

**Checkpoint**: US1 is deployable as the MVP. A valid source continuously produces
truthful health and observations; invalid or failed sources are isolated and
actionable.

---

## Phase 4: User Story 2 — Investigate Security Activity (Priority: P2)

**Goal**: An analyst explores signature, protocol, and cluster-flow activity in
Grafana and pivots by exact Community ID or explicitly approximate time/attributes.

**Independent Test**: Load a synthetic session with a signature and protocol
records, pivot from either record to its exact counterpart in under three minutes,
then verify an event without Community ID is returned only as `attribute-time`.

### Tests for User Story 2

- [X] T051 [P] [US2] Extend the US1 Draft 2020-12 contract tests with Hubble observations, every supported subtype, and forbidden raw/sensitive fields in `test/contract/observation_schema_test.go`
- [X] T052 [P] [US2] Add failing exact, direction-normalized, clock-skew, ambiguous, and no-match correlation tests in `internal/observation/correlation_test.go`
- [X] T053 [P] [US2] Add failing real-Loki tests for time, tap, target, type, severity, rule, Community ID, endpoint, and fallback queries with ingestion-latency measurement in `test/integration/loki_queries_test.go`
- [X] T054 [P] [US2] Add failing Hubble TLS/GetFlows/reconnect/lost-event/allowed/denied normalization tests against a gRPC fixture in `test/integration/hubble_observation_test.go`
- [X] T055 [P] [US2] Add failing dashboard contract tests for bounded labels, required panels, exact/approximate badges, safe links, query ranges, and supported schema fields in `test/contract/grafana_dashboards_test.go`
- [X] T056 [US2] Add a failing end-to-end investigation test covering the observation-only overview, exact pivot in both directions, fallback pivot, every protocol subtype, Hubble context, and 30-second searchability in `test/e2e/investigation_test.go`

### Implementation for User Story 2

- [X] T057 [US2] Implement exact Community ID and direction-normalized time/attribute correlation classification with explicit ambiguity results in `internal/observation/correlation.go`
- [X] T058 [US2] Define reviewed LogQL query templates for overview, signature detail, exact pivot, approximate pivot, protocol filters, and Hubble timelines in `config/grafana/queries/trawl.logql`
- [X] T059 [US2] Implement a TLS-authenticated Hubble Observer GetFlows client with bounded filters, reconnect backoff, event-time watermarks, and lost-event signals in `internal/events/hubble/client.go`
- [X] T060 [US2] Normalize Hubble endpoints, namespaces/workloads, verdicts, drop reasons, observation points, timestamps, and safe flow fields into cluster-flow observations in `internal/events/hubble/normalize.go`
- [X] T061 [US2] Wire leader election, Hubble observation streaming, normalized stdout output, probes, metrics, and graceful reconnect in `cmd/event-worker/main.go`
- [X] T062 [US2] Deploy the observation-mode event worker with Hubble CA/client mounts, read-only Loki configuration, Restricted security context, RBAC, and egress NetworkPolicy in `config/manager/event-worker.yaml` and `config/networkpolicy/event-worker.yaml`
- [X] T063 [US2] Extend embedded normative-schema validation to Hubble records and keep Alloy structured-metadata mappings synchronized in `internal/observation/schema.go` and `config/alloy/trawl-observations.alloy`
- [X] T064 [P] [US2] Provision the independently complete observation-only Trawl Overview dashboard for observation volume, signatures, protocols, Hubble verdicts, tap health, and suspected-duplicate indicators in `config/grafana/dashboards/trawl-overview.json`
- [X] T065 [P] [US2] Provision the Alert Investigation dashboard with exact Community ID and visibly approximate fallback pivots in `config/grafana/dashboards/alert-investigation.json`
- [X] T066 [P] [US2] Provision the Protocol Analysis dashboard for connection, DNS, HTTP, TLS, certificate, file, notice, and weird records in `config/grafana/dashboards/protocol-analysis.json`
- [X] T067 [US2] Add deterministic investigation fixtures and make schema, Loki, Hubble, dashboard, and end-to-end investigation tests pass in `test/fixtures/observations/` and `test/e2e/investigation_test.go`

**Checkpoint**: US2 provides a complete investigation workflow using fixture data
or the live US1 source, with honest correlation semantics and bounded telemetry.

---

## Phase 5: User Story 3 — Collect a Bounded Forensic Capture (Priority: P3)

**Goal**: An authorized analyst requests one target-specific bounded capture,
observes truthful lifecycle progress, and downloads a verified unexpired artifact.

**Independent Test**: Submit a filtered manual CaptureJob, generate matching and
non-matching traffic, verify first-bound stop, metadata/checksum/download, then
exercise invalid filter, zero-packet, storage failure, restart, unauthorized, and
expired paths.

### Tests for User Story 3

- [x] T068 [P] [US3] Add failing CaptureJob API tests for configured-namespace enforcement, defaults, bounds, manual/policy caller unions, execution immutability, authorized retention-only updates, durable-audit failure, and non-resurrection in `api/v1alpha1/capturejob_types_test.go`
- [x] T069 [P] [US3] Add failing lifecycle tests for every legal/illegal transition, observed facts, zero-packet completion, failure reasons, downloadability, and expiry in `internal/capture/state_test.go`
- [x] T070 [P] [US3] Add failing dumpcap-runner tests for BPF dry-run before socket open, duration/size first-bound stop, snaplen, cancellation, sanitized failures, and <=1MiB overshoot in `internal/capture/runner_test.go`
- [x] T071 [P] [US3] Add failing real-MinIO tests for stable object keys, conditional upload, manifest/checksum verification, missing/mismatch handling, presign ceiling, and idempotent delete in `test/integration/artifact_storage_test.go`
- [x] T072 [P] [US3] Add failing envtest cases for target resolution, stable Job/reporter creation, reporter field ownership and progress patches, existing Job/object adoption, storage failure, audit failure, controller restart, and one terminal result in `internal/controller/capturejob_controller_test.go`
- [X] T073 [P] [US3] Add failing OpenAPI/handler/CLI tests for TokenReview audience, `capturejobs/download` SubjectAccessReview, enumeration resistance, lifecycle responses, no-store headers, short redirects, and durable audit acknowledgement before redirect in `internal/gateway/handler_test.go` and `internal/gateway/client_test.go`
- [x] T074 [P] [US3] Add failing fake-clock tests for exact deadline denial, authorized shortening/extension, upload protection, hourly deletion retry, 24-hour bound, and metadata preservation in `internal/controller/retention_test.go`
- [x] T075 [US3] Add a failing end-to-end manual capture matrix for reporter-driven progress, successful CLI download, invalid-filter, inactive-source, unavailable-target, zero-packet, full-storage, audit outage, restart, unauthorized-download, and expiry cases in `test/e2e/manual_capture_test.go`

### Implementation for User Story 3

- [x] T076 [US3] Define CaptureJob execution, policy snapshot, artifact, failure, phase, condition, print-column, status-subresource, and validation types in `api/v1alpha1/capturejob_types.go`
- [x] T077 [US3] Implement CaptureJob defaulting and validation for configured-namespace enforcement, caller identity, manual/policy fields, execution immutability, bounded pre-expiry retention changes, controlled delete policy, and durable audit acknowledgement in `internal/admission/capturejob_webhook.go`
- [x] T078 [P] [US3] Implement duration/size/snaplen parsing, supported placeholder-free manual BPF validation requests, and safe runner arguments in `internal/capture/bounds.go` and `internal/capture/filter.go`
- [x] T079 [P] [US3] Implement the artifact manifest, stable namespace/UID object key, SHA-256 calculation, packet-count parsing, and verification comparison in `internal/capture/manifest.go`
- [x] T080 [US3] Implement the capture runner sequence plus atomic versioned runner/reporter protocol for target/interface checks, BPF dry-run, post-socket `CaptureStarted`, bounded dumpcap execution, pre-upload `CaptureEnded`, compact terminal result, conditional upload, and sanitized exits in `internal/capture/runner.go` and `internal/capture/reporter.go`
- [x] T081 [US3] Wire capture and unprivileged reporter modes, bounded shared-file validation, field-owned status patches, signal handling, metrics, and exit codes in `cmd/capture-runner/main.go`; mount no Kubernetes API credentials in capture mode
- [x] T082 [US3] Build the digest-pinned capture-runner image with reviewed dumpcap/libpcap, non-root defaults, writable bounded work volume, and source checksums in `images/capture-runner/Containerfile` and `images/capture-runner/SOURCES.lock`
- [x] T083 [P] [US3] Extend the foundational private MinIO/S3 client with artifact manifest metadata, presign, idempotent delete, expiry verification, timeouts, TLS, and safe errors in `internal/storage/s3.go`
- [x] T084 [US3] Implement deterministic node-pinned Kubernetes Job rendering with direct interface access, ephemeral-storage bounds, explicit capture-only capabilities, shared progress `emptyDir`, unprivileged reporter sidecar, capture-container token suppression, reporter projected token, resource-name-scoped status Role, and owner reference in `internal/controller/capturejob_workload.go`
- [x] T085 [US3] Implement CaptureJob reconciliation, active tap/target resolution, Job observation/adoption, reporter-owned progress consumption, S3 HEAD verification, durable audit before lifecycle commits, conditions, retries, and terminal convergence in `internal/controller/capturejob_controller.go`
- [x] T086 [US3] Implement the guarded lifecycle transition and artifact-downloadability logic used by the reconciler and gateway in `internal/capture/state.go`
- [x] T087 [US3] Implement deadline calculation, immediate download denial, upload-aware hourly deletion, object absence verification, retry conditions, and `Expired` transition in `internal/controller/retention.go`
- [X] T088 [P] [US3] Implement audience-bound Kubernetes TokenReview and resource-name/subresource SubjectAccessReview clients with deny-by-default caching in `internal/authz/kubernetes.go`
- [X] T089 [US3] Implement the artifact gateway download handler and CLI client library with live CaptureJob/object verification, five-minute/deadline presign calculation, enumeration-safe errors, no-store responses, rate limits, and durable audit acknowledgement before redirect in `internal/gateway/handler.go` and `internal/gateway/client.go`
- [X] T090 [US3] Wire TLS serving, auth/audit/storage clients, probes, metrics, request IDs, graceful shutdown, and log redaction in `cmd/artifact-gateway/main.go`, and implement bearer-producing kubeconfig-exec or token-stdin download without credential arguments in `cmd/trawlctl/main.go`
- [X] T091 [US3] Deploy the gateway and capture reporter permissions with explicit ServiceAccounts, resource-name-scoped reporter status Roles, `capturejobs/download` roles, TokenReview/SubjectAccessReview access, artifact-only storage Secret mounts, audit-sink mTLS, TLS, and NetworkPolicies in `config/gateway/deployment.yaml` and `config/rbac/artifact-gateway-role.yaml`
- [X] T092 [US3] Generate and review the CaptureJob CRD/cluster-wide namespace-rejecting webhook/namespaced RBAC, manual analyst and retention-admin roles, successful/invalid samples, and capture image digest patch in `config/crd/bases/trawl.cloud_capturejobs.yaml`, `config/rbac/capturejob-roles.yaml`, and `config/samples/`
- [x] T093 [US3] Extend Trawl Overview with recent capture activity and add execution lifecycle, artifact health, retention, storage usage, and non-secret copyable `trawlctl` commands to `config/grafana/dashboards/trawl-overview.json` and `config/grafana/dashboards/capture-management.json`
- [x] T094 [US3] Complete real dumpcap/reporter/MinIO/audit-ledger/gateway/CLI integration fixtures, including checksum comparison and secret-leak assertions, in `test/integration/manual_capture_test.go`
- [x] T095 [US3] Make the full manual capture/CLI matrix pass and record sanitized lifecycle and timing evidence in `test/e2e/manual_capture_test.go` and `test/e2e/results/manual-capture.md`

### US3 implementation notes (deviations from the task text)

Recorded as they are made, so the task list and the tree do not silently
diverge.

- T068: the API tests are envtest cases in `test/integration/capturejob_api_test.go`
  (repo convention; they share `suite_test.go`), not `api/v1alpha1/capturejob_types_test.go`.
  Caller identity, retention authorization and durable-audit failure are unit
  tests in `internal/admission/capturejob_webhook_test.go`, since they depend
  on the admission request rather than the schema.
- T076: `status.runnerResult` (`RunnerResult{outcome, reason, stopReason,
  packetCount, sizeBytes, sha256, exitCode, message}`) is added beyond
  `contracts/crd-api.md` as the reporter-owned carrier for the runner's terminal
  outcome; `crd-api.md` is updated alongside. The requester is recorded in the
  `trawl.cloud/requester` annotation, stamped by the mutating webhook from the
  API server's user info and immutable afterwards.
- T077: retention-admin identity is installation configuration
  (`capture.retentionAdminGroups` / `capture.retentionAdminUsers`), and the
  event worker identity for `requestType: Policy` is
  `capture.eventWorkerServiceAccount` in the system namespace. Deletion is
  namespace-gated only at admission; the controller's finalizer records it as
  `artifact.expire` records with the outcome. Filter validation at admission is
  size and character set only; BPF compilation happens in the runner (T080).
- T073/T089: the download route is the OpenAPI contract's
  `/api/v1/namespaces/{namespace}/capturejobs/{name}/download`, not the plan
  prose's `/v1/captures/...`, and the refusal codes follow the contract rather
  than the plan's "enumeration-safe 404 for everything": 403 for a denied
  SubjectAccessReview (decided before the CaptureJob is read, so it reveals
  nothing about existence), then 404/409/410 for an authorized caller. The
  quickstart agrees - a viewer gets 403.
- T073/T089: `X-Trawl-SHA256` is added to the 303 beyond the original contract,
  which defined no way for the CLI to learn the expected checksum. The CLI talks
  to nothing but the gateway, so without it a truncated or substituted object
  would download cleanly. `artifact-api.openapi.yaml` is updated alongside.
- T089: the request ID is always generated by the gateway and never taken from
  the request, because it forms part of the download audit record's idempotency
  key - a caller-chosen value would let a repeat download collapse onto an
  earlier record and disappear from the ledger.
- T089: the per-caller rate limit is keyed by authenticated identity rather than
  source address (every request arrives from the same ingress), and is applied
  after authentication but before authorization so a throttled caller cannot
  hammer the API server's SubjectAccessReview path.
- T088: `capture.DecideDownload` was extracted so `Downloadable` and the gateway
  cannot disagree; the bool is now derived from it. The gateway needs the reason
  a download is refused (409 versus 410), which the bool cannot carry.
- T090: `config.Images.ArtifactGateway` was NOT added. The gateway is a static
  Deployment like the event worker, so its image is pinned in
  `config/gateway/deployment.yaml` and refreshed by `hack/refresh-digests.sh`.
  `config.Images` is for images the operator renders at runtime; an unused field
  there would be exactly the dead wiring this slice existed to remove.
- T090: `cmd/trawlctl` takes its bearer token from stdin or from the standard
  output of a command it runs (`--token-exec`, whose own arguments follow a
  `--`), never from an argument or the environment. It refuses an existing
  `--output`, writes to `<output>.part`, and renames only after
  `gateway.Client.Download` has verified the checksum - a failure leaves the
  final name untouched, which `TestTheFinalNameNeverHoldsUnverifiedBytes`
  asserts from inside the object store while the transfer is still running.
  Exit codes: 0 success, 1 a failed or refused download, 2 a usage error.
- T090: the client binary has no image and no `images.yml` entry. It runs on the
  analyst's workstation; `make trawlctl` builds it, and quickstart §6 says so.
- Not a tasks.md item: `test/integration/manual_capture_test.go` is the plan's
  Slice B3 integration half. The plan calls it T074, but tasks.md's T074 is the
  retention test in Slice C - the numbers do not line up, so nothing was ticked
  for it. It drives the real reconciler against MinIO to Completed, then
  downloads through an in-process gateway with `gateway.Client`: a presigned URL
  from a real object store, the bytes it serves, and the ledger record. The
  TokenReview and SubjectAccessReview are faked, because envtest issues no
  audience-scoped service account tokens and its RBAC has no bindings to
  consult; `internal/authz` covers the real reviewer.
- T091: `artifact-gateway-tls` is added to `config/certmanager/certificate.yaml`
  now that the Service DNS name exists; B0 deliberately deferred it. It carries
  localhost/127.0.0.1 in its SANs because the documented access path is a
  port-forward, and without them the first thing anyone reaches for is a flag to
  skip verification.
- Not in tasks.md: `internal/tlsutil` now holds the certificate reloader the
  audit sink had privately, since the gateway needs the same renewal behaviour;
  the manager's metrics container port (8443) is declared, which it never was.
- T072: the controller tests are envtest cases in
  `test/integration/capturejob_controller_test.go`, for the same reason as T068.
- T079: the packet count comes from walking the pcapng blocks of the finished
  file (EPB and SPB), in the same pass as the SHA-256, not from parsing
  dumpcap's stderr.
- T080/T081: the reporter is its own binary and image, `cmd/capture-reporter`
  with the logic in `internal/capture/reporter/`, not a mode of
  `cmd/capture-runner`. The runner image may not link client-go (depguard), and
  a mode switch in one binary would have made that rule unenforceable. The
  runner therefore mounts no API credential at all; the reporter sidecar holds
  the only token, scoped by a resource-name Role to this one CaptureJob's status.
- T082: the runner runs as uid 0 with exactly NET_RAW and NET_ADMIN, the same
  posture as the analyzers, rather than "non-root defaults"; dumpcap's socket
  open needs the capabilities and the image has no setcap step to lose. dumpcap
  comes from the Debian `wireshark-common` package, version and .deb sha256
  pinned in `images/capture-runner/SOURCES.lock`, not built from source.
- research.md §9: `dumpcap -d` activates the capture handle to learn the link
  type before compiling the filter. The invariant kept is the one that matters:
  no output file, no packets, and no `CaptureStarted` before the filter
  compiles.
- T085: `RunnerCreateFailed` is reserved for a runner Job the apiserver
  rejects (Invalid or Forbidden); transport errors on create are retried as a
  dependency failure with the phase unchanged. Deleting a CaptureJob deletes
  its Job in the background and waits for the runner's pod to be gone before
  removing the artifact, so a runner cannot upload into a key that was just
  deleted.
- Not in the task list but required: `audit.Committer` moved from the admission
  package so the controller commits through the same contract as the webhooks;
  the closed telemetry label enums for the capture metrics; the `images.yml`
  split into a `capture-runner-image` job (Containerfile over a pinned Debian
  base) and a `capture-reporter` binary image; `capture.credentialsSecret`,
  `capture.startupBudget`, `capture.uploadBudget` and the runner/reporter
  resource settings in the installation config.
- Follow-up hardening, out of scope for US3: controller-issued presigned PUT
  URLs so the privileged runner holds no long-lived bucket credential.
- Slice B3 live acceptance ran on the single-node homelab cluster on 2026-09-04
  against the `1c81d87` build. `manual-tls` went `Pending -> Capturing ->
  Storing -> Completed` on the first attempt: 102 packets, 11972 bytes,
  `stopReason: Duration`, `ArtifactVerified=True`, and a seven-day retention
  deadline. The analyst download returned bytes whose SHA-256 equals
  `status.sha256`, `capinfos` counts the same 102 packets, no `.part` survived,
  and the file is written 0600. The viewer is refused with a sanitized
  `{403, request_id}` that matches its ledger record; the `denied` record omits
  the resource UID, so a refusal does not confirm the artifact exists. Both
  `artifact.download` records carry no URL-bearing field. The invalid-filter
  sample fails with `InvalidFilter`, `FilterValid=False`, and no artifact.
- Quickstart §6 could not be run as written, for two reasons now fixed there.
  The samples name `targetNode: talos-sensor-01`, a placeholder no real cluster
  has; §6 now reads the node from the tap and substitutes it rather than the
  samples carrying a homelab hostname into a public repository. The field to
  read is `status.targets[].nodeName`, not `.node`.
- The gateway answers `303` with a presigned URL for the endpoint named by
  `storage.profiles[].endpoint`, and the CLI follows it from the workstation.
  Nothing in the codebase distinguishes an in-cluster endpoint from one a client
  can reach, so with the development MinIO of `config/dev/trawl-config.yaml` the
  documented flow stops at `no such host` after a port-forward of the gateway
  alone. The SigV4 signature covers the `host` header, so the bucket has to be
  reached under the name it was signed for; §6 now forwards MinIO and maps that
  name. A production object store is reachable already, which is why this only
  shows up here. An operator-configured external presign endpoint is the real
  fix and is not in US3.
- The "no presigned URL in any log" check currently passes vacuously: both
  artifact-gateway pods emit zero log lines, startup included, while the
  controller-manager logs normally, and MinIO's access log is off. The grep for
  `X-Amz-Signature` therefore found nothing because there was nothing to search,
  not because a URL was withheld. The silence is total and deliberate as far as
  the code goes: `internal/gateway` contains no logger at all, and
  `cmd/artifact-gateway` writes to stderr only from `fatal` and the metrics
  server, so the process says nothing on startup, nothing per request, and
  nothing about an authorization decision. Routing every decision to the audit
  ledger instead is ADR-0003's design and keeps URLs and tokens out of stdout,
  but a server that cannot report that it is listening, or why it refused
  something, is hard to operate; the vacuous grep is a side effect of that
  rather than a finding about presigned URLs. Worth a decision in Slice C.
- T074: the retention tests are envtest cases in `test/integration/retention_test.go`,
  not `internal/controller/retention_test.go`, for the same reason as T068 and
  T072 - they drive a real reconciler against a real API server. The clock is
  the reconciler's own `Now` field rather than the `internal/status` package
  clock, so a test moves time by reconciling `at` a chosen instant.
- T087: a refused deletion is **not** returned as a reconcile error. An error
  gets controller-runtime's exponential backoff, which retries a broken bucket
  within milliseconds and then settles at a cadence nobody chose; the
  requirement is a verified deletion within 24 hours of the deadline, so the
  retry is a flat hour and the failure is carried by
  `RetentionEnforced=False/RetentionFailed`, the reconcile-outcome metric, and a
  `failed` expiry record. `RetentionOverdue` is exported so the alert rule and
  the dashboard read the 24-hour bound from the same place the controller does.
- T087: retention is a second controller over CaptureJob
  (`Named("capturejob-retention")`), not part of `CaptureJobReconciler`. The two
  run on different clocks - one on the runner's progress, one on a deadline days
  away - and a bucket refusing a delete must not hold up captures still running.
- T087: the deadline is always `status.completedAt` plus `spec.retention`, never
  `now` plus it, which is what makes a shortening a shortening; recomputing from
  the moment of the change would let repeated shortenings extend an artifact's
  life indefinitely. It is exclusive at the instant itself, matching
  `capture.DecideDownload`, so the gateway and retention cannot disagree about
  whether an artifact is live.
- T087: `Downloadable=False` is written and persisted **before** the delete, and
  `TestTheArtifactIsDeniedBeforeItIsDeleted` asserts that from inside the
  store's `Delete`. Afterwards the two orderings are indistinguishable, so the
  assertion has to run mid-deletion (principle 31). The test fails loudly with
  "the ordering was never exercised" if no delete is attempted, rather than
  passing for free.
- T087: `storage.Fake` gained `FailDelete`, `SwallowDeletes` and `DeleteCount`.
  `SwallowDeletes` is what makes the post-delete `Head` worth having: against a
  store that always tells the truth the absence check cannot fail, so a test
  using one proves the check is present and nothing about whether it works
  (principle 29). All four guards - the write-first ordering, the absence
  verification, the exclusive deadline, and the completedAt-based recomputation
  - were removed one at a time and each was caught by a named test failing for
  the right reason.
- **Defect found by the cluster acceptance, fixed here.** An authorized
  retention change permanently stopped a capture being downloadable, and the
  status blamed expiry for it. A retention change bumps `metadata.generation`;
  `ArtifactVerified` was stamped at the previous one and nothing re-verifies an
  artifact a retention change did not touch, so `status.IsTrue` read the stale
  True as not-true and `capture.DecideDownload` answered not-ready forever. The
  gateway refused with `409 the capture has no verified artifact to download`
  for an artifact that was verified, present, and two hours short of its
  deadline. `setDownloadable` then reported the reason as `Expired` because it
  tested downloadability and guessed the reason from the phase. Two fixes: the
  controller carries `ArtifactVerified` forward to the new generation on the
  retention-change path (`status.CarryForward`, which moves only the observed
  generation and not the transition time), and `setDownloadable` switches on
  `DecideDownload`'s decision rather than re-deriving it, so the reason can no
  longer be a lie. No envtest case caught this because none bumped the
  generation of a completed capture; the regression test that does is
  `TestAnAuthorizedRetentionChangeKeepsTheArtifactDownloadable`.
- T075 is **complete**. `test/e2e/manual_capture_test.go` covers the successful
  CLI download with checksum agreement, the viewer's refusal and its ledger
  record, the invalid filter, the unavailable target, the inactive source, the
  zero-packet capture, an authorized shortening moving the deadline from
  completion, and - each opt-in behind its own gate - a full artifact store
  (`TRAWL_E2E_FULL_STORAGE=1`), an audit outage (`TRAWL_E2E_LEDGER_OUTAGE=1`, the
  gate the NetworkTap suite already uses), a controller restart mid-capture
  (`TRAWL_E2E_RESTART=1`) and a real expiry (`TRAWL_E2E_EXPIRY=1`). Every gated
  spec has been run, not merely written; see the note below on why that was the
  condition for ticking this.
- T075: the acceptance specs found three rules no unit test had exercised. The
  shortest retention the API accepts is an hour, so a live expiry cannot be
  made fast and is opt-in rather than faked. Retention may only be changed by a
  member of `capture.retentionAdminGroups`, which a cluster administrator is
  deliberately not in, so the spec impersonates one - a service account cannot
  be put in an installation's own group. The bundle ships a
  `trawl-retention-admin` ClusterRole and binds nothing to it, because who the
  retention admins are is an installation decision, so the spec makes the
  binding itself and that is also what proves the shipped role carries the
  verbs a retention change needs.
- T075: the download specs skip unless the presigned redirect can be followed
  from the machine running them. The gateway answers 303 for the object store
  endpoint and the client follows it, and the SigV4 signature covers the host
  header, so the bucket has to be reachable under exactly the name and port it
  was signed for. Against the development MinIO the suite forwards that exact
  port when the name already resolves to loopback; when it cannot, it skips
  with the fix rather than failing, because that describes the machine and not
  the software.
- T075: the expiry spec asserted the wrong refusal until review caught it. An
  expired capture is `410 Gone`, not `404`: the artifact API contract
  distinguishes a capture whose retention ended from one that never existed,
  because an analyst told "no such capture" goes looking for a typo rather than
  for the retention policy. The assertion was never going to pass, and being
  behind `TRAWL_E2E_EXPIRY=1` meant the hour-long wait would have been spent
  before anyone found out - the same shape as T094's silently skipping specs.
  Check an opt-in spec against the shipped contract, not against the design you
  remember.
- T075: the refusal specs assert `HTTP 410` and `HTTP 403`, not the bare
  digits. The capture name carries a nine-digit run id and the CLI's message
  carries a request id, so a bare `strings.Contains(out, "410")` can be
  satisfied by a refusal that is not the one under test - including the 409
  not-ready that the retention defect above produced.
- T075: the artifact bucket connection is memoized for the run like the
  ledger's, and the ledger-outage spec drops both when it restores storage.
  They are the same MinIO, so a connection held across that spec is a socket to
  a deleted pod either way; memoizing one without adding it to that reset would
  have made the next reader fail on a refused connection that reads like a
  broken bucket rather than a stale fixture.
- T075 inactive-source: the fixture is a tap whose node selector matches no
  node, not a tap naming an interface that does not exist. A tap with a target
  places a sensor DaemonSet and waits on it, which costs minutes and re-tests
  what the NetworkTap suite covers; a selector nothing carries leaves the tap
  out of Active immediately with nothing scheduled, which is all a CaptureJob
  needs to see. The deployed tap is deliberately left alone - taking the
  installation's monitoring down to observe a status field would make this a
  disruptive spec instead of one that runs in every pass.
- T075 inactive-source: `TapInactive` is also the reason a *missing* tap fails
  with, so the failure reason alone does not tell an operator which object to
  look at. The `TargetReady` condition message is the only place the difference
  survives, so the spec asserts on it as well. The failure arrives after a grace
  window of twice the tap heartbeat - three minutes on the shipped constant - so
  the spec's timeout clears that grace rather than a reconcile.
- T075 zero-packet: an empty capture is a completed capture, not a failure, and
  the assertion set is built around zero being the value most likely to be lost.
  It is the zero value of the count, the field is an optional pointer, and it
  passes through a manifest, a status write and JSON, so anywhere it is treated
  as unset a real capture is reported as one that never ran. The filter is an
  RFC 5737 documentation address on a port nothing listens on: a filter that
  merely looks unlikely can be satisfied by traffic that happens to arrive, and
  would fail the spec somewhere else and much later. The empty result is also
  downloaded, because the empty case is the one a shortcut would skip. Note that
  `stopReason` lives on `status.runnerResult`, not on the status root - it is
  the runner's relayed claim rather than something the controller verified.
- T075 full-storage: the lever is a bucket quota below what the artifact bucket
  already holds, not real bytes. Filling a shared cluster's object store means
  writing gigabytes and hoping they can all be removed, and the writer is told
  the same thing either way; MinIO enforces the quota on the next write rather
  than after a usage scan, which was checked before the spec was written. The
  quota is set with `mc` inside the MinIO pod, building its alias from the
  `MINIO_ROOT_USER`/`MINIO_ROOT_PASSWORD` the pod already has, so the root
  credential never becomes an argument and never reaches the workstation. The
  spec ends by completing a capture after the quota is cleared, which is what
  distinguishes "storage was full" from "captures stopped working" and is also
  what proves the lever was really lifted.
- T075 audit outage: two things the installation's shape decides. The ledger and
  the artifact bucket are the same MinIO, so stopping the ledger stops both and
  the gateway's `503` does not name the missing dependency - the spec asserts
  that the gateway refused rather than served, which is the property, and says
  so rather than claiming more. And the gateway's `readyz` consults the artifact
  bucket, so the outage takes every gateway pod out of the Service's endpoints;
  a forward to the Service then fails with no endpoints, which is the Service
  behaving correctly and says nothing about what the gateway would have
  answered. The spec forwards a gateway *pod* directly to observe the refusal.
- T075 restart: the spec compares the controller's pod names before and after.
  A label selector that matches nothing deletes nothing and reports success, and
  a rollout that never started reports success immediately, so without the
  comparison the spec would pass having restarted nothing - the failure shape a
  disruption spec is most likely to have and least likely to notice. The capture
  runs for 90s so the restart lands while packets are being collected; a restart
  before `startedAt` would test the controller creating a runner Job, which
  every other spec here already covers.
- T075: two harness defects were found by *running* the gated specs, both of the
  "reports plausibly while doing nothing" kind. `kubectl port-forward` binds its
  local listener before it contacts anything, so forwarding a pod on the
  Service's port number - the container listens on 8443, the Service on 443 -
  bound happily, passed the old readiness check, and failed minutes later as a
  refused connection that read like the gateway being down. The forward helper
  now waits for a TLS handshake, which cannot succeed unless bytes are really
  reaching the gateway, and reads the container's port from the pod rather than
  assuming the Service's.
- T075: the object-store port-forward is a **third** connection the run
  memoizes, after the ledger and artifact clients, and `stopLedger`'s restore
  has to drop it too. The presigned redirect is followed by the CLI over that
  forward, so after an outage the cluster is healthy and the next download fails
  inside the object-store fetch, which reads like a broken bucket rather than a
  stale fixture. It is easy to miss precisely because it is not an S3 client.
  The spec that caused the outage also re-establishes the route before its own
  post-restore download; every later spec picks up a fresh one from the reset.
- T095 is **complete**. `test/e2e/results/manual-capture.md` is re-run against
  the whole matrix on the deployed `8814f68`: SC-006 at 100% of 20 samples on
  both budgets (start p50 2s / p95 3s against 10s; downloadable p50 0s / p95 1s
  against 60s), the analyst-allowed and viewer-denied download decisions with
  their ledger object names, the nine lifecycle specs, the audit outage and -
  for the first time - a real expiry. Every gated case has a recorded window of
  its own, because each stops something installation-wide and they cannot share
  one.
- T095: the expiry spec passed on its **second** execution and has never passed
  on a first. Its first real run gave up twenty-two seconds short of the
  deadline the object was carrying, because it computed one absolute timeout
  from the deadline it read at completion. The retention reconciler recomputes
  `completedAt + retention` and writes the answer back when status disagrees -
  `observedDeadline` exists to do exactly that - so the reading a spec takes at
  completion is not the one enforcement acts on. `waitForExpiry` now re-reads
  the deadline as it waits, logs it when it moves, and reports both timestamps
  when it gives up. The deadline was separately confirmed not to drift on an
  idle cluster, so this was the spec's fault and not the installation's. That
  makes four assertions in this suite that were wrong until something forced
  them to run, and the first of the four that execution caught rather than
  review.
- T095: SC-006 is measured from the CaptureJob's own status - `requestedAt` to
  `startedAt`, and `captureEndedAt` to the `Downloadable` transition - rather
  than from the test's polling. A test that timed its own loop would report its
  poll interval as much as the system's latency, and would give a figure nobody
  could reproduce from the stored object afterwards. Two honest limits go with
  it: `metav1.Time` serializes to whole seconds, so every figure is quantized
  and the `0s` p50 means "under a second, not resolvable further"; and
  `startedAt` is the node clock while `requestedAt` is the controller's, which
  is the same clock only because the reference cluster is a single node.
- T094 is split across two files rather than the one the task names. The
  gateway, CLI and ledger half is `test/integration/manual_capture_test.go`,
  written in Slice B2 against envtest and real MinIO. The real-dumpcap half is
  `test/integration/capture_lifecycle_test.go` behind the `investigation` build
  tag: real dumpcap on loopback, the real reporter against envtest, real MinIO,
  the checksum comparison, and the secret-leak assertions over both the runner's
  log output and the status. Splitting it keeps the default `make test` free of
  a suite that needs a capture-capable binary.
- T094: the tagged file skips unless dumpcap is present *and* permitted to open
  an interface, which are different problems with different fixes, so the skip
  says which. On a Debian-family workstation `/usr/bin/dumpcap` is mode 754
  `root:wireshark`, so it is not executable at all unless the account is in the
  `wireshark` group - `sg wireshark -c '...'` picks that up without a re-login.
  A skipping test proves nothing, so these were not counted until they had run:
  changing the capture filter by one port makes the capture see no packets, and
  making the invalid filter valid stops it reporting `InvalidFilter`, each
  caught by its named assertion.
- T094: the `investigation` lint pass covered `./test/e2e/...` only, so a tagged
  file under `test/integration/` would have rotted unlinted. Widening it to both
  directories found four real issues in the new file on its first run, which is
  the argument for the widening.
- Deploying is two applies, and their order matters. `config/dev/trawl-config.yaml`
  is not part of `config/default`, so `kustomize build config/default | kubectl
  apply` repoints only the three Deployments and the CRD; the ConfigMap holding
  the sensor, runner and reporter digests needs its own apply. Applying it
  *after* the Deployments, as this deploy first did, leaves the controller
  having loaded the previous config at startup - the pod started at 22:12:21 and
  the ConfigMap was written at 22:12:24 - so it renders the tap from stale image
  references and would create capture runners from the previous build. The
  symptom is visible in the tap DaemonSet's container images and nowhere else,
  and both applies report success either way. Apply the ConfigMap first, or
  restart the controller and event worker afterwards.
- T093: `capture-management.json` is the first Prometheus dashboard in the
  repository; the other three are Loki-only. Two contract rules were written as
  statements about every query and are really statements about LogQL - Loki
  indexes a small fixed label set, and holds every cluster's records together,
  so a stream selector must use only indexed labels and must pin `cluster`.
  PromQL uses the same brace syntax with neither property, so both rules now
  apply to Loki targets only, selected by the target's (or panel's) datasource
  type. Mutating a Loki query to drop `cluster` and select on `request_id`
  still fails both, so the exemption is for Prometheus rather than for
  everything.
- T093: no panel filters `trawl_artifact_operations_total` to the presign
  operation, because `TestDashboardsCarryNoSecretsOrDownloadLinks` forbids the
  string `presign` anywhere under `config/grafana`. The operation is still
  visible: the panel groups by the label rather than naming the value, so
  presign arrives as a series from the data instead of from the file.
- The acceptance also showed `kubectl get capturejobs` printing `EXPIRES` as
  `<invalid>`. A `type=date` print column renders the time elapsed since its
  value, which is what makes `Age` readable, but `status.retentionDeadline` is
  in the future for every capture that has not already been deleted, so the
  column was `<invalid>` for the whole life of the object. It is now
  `type=string` and prints the timestamp. `NetworkTap`'s `Last Packet` is
  genuinely a past time and stays a date.
- Not in tasks.md: `.gitignore` gained the two artifacts §6 has the operator
  create - `*.pcapng` and `test/e2e/certs/` - because neither was ignored and
  captured traffic and credentials are never committed. It also gained
  `/artifact-gateway`, `/capture-reporter` and `/trawlctl`, which were missing
  from the list of binaries a `go build ./cmd/x` without `-o` drops in the
  repository root.

- T092 is **review-and-tick, not build**: every artefact it names already
  existed and the cluster runs off them, and `make verify` reports no drift, so
  the "generate" half needed nothing. The review half is recorded in
  `test/e2e/results/t092-security-review.md` - the off-namespace rejection with
  an in-namespace control, the analyst/viewer/retention-admin verb matrix
  including the `capturejobs/download` split, and the invalid sample's failure
  reason read off the live object. Nothing was corrected; all three claims held.
- T092: unlike everything else in `test/e2e/results/`, that document was
  measured **by hand**, which is a limit and not a new convention. T121
  (`test/contract/security_manifests_test.go`) is the task that makes the static
  half re-runnable, and the review was deliberately not written there - T121's
  remit is much wider (wildcard RBAC, host namespaces, floating tags, hostPath,
  public buckets, telemetry) and half-filling it under T092's tick would have
  hidden how much of it is still missing.
- T092: **`kubectl auth can-i` cannot see a subresource.** Asked about
  `capturejobs.trawl.cloud/download` it silently answers for `capturejobs`,
  reporting the analyst as able to `create` the download subresource and the
  viewer as able to `get` it - the one permission the whole design withholds.
  T121 must assert this boundary with a `SubjectAccessReview` carrying an
  explicit `subresource` field, which is also what the gateway itself submits.
  Written with `can-i`, T121 would pass against RBAC flattened to let any viewer
  download every capture.
- T092: `status.failure.reason` is the `FailureReason` enum (`InvalidFilter`)
  while the `FilterValid` condition's reason is `FilterInvalid`
  (`internal/status/conditions.go:105`). Both spellings are correct in their own
  field. A check that reads conditions expecting the enum spelling will call the
  sample wrong when it is right.
- T092: `config/samples/trawl_v1alpha1_capturejob_manual.yaml` names
  `targetNode: talos-sensor-01`, which does not exist on this single-node
  cluster; applied verbatim here it would fail `TargetUnavailable`. Left as is -
  a node name is necessarily installation-specific and the sample is
  illustrative - but it is why the live `manual-tls` object carries
  `talos-node` and the file does not.

**Checkpoint**: US3 provides bounded, restart-safe manual evidence collection and
authorized retrieval without requiring automatic policy evaluation.

---

## Phase 6: User Story 4 — Trigger Captures from Security Events (Priority: P4)

**Goal**: An operator arms signature or denied-flow policies that create at most
one equivalent bounded capture, preserve trigger context, and expose non-match,
duplicate, rate-limit, source-gap, and failure decisions.

**Independent Test**: Arm one policy of each supported type, emit matching,
non-matching, duplicate, threshold, and over-limit events, restart the worker, and
verify exact execution counts, immutable snapshots, target selection, counters,
and unaffected parallel policy evaluation.

### Tests for User Story 4

- [x] T096 [P] [US4] Add failing CapturePolicy API tests for configured-namespace enforcement, closed trigger unions, severity/reason filters, thresholds, typed placeholders, capture/rate/retention bounds, defaults, armed state, CRUD transitions, delete behavior, and durable-audit failure in `api/v1alpha1/capturepolicy_types_test.go`
- [x] T097 [P] [US4] Add failing pure Suricata match and safe typed-template rendering tests for severity, rule, category, flow fields, non-match reasons, and final BPF validation in `internal/policy/suricata_test.go`
- [x] T098 [P] [US4] Add failing Hubble drop match and rolling-threshold tests for reason, namespace, count/window, clock skew, replay, and source gaps in `internal/policy/hubble_test.go`
- [x] T099 [P] [US4] Add failing canonical direction-neutral flow key, cooldown bucket, deterministic name, same-policy, and cross-policy duplicate tests in `internal/policy/dedup_test.go`
- [x] T100 [P] [US4] Add failing persisted hourly-limit, active-count, policy-generation, restart-rebuild, and clock-boundary tests in `internal/policy/rate_limit_test.go`
- [x] T101 [P] [US4] Add failing Loki overlap cursor tests for timestamp ties, fingerprints, safe replay, cursor loss, malformed alerts, query failure, and lag/gap reporting in `internal/events/loki/cursor_test.go`
- [x] T102 [P] [US4] Add failing event-worker integration tests for concurrent policies, durable audit before create, audit outage, create-or-get races, leader handoff, CaptureJob snapshots, status counters, policy deletion, and independent failures in `test/integration/event_worker_test.go`
- [x] T103 [US4] Add a failing end-to-end automatic trigger matrix for signature/drop matches, thresholds, non-matches, duplicates, cross-policy collapse, hourly limits, reconnect gaps, and restarts in `test/e2e/automatic_capture_test.go`

### Implementation for User Story 4

- [x] T104 [US4] Define CapturePolicy trigger/capture/rate spec, runtime counters, phases, conditions, print columns, status subresource, defaults, and structural/CEL validation markers in `api/v1alpha1/capturepolicy_types.go`
- [x] T105 [US4] Implement CapturePolicy validation/defaulting for configured-namespace enforcement, same-namespace tap references, trigger unions, typed placeholders, bounds, retention ceiling, operator identity, and durable audit acknowledgement in `internal/admission/capturepolicy_webhook.go`
- [x] T106 [P] [US4] Implement deterministic Suricata signature matching, decision reasons, safe trigger snapshots, and typed filter rendering in `internal/policy/suricata.go`
- [x] T107 [P] [US4] Implement denied Hubble flow matching and bounded rolling threshold windows with replay-aware event identity in `internal/policy/hubble.go`
- [x] T108 [US4] Implement canonical direction-neutral five-tuple keys, cooldown buckets, deterministic CaptureJob names, and persisted create-or-get deduplication in `internal/policy/dedup.go`
- [x] T109 [US4] Implement hourly/active counts rebuilt from CaptureJobs, cooldown decisions, and policy-generation-aware status accounting in `internal/policy/rate_limit.go`
- [x] T110 [P] [US4] Implement atomic ConfigMap cursor persistence, overlap queries, fingerprint replay suppression, lag, and known-gap state in `internal/events/loki/cursor.go`
- [x] T111 [P] [US4] Implement bounded Loki range queries and normalized Suricata alert decoding without raw event logging in `internal/events/loki/alerts.go`
- [x] T112 [P] [US4] Extend the Hubble client with threshold-window replay, reconnect watermarks, and explicit unrecoverable loss reporting in `internal/events/hubble/client.go`
- [x] T113 [US4] Implement policy indexing, independent evaluation, target resolution, snapshot/bounds resolution, durable audit acknowledgement, CaptureJob construction, and decision emission in `internal/policy/engine.go`
- [x] T114 [US4] Implement CapturePolicy status/condition reconciliation, monotonic decision counters, last execution/suppression references, source health, and retry isolation in `internal/policy/status.go`
- [x] T115 [US4] Wire Loki alert polling, Hubble drop evaluation, policy cache watches, mTLS audit client, leader election, persistent cursors, metrics, and graceful handoff into `cmd/event-worker/main.go`
- [x] T116 [US4] Grant the event worker only read/watch NetworkTap/CapturePolicy/CaptureJob, create CaptureJob, patch CapturePolicy status, cursor ConfigMap permissions, and egress to the audit sink in `config/rbac/event-worker-role.yaml` and update `config/manager/event-worker.yaml`
- [x] T117 [US4] Generate and review the CapturePolicy CRD/cluster-wide namespace-rejecting webhook/namespaced RBAC plus armed/disarmed Suricata and Hubble samples with no deferred trigger types in `config/crd/bases/trawl.cloud_capturepolicies.yaml` and `config/samples/`
- [x] T118 [US4] Add policy phase, decision counters, source gaps, active captures, cooldown/rate state, and suppression references to `config/grafana/dashboards/capture-management.json`
- [x] T119 [US4] Make unit, integration, restart, and end-to-end automatic trigger matrices pass and record sanitized count evidence in `test/e2e/automatic_capture_test.go` and `test/e2e/results/automatic-capture.md`

### US4 implementation notes

- The Loki blocker recorded in earlier handoffs was a measurement error, not a
  gap. Suricata alerts do reach Loki: the pipeline sets `service_name`,
  `observation_type` and `source_kind`, so the probes that queried
  `{namespace="trawl-system"}` and `{pod=~"trawl-tap.*"}` could never have
  matched - those are precisely the high-cardinality labels the telemetry
  contract forbids. `{service_name="trawl-observation", source_kind="Suricata"}`
  returns the alerts. T101 and T111 can be written against a populated stream.
- A real defect was found while confirming that: `severity`, `rule_id` and
  `category` were declared as structured metadata and populated by nothing,
  because the second `stage.json` read `source = "details"` and no earlier stage
  extracted `details`. Fixed by reading them at full path in the first stage.
  **The gitops HelmRelease still needs `hack/render-alloy-config.sh` run against
  `main`** before the fix reaches the cluster; until then those three fields are
  absent from every alert in Loki, and any query filtering on them matches
  nothing rather than failing.
- The contract tests could not have caught it: they regex the names in
  `stage.labels`, and a name declared there is a name whether or not anything
  populates it. `test/contract/alloy_labels_test.go` now also resolves each
  expression against a real marshalled envelope.
- T097/T106, T098/T107 were run as vertical TDD pairs rather than
  tests-then-implementation, because writing a full suite against code that does
  not exist yet tests imagined behavior. Task content is unchanged; only the
  order differs.
- **Matching takes the normalized envelope**, not raw EVE JSON or `flowpb.Flow`.
  Both sources already normalize to `observation.Observation`, and that is also
  the shape sitting in Loki, so the matchers are pure functions with no fakes.
- **Placeholder values are typed, not escaped.** BPF has no quoting to escape
  into, so a value carrying filter syntax can only be refused. A source IP of
  `1.2.3.4 or tcp` would otherwise render a filter capturing all TCP traffic
  instead of one host.
- **The threshold window counts on `ObservedAt`, not `EventTime`.** A window
  measured on producer time is one an unsynchronized producer can distort: a
  single flow stamped an hour ahead advances the window past every real event
  and silently stops the policy firing. `EventTime` is still what the snapshot
  records.
- T099/T108: the deduplication key deliberately excludes the policy, so two
  policies matching the same traffic under the same cooldown collapse to one
  capture. FR-031 says "within the cooldown window", which reads per-policy,
  while the edge cases say equivalent cross-policy requests collapse; **the
  ambiguity was raised and resolved in favour of cross-policy collapse**, which
  is what the edge case describes and what "at most one equivalent bounded
  capture" implies. Policies with *different* cooldowns bucket differently and
  will not collapse - that is accepted, not overlooked. T113 may rely on this.
- T099/T108 are complete. The persisted create-or-get half landed with T113:
  propose `CaptureJobName(key)`, and on `AlreadyExists` adopt the existing job
  rather than capturing twice.
- T096 lives in `test/integration/capturepolicy_api_test.go`, not the
  `api/v1alpha1/...` path the task names. The schema is only meaningfully
  testable against a real API server: asserting the markers are present in
  source tests that someone typed them, not that they mean what was intended.
  Confirmed load-bearing by stripping the trigger's CEL block, which fails three
  of the four union cases (the fourth passes on the enum alone).
- T105's reason for existing is the filter template. No schema rule can express
  "one of these five placeholder names", so `policy.ValidateFilterTemplate` is
  shared between the webhook and the renderer - one map keyed by name holding
  both the resolver and a specimen value, so the two cannot drift.
- The CapturePolicy webhook is registered in `cmd/controller-manager/main.go`
  and the CRD is listed in `config/crd/kustomization.yaml`. Both were done with
  T104/T105 rather than deferred: either omission leaves the feature passing its
  tests and absent from the cluster.
- `make setup-envtest` is required before `go test ./test/integration/...`, and
  `KUBEBUILDER_ASSETS` must be an **absolute** path
  (`export KUBEBUILDER_ASSETS="$(pwd)/$(bin/setup-envtest use 1.36.2 --bin-dir bin -p path)"`);
  the relative path setup-envtest prints leaves envtest looking in
  `/usr/local/kubebuilder/bin`. `make test` sets this itself.

- **T113 and T114 are not at the paths the tasks name.** Both need a Kubernetes
  client, and `.golangci.yml` forbids `sigs.k8s.io/controller-runtime` and
  `k8s.io/client-go` under `internal/policy/**` - the boundary plan.md's Project
  Structure draws around the pure domain ("pure match, threshold, dedupe,
  cooldown, hourly limit"). They are
  `internal/controller/capturepolicy_engine.go` and
  `internal/controller/capturepolicy_status.go`, as `PolicyEngine` and
  `PolicyStatusTracker`. `internal/policy` keeps the pure logic they call into.
  Weakening the lint rule to match the task path would have traded a real
  architectural boundary for a filename.
- T113: a policy-created CaptureJob carries **no owner reference**. An owner
  reference would have the API server delete the evidence when the rule that
  collected it is deleted. `spec.policyRef` records the relationship without
  handing it the object's lifetime.
- T113: a matched event with **no eligible target still creates the job**,
  without a `targetNode`. FR-034 wants the failure visible on both the policy
  and the attempted execution, and a request that is simply dropped leaves
  nothing to look at. The CaptureJob schema already permits this shape for a
  Policy request, and T102 asserts the API server admits it.
- T113: a **disarmed policy is still evaluated** and reports what it would have
  captured, creating nothing and writing nothing to the ledger. That is what the
  contract's `disarmed` decision label is for, and "this rule would have fired
  eleven times today" is what an operator needs before arming it. A disarmed
  policy that did not match reports nothing at all, so its counters do not climb
  with ordinary traffic.
- T113: only creations reach the audit ledger. A **deduplicated request created
  no capture**, so its collapse is recorded in status counters and metrics
  rather than as ledger history. The stable key covers the deduplication key,
  the step, and the policy UID: the first is what two racing workers agree on
  without having spoken, and the last is what stops two policies wanting one
  capture from claiming one record identity with different content.
- T114: status is **batched, not written per event**. A busy signature produces
  decisions faster than the API server should be asked to record them. Counters
  are applied as deltas so they accumulate, and a failed write keeps its batch
  for the next flush - a conflict has nothing to do with the policy, and
  dropping the batch would silently lose decisions that really happened. Every
  policy is reconciled on each flush, not only the ones with pending decisions,
  or a newly armed policy would sit with an empty status indefinitely.
- T114: phase and the rate-limit condition are **derived from the CaptureJobs on
  every flush** rather than latched on the last suppressed decision, so they
  clear as captures age out of the trailing hour.
- T115 replaces the hand-rolled leader election with a **controller-runtime
  manager**. The cache is what makes evaluation affordable - every armed policy
  is consulted per event - and it supplies the policy watches and the graceful
  handoff the task asks for. The probe and metrics servers stay outside it, so a
  standby holding no lease still answers probes.
- T115: a **truncated alert page is not counted as a gap**. The page is the
  front of the window and the cursor advances over what was read, so the rest is
  backlog; if the backlog ever outruns the lookback, `Cursor.Resume` reports
  that as the gap it has by then really become. A **failed query does not
  advance the cursor** (advancing over an unread window makes a transient outage
  permanent), while a **failed evaluation does** (the failure is already on the
  policy, and not advancing would stop the cursor forever).
- T115 added `eventWorker.auditClient` to the installation config, an
  `event-worker-audit-client` Certificate, and the matching mount in
  `config/manager/event-worker.yaml`, plus
  `TestDevConfigEventWorkerPathsAreMounted`. Deferring them to T116 would have
  left a worker that evaluates every event and creates nothing (FR-036) - a
  component that looks finished and does nothing.
- T115: `hubble.Client.ReplayWindow` became `SetReplayWindow`. The worker
  recomputes the widest armed threshold window on each status tick while the
  stream goroutine reads it on every reconnect; the exported field was a real
  data race.
- T117 is review-and-add rather than generate: the CRD was generated and wired
  into `config/crd/kustomization.yaml` with T104/T105. The review confirmed
  `scope: Namespaced`, the trigger enum closed to `SuricataAlert` and
  `HubbleDrop` with no deferred types, and both webhook configurations carrying
  no `namespaceSelector` or `objectSelector` - which is what makes them
  cluster-wide, so a policy written in any namespace reaches the gate that
  rejects it (FR-001).
- T117 added `config/rbac/capturepolicy-roles.yaml`. **RBAC cannot separate
  arming from editing**: armed is a field on the spec, so anyone who may update
  a policy may arm it. Two other things carry that weight - the field defaults
  to false so arming is always a deliberate second act, and the ledger records
  it as `capturepolicy.arm` rather than as an ordinary update. `capture-policy-admin`
  deliberately does not grant `capturejobs/download`: authoring a rule that
  collects packets is a different act from reading them.
- **Nothing validated `config/samples` before T117.** A sample that does not
  apply is the first thing an operator copies. `test/integration/samples_test.go`
  now applies every sample to a real API server and additionally runs the
  CapturePolicy ones through `admission.ValidateCapturePolicySpec`, because the
  filter template's placeholders are a webhook contract no schema rule can
  express - a sample naming an undocumented placeholder applies cleanly in
  envtest and is refused by the first real cluster. Mutation-checked: changing
  the sample to `{{src.ip}}` fails the webhook test and passes the apply test.
  `config/samples/invalid` is deliberately not swept, because half of it is
  webhook-rejected rather than schema-rejected and a blanket assertion would
  pass for the wrong reason; the one sample the schema itself refuses is
  asserted by name.
- T118: **policy phase, active captures and the suppression references are not
  on a Prometheus panel**, and could not be. contracts/telemetry.md closes the
  label set and forbids a policy or rule identifier as a label, because a rule
  identifier turns one series into as many as an operator can write. So the
  dashboard splits them: six metric panels for the aggregate shape (decisions,
  source health, lag, gaps, suppression, events), a Loki panel over the audit
  ledger for per-policy attribution, and a text panel with the `kubectl`
  commands that read phase, active captures, `lastTriggerTime` and
  `lastCaptureRef` off the object. Omitting them silently would have left an
  operator concluding Trawl does not report them.
- T118: the audit query was added to `config/grafana/queries/trawl.logql` as
  `policy_actions`, because `TestLogQLTemplatesAndDashboardsAgree` treats the
  reviewed templates as the contract. Two new contract tests pin the panels:
  both were mutation-checked by deleting the panels and by gutting the text
  panel's content.
- T103 **pushes synthetic alert observations into Loki** rather than trying to
  trip a specific ET rule with generated traffic. Suricata alerts reach the
  worker through the observation pipeline, so this makes the alert content
  synthetic and everything downstream real: a real worker polls it, real
  policies evaluate it, a real CaptureJob is admitted by the installed webhook,
  and a real runner collects packets. The sensor-to-Loki half is covered where
  it belongs, in the investigation and NetworkTap acceptance suites, against
  live traffic. The fixture reads the deployed tap's UID, node and interface off
  the cluster, because the engine attributes an alert to a policy by tap UID and
  an invented one would be declined as another tap's traffic.
- T103's denied-flow specs are **not** written against synthetic data, because
  the worker reads drops from Hubble's live gRPC stream rather than from Loki.
  They were written under T119, against a deployed worker: a scratch namespace,
  a deny-all-egress NetworkPolicy and a prober, reading the `POLICY_DENIED`
  verdict Cilium actually reports.
- T103 **no longer skips.** It skipped, loudly, naming the missing CapturePolicy
  CRD for as long as the cluster ran `8814f68`, which predates US4 - a skip
  describes the installation rather than the software, and a red build on a
  cluster running last month's image teaches people to ignore the colour. T119
  installed the CRD, and the whole matrix now runs: see
  `test/e2e/results/automatic-capture.md`.
### What deploying US4 found (T119)

The first task in this project that could not be finished from a laptop, and it
paid for itself in the first ten minutes.

- **The rollout is not a gitops PR.** Earlier handoffs said T119 needed a PR
  against `talos-gitops` pinning new digests. Trawl is not Flux-managed:
  `talos-gitops` carries no trawl path on any branch, Flux has no Kustomization
  for it, and every object in `trawl-system` carries kubectl's
  `last-applied-configuration`. The rollout is
  `kustomize build config/default | kubectl apply -f -` from this repo.
- **`config/default` already carried everything US4 adds.** The CapturePolicy
  CRD, the worker's Role and RoleBinding, the `event-worker-audit-client`
  Certificate and the worker NetworkPolicy all render from the default overlay
  with no rewiring. The worry that they might not was unfounded.
- **Two files the rollout does not carry.** `config/dev/trawl-config.yaml` and
  `config/hubble/` are applied out of band - the ConfigMap because it is a
  worked example rather than an installation, the Hubble certificate because
  `namePrefix` would double-prefix it. Both are load-bearing. The new binaries
  require `eventWorker.auditClient.*`, which the deployed ConfigMap did not
  have, so both pods crash-looped on `invalid installation configuration` until
  the ConfigMap was applied separately. A fresh install has the same hole and
  nothing announces it.
- **`capture.eventWorkerServiceAccount` named an identity that does not
  exist.** See the commit; the short version is that `namePrefix: trawl-`
  renames the worker to `trawl-event-worker` while the configuration named the
  pre-prefix `event-worker`, so the CaptureJob webhook refused every automatic
  capture as coming from someone other than the event worker. Every existing
  check in `devconfig_check_test.go` pairs the configuration against the same
  pre-kustomize manifests and so could not have caught it. The new check
  compares against the transformed name.

#### Known issue recorded and deliberately not fixed

- **A thresholded drop policy cannot say it is counting.** A qualifying flow
  held below its threshold is recorded as `OutcomeNotMatched`, which is the
  same counter every `FORWARDED` flow in the cluster increments against a drop
  policy. So `decisions.notMatched` is dominated by background traffic, and an
  operator holding a thresholded policy has no way to tell "accumulating
  toward five" from "seeing nothing at all" - the two look identical in status
  and in the metrics derived from it. `TestADropPolicyBelowItsThresholdCapturesNothing`
  deliberately makes no assertion about it, because any assertion available
  today would pass with the prober never started.

#### The Alloy render: not outstanding, and the note that said so was stale

Earlier handoffs carried "the gitops HelmRelease still needs
`hack/render-alloy-config.sh` run against it" as an open item. **It is already
done on `talos-gitops` `main`**, and was when the note was written. Verified by
rendering against `origin/main` in a throwaway worktree:
`TRAWL_GITOPS=<worktree> hack/render-alloy-config.sh --check` reports a match.

Two traps found while checking, worth recording because both would have caused
real damage:

- **Check against `origin/main`, never against whatever branch the gitops
  checkout happens to be on.** That checkout was on a feature branch whose
  `alloy.yaml` is 114 lines where `main`'s is 421 - it simply predates the
  render. Rendering against it and opening a PR would have reverted the entire
  generated region.
- **`main` already carries a drop rule, and it is more carefully scoped than
  the obvious one.** It drops `trawl-system/(sensor-agent|event-worker)` and
  deliberately *not* the controller manager, because the manager's ordinary
  container logs are what an operator reads when Trawl itself is the thing
  misbehaving - the audit pipeline takes the audit records from the same
  stream, and both copies are wanted. Adding `manager` to that regex would have
  silently removed the logs you need during an incident.

### Code review of the US4 branch

Two passes: one over the branch, one over its own fixes. The second found a
defect in the first's fix, which is the pattern this project keeps producing.

- **An IPv6 zone was a BPF injection.** `netip.ParseAddr` accepts everything
  after `%` as a zone - spaces, operators, whole clauses - and `String`
  re-emits it verbatim, so `RenderFilter` turned a source IP of
  `fe80::1%or udp port 53` into exactly that filter. The address comes from an
  observation record, which nothing validates as an address on ingest, so a
  crafted `flow.source.ip` widened any capture using `{{source.ip}}`. Parsing
  was the whole defense and parsing alone was not it. Zones are refused; a zone
  names a local interface and is meaningless in an on-wire filter.
- **The alert path would have hung on its first poll.** The cursor store is
  handed the manager's cached client, controller-runtime caches ConfigMaps by
  default, and a cached read starts an informer that LISTs and WATCHes every
  ConfigMap in the namespace - which the worker's Role deliberately withholds.
  Reflector forbidden, informer never syncs, `Get` blocks forever: no alert ever
  polled, no error anywhere. The review proposed granting `list`/`watch`, which
  works and **undoes the least privilege**: neither verb can be restricted by
  `resourceNames`, so it hands the worker every ConfigMap in the namespace,
  `trawl-config` included. The fix is `Client.Cache.DisableFor` on ConfigMaps
  instead. Every RBAC test used a direct client and would have passed with this
  broken, so one now builds the client the way `cmd/event-worker` does.
- **`spec.retention`'s clamp was dead code, in both webhooks.** The structural
  schema default of `30d` is applied while the API server decodes the request,
  before any mutating webhook runs, so the emptiness check never fired - and on
  an installation with a lower ceiling (the dev config's is 7d) validation then
  refused **every** policy *and every manual capture* that omitted retention.
  Both now clamp whenever the value exceeds the ceiling, which is what the
  field's own documentation always described. The consequence to know: an
  explicit `retention: 90d` in a Git-managed manifest is rewritten to the
  ceiling on every apply, which a GitOps tool will show as permanent drift.
- **The dedup race left a dangling audit intent** - but only across two
  *different* policies. For one policy on two workers the intent records are
  byte-identical and converge, so nothing was dangling there. The first fix
  gave the race path its own message, which made it **conflict** with the
  winner's record on the same stable key: a healthy collapse reported as an
  integrity error. The key now carries the decision (as `StableKeyForAdmission`
  already does, and for the same reason) and the race path writes the winner's
  content exactly. This also separates a failed outcome from a succeeded one,
  which shared a key before. Caught only by testing against a real `audit.Sink`;
  the fake committer returns success for anything and resolves no keys.
- **The threshold window was discarded on any generation bump** - arming a
  policy, changing its retention - throwing away a count that might have been
  one flow from firing. Keyed on the threshold itself now.
- **`DropThreshold.Window`'s documented 1s-15m bound was enforced nowhere.** A
  `0s` window expires everything not simultaneous with the newest event, so a
  threshold policy is armed, matching, and structurally incapable of firing. Now
  a CEL rule. Note for the test: `600m` is refused by the pattern, not the rule,
  because `metav1.Duration` marshals it as `10h0m0s`; `16m` is the smallest
  value that reaches CEL.
- **A node-name fix was reverted after review.** Hubble can report
  `<cluster>/<node>`; stripping the qualifier to make it match is the obvious
  fix and the wrong one. Under ClusterMesh the relay serves peer clusters' flows
  and node names repeat, so `prod-eu/worker-1` would match a local target called
  `worker-1` and the capture would file **the local node's unrelated traffic as
  evidence for another cluster's flow**. The comparison stays exact: withholding
  evidence is loud and recoverable, manufacturing the wrong evidence is neither.
  Stripping safely needs to know which cluster is ours, which nothing here does.
  This cluster reports bare names, so the original finding was hypothetical.
- Not fixed, recorded: `CapturePolicy` now clamps an over-ceiling retention
  while a `CaptureJob` update still rejects one, so the same input gets two
  answers depending on which resource is written. And a stored policy with a
  window over 15m becomes un-updatable, including to disarm it, on a cluster
  without CRD validation ratcheting.

- **Test provenance for Group E.** The engine, status and worker tests were
  written before their implementations and each was mutation-checked. One did
  not discriminate: `TestARecordTheOverlapRedeliversIsNotEvaluatedTwice` passed
  with the cursor's replay suppression removed entirely, because the
  deduplication key collapses the repeats downstream - it asserted the wrong
  mechanism. It now reads the accepted and replayed counters. A second mutation
  (removing the target heartbeat check) failed to build rather than failing the
  test, which is the handoff's warning about badly chosen mutations, not a weak
  test; widening it to a 100x window caught it.
- T116 grants **`update` on `capturepolicies/status`, not `patch`** as the task
  text says. The status tracker reads the policy, applies its batch of
  decisions, and writes back against the resourceVersion it read, so a
  concurrent writer loses with a conflict rather than silently clobbering the
  counters; a merge patch of computed totals would discard the other writer's
  increments with nothing noticing.
- T116: the worker gets `create` on CaptureJobs and deliberately no `update`,
  `patch` or `delete`. A capture is evidence and the worker's job ends when it
  has asked for one. Likewise the ConfigMap grant is restricted by
  `resourceNames` to `trawl-alert-cursor`, since an unrestricted one would
  include `trawl-config`.
- T116 also opened **egress to Loki** in
  `config/networkpolicy/event-worker.yaml`, which the task text does not name.
  T115 made the alert stream a polled Loki query, so without it every poll times
  out and no signature ever triggers a capture. The audit-sink egress and the
  `event-worker-audit-client` mount landed with T115 for the same reason.
- T116 is tested rather than reviewed. envtest runs the API server with
  `--authorization-mode=RBAC`, so
  `test/integration/event_worker_rbac_test.go` applies the Role from
  `config/rbac/event-worker-role.yaml` verbatim, binds it, and runs the real
  engine and status tracker through an impersonating client. Restating the rules
  in the test would have tested the file against itself. Four mutations were
  checked: dropping `create` on capturejobs, dropping `update` on
  `capturepolicies/status`, adding `update` on `capturepolicies`, and removing
  the `resourceNames` restriction each fail a test.

**Checkpoint**: All four user stories are functional. Automatic capture reuses the
same bounded, authorized execution path proven by US3.

---

## Phase 7: Polish & Cross-Cutting Release Gates

**Purpose**: Verify security, failure isolation, compatibility, performance,
operations, supply chain, and the complete quickstart before release.

- [x] T120 [P] Add audit completeness and durability tests for every required mutation, policy decision, transition, download decision, retention change, and expiry action, including intent/outcome pairs, idempotent retry, conflicting keys, MinIO/Loki outages, cursor overlap, duplicate-copy collapse, replay, bounded ledger retention, and fail-closed user actions in `test/integration/audit_test.go`
- [x] T121 [P] Add static security tests that reject off-namespace Trawl resources, wildcard RBAC, unexpected host namespaces/capabilities, service-account token leakage, floating tags, hostPath, public buckets, browser download links, and secret-bearing telemetry in `test/contract/security_manifests_test.go`
- [x] T122 [P] Add stored `v1alpha1` fixture round-trip, additive-defaulting, older-controller rollback, CRD storage-version, and uninstall-preservation tests in `test/integration/upgrade_rollback_test.go`
- [x] T123 [P] Document tap/analyzer health, packet loss/duplication, malformed records, trigger gaps, audit-ledger/replay backlog, storage/retention failure, and restart recovery procedures in `docs/src/content/docs/operations/runbook.md`
- [x] T124 [P] Document privileges, RBAC roles, BPF/filter trust boundary, evidence classification, local download handling, audit review, and purge approval in `docs/src/content/docs/security/evidence-handling.md`
- [x] T125 Run analyzer, controller, trigger, Loki, Hubble, MinIO, audit sink/replay, gateway, and retention failure injection while asserting durable audit or fail-closed user actions and passive unaffected monitoring in `test/e2e/failure_isolation_test.go`
- [x] T126 Run the 60-minute produced-rate reference test, recording the measured rate, plus at least 20 timed valid tap create/update trials and enforce first-observation <=15m, 95% reconciliation <=2m, packet-loss, ingestion-latency, capture-start/store, bound-overshoot, and trigger-count thresholds in `test/e2e/reference_load_test.go`
- [x] T127 Run exact deadline-denial and accelerated 24-hour deletion validation with upload protection and preserved metadata in `test/e2e/retention_test.go`
- [x] T128 Generate SBOMs, provenance, vulnerability results, upstream source verification, rule/script hashes, and immutable image digests in `dist/supply-chain/manifest.json`
- [x] T129 Configure release-blocking Go, container, manifest, dependency, and secret scanning with reviewed suppressions and expiry dates in `.github/workflows/security.yml` and `security/suppressions.yaml`
- [x] T130 Regenerate CRDs, RBAC, webhooks, install bundle, examples, observation schema embedding, and dashboards and prove a clean drift check in `dist/install.yaml` and `test/contract/generated_artifacts_test.go`
- [x] T131 Execute every command and expected outcome plus the defined ten-attempt exact-correlation timing protocol in `specs/001-cloud-native-nsm/quickstart.md` on the representative cluster and save only sanitized durations/counts in `test/e2e/results/quickstart.md`
- [x] T132 Complete the constitutional, security, operational, and measurable-outcome release checklist with links to passing evidence in `docs/release/readiness.md`

### Phase 7 implementation notes

- **T121 asserts what was not already asserted, and says where the rest lives.**
  Seven of the nine properties the task lists were already covered before the
  file existed - wildcard RBAC, floating tags, hostPath and host namespaces,
  restricted Pod Security, default-deny networking, browser download links and
  secret-bearing telemetry all have named tests in `generated_artifacts_test.go`,
  `grafana_dashboards_test.go` and `observation_schema_test.go`. Duplicating them
  would have produced a second thing to keep true and a second place to look, so
  `security_manifests_test.go` opens with an index of them and adds the three
  that nothing covered: that admission can *see* an off-namespace resource
  (a `namespaceSelector` on the webhook configuration would make the system
  namespace rule unreachable rather than enforced), that a ServiceAccount bound
  to nothing refuses a token, and that nothing publishes the artifact bucket.
  A fourth was added beside them: no container may *add* a Linux capability.
  `TestManifestsRequestNoHostAccess` catches `privileged: true`, which is the
  loud form; a single added capability is the quiet one.
- **The T121 checks render `config/default` rather than reading `config/`.**
  Directly because of T119: a check that reads the pre-kustomize files is
  checking a workload nobody runs. All four were mutation-checked - a
  `namespaceSelector`, an unbound ServiceAccount, an added `NET_ADMIN`, and an
  anonymous bucket grant written into documentation - and each failed naming the
  defect. (The grant is described rather than quoted here on purpose: the check
  scans `specs/` and `docs/` too, so spelling the command out in prose about the
  check makes the check fail on its own description. That is the scanner working,
  not a false positive worth loosening it for - a copyable grant in
  documentation is exactly what it is meant to catch.)

- **T122 found that `make undeploy` destroyed every capture record.** It
  rendered `config/default` - which lists `../crd` - and piped the whole thing
  to `kubectl delete`. Deleting a CustomResourceDefinition deletes every object
  of that kind, so removing the operator also removed every CaptureJob,
  NetworkTap and CapturePolicy: the trigger snapshot saying why a capture was
  taken, the retention deadline, and the artifact key saying where the packets
  are. The pcaps survive in the bucket with nothing left in the cluster that
  knows they exist, and at the terminal it looks like a tidy uninstall.
  `hack/undeploy-manifests.sh` now filters the CRDs out of the delete set.
  `make uninstall` still removes them; it is no longer a side effect of
  removing a Deployment, and its help text says what it costs.
- **The schema-surface golden is the rollback gate.**
  `test/integration/testdata/v1alpha1-schema-surface.json` records every
  property path and every required path in the stored version. A property that
  disappears is data loss on the next write, because the API server prunes what
  the schema does not describe; a property that becomes required strands every
  stored object that omitted it, because without CRD validation ratcheting the
  API server then refuses every update to those objects - including the disarm.
  Regeneration is env-gated (`TRAWL_UPDATE_SCHEMA_SURFACE=1`) and never
  automatic: a test that rewrites its own expectations records the breakage
  instead of catching it.
- **`make test-integration` now passes `-count=1`.** envtest reads
  `config/crd/bases` at runtime, so editing a CRD changes nothing Go's test
  cache keys on. It served four consecutive stale passes during T122's mutation
  checks while the CRD under test was deliberately broken - the exact case
  these tests exist to catch. Two other traps in the same area, both worth
  knowing: removing a CRD field that a CEL rule references makes the CRD refuse
  to *install*, so the API server fails the suite before any test runs and the
  mutation proves nothing about the test; and `Armed bool json:"armed,omitempty"`
  means a typed client cannot send `armed: false` as an explicit value, so a
  disarm relies on the CRD default rather than on the field being written.

- **T120 adds completeness, not mechanics.** Conditional write, verification,
  idempotent retry, conflicting content for one key, fail-closed on an
  unavailable ledger, write-once retention, replay, cursor overlap and backlog
  were all covered already, in `internal/audit`'s unit tests and in
  `audit_ledger_test.go`. Every one of those starts from a record the test
  constructed, so all of them would keep passing if a mutating path stopped
  committing - or never committed - one. The two new questions are whether
  every declared action is written by some production path, and whether a
  fallible action leaves both of its records. Both were mutation-checked:
  removing the last two emitters of `retention.change` fails the first, and
  dropping `decision` from `StableKeyForAdmission` fails the second on every
  fallible action at once.
- **Why the intent/outcome check matters more than it looks.** Decision is part
  of the admission stable key, and that is the only thing keeping the two
  records of one request apart. Drop it and the outcome is written to the key
  the intent already holds, where the ledger refuses it as a content conflict -
  so the operation completes with the ledger saying it was authorized and
  nothing saying whether it happened. For a system whose output is evidence,
  "authorized and then silence" cannot be told apart from "authorized and then
  failed".

- **T123 and T124 fill the two sidebar sections that were already configured
  and empty.** `astro.config.mjs` autogenerates Operations and Security from
  directories that did not exist, so the docs site had been shipping with two
  dead nav entries.
- **Both documents cite the system rather than describing it in general terms.**
  The runbook is written around the metric names, condition types and phases the
  code actually emits, and the roles table in the evidence document is read off
  the rendered `ClusterRole` verbs. Both also record the known blind spots found
  in this and earlier sessions rather than omitting them: the `entry too far
  behind` gaps in the Loki copy, the `failed` policy decision that logs nothing,
  the thresholded policy that cannot say it is counting, the retention clamp
  asymmetry that shows as permanent GitOps drift, and the label mistake that
  once made a populated Loki look empty. A runbook that pretends the blind spots
  are not there costs more than one that names them.
- **The evidence document ends with where the controls stop.** A downloaded file
  is outside all of them, a namespace administrator bypasses the role model
  entirely by reading the bucket credentials, Trawl classifies no content, and
  retention bounds the artifact but not the analysis derived from it. A control
  someone believes in and does not have is worse than one they know they lack.

- **T129 found that `govulncheck` had never run.** It was pinned in
  `hack/tools.mk`, installed by `hack/verify-tools.sh`, and asserted to be the
  right version by `make verify` - and nothing ever invoked it. A pinned scanner
  nobody runs is a supply-chain control on paper only. It now runs in CI and in
  a new `make security` target, and reports zero reachable vulnerabilities (one
  in an imported package and three in required modules, none of them called).
- **One suppression list, and its dates are enforced.** `security/suppressions.yaml`
  is the only place a finding may be accepted, and `hack/verify-suppressions.sh`
  fails the build on an entry that is past its `expires` date, missing a field,
  naming a scanner the project does not run, or carrying a reason too short to
  re-review. Trivy's ignore file is *generated* from it rather than maintained
  beside it, so a container suppression cannot outlive its review by living
  somewhere the checker never reads; `security/.trivyignore` is gitignored for
  the same reason.
- **Caveat: "release-blocking" needs a repository setting this commit cannot
  make.** The workflow is written to fail rather than warn, but a required check
  is required only when branch protection says so. Someone with admin on the
  repository has to add the Security jobs to the protected-branch rules, or the
  gate is advisory in practice.

- **T130's value is bundle completeness, not regeneration.** `make verify`
  already proved no drift and `dist/` is gitignored, so "regenerate and check"
  asserts almost nothing on its own. The two new contract tests ask the
  question that has actually bitten this repository twice: is the generated
  artifact *shipped*? A CRD reaches the installer only if someone listed it in
  `config/crd/kustomization.yaml`; controller-gen writes the file either way and
  envtest reads `config/crd/bases` directly, so a forgotten entry leaves every
  test passing while the installer ships without the type. The audit Service and
  the artifact gateway were both written-but-never-applied for exactly this
  reason, as `config/default/kustomization.yaml`'s own comments record.
- **The webhook check is the more dangerous half.** A configured path the
  manager does not register is worse than a missing one, because `failurePolicy`
  is `Fail`: the API server calls a path nothing serves and refuses every create
  and update of that kind installation-wide, naming a webhook rather than the
  real fault. Comparing markers to manifests would be circular - controller-gen
  generates one from the other - so the check compares the configuration against
  the manager's registration calls instead.
- **A mutation check caught a loose assertion in one of these tests.** The
  webhook check first matched the handler name as a bare substring, which a
  rename satisfies; it is anchored on the construction now, and the mutation was
  redone as an outright deletion of the registration block.

- **T128's governing rule: a section that could not be produced is recorded as
  absent with a reason, never omitted.** A manifest missing its SBOM section
  looks exactly like one whose SBOMs were never generated, and the second is the
  case somebody needs to know about. `dist/` is gitignored, so what is committed
  is the generator, the CI job that runs it where the images exist, and two
  contract tests - one asserting every required section is present with either
  content or a stated reason, one asserting the sources are pinned.
- **The generator found one real gap and one of its own making.** `cbindgen` is
  pinned by version with no checksum; that is now named in the manifest's
  warning rather than sitting in a list of things that look equally pinned.
  (crates.io makes a published version immutable, so it is weaker than the
  others rather than unsafe.) The generator also *reported* the capture-runner's
  wireshark pin as unpinned, which was wrong - it pins each Debian package under
  a nested `packages:` block and the check only read the top level. Fixed before
  committing: a manifest that cries wolf is read with the same attention as one
  that stays silent.
- **Zeek and Suricata are required to carry a detached signature, not merely a
  checksum.** They are compiled from upstream source and parse hostile input, so
  "the bytes did not change" is a weaker claim than the one that matters, which
  is who published them. Mutation-checked by deleting Zeek's signing key
  fingerprint.

- **Six contract tests had never run in CI.** `make test` did not depend on the
  `kustomize` target, so on a clean checkout `bin/kustomize` was absent and
  every test calling `renderDefault` took its `t.Skip`. `go test` prints nothing
  for a skip without `-v`, so the job was green and silent - including for
  `TestNetworkPolicyIngressPortsAreDeclaredContainerPorts`, which predates this
  phase, and for all four of T121's security gates. A silent skip is worse than
  a failure because it looks like coverage. `make test` now depends on
  `kustomize`, and `renderDefault` fails rather than skips when `CI` is set, so
  the class cannot recur quietly if that dependency is ever dropped again.

- **T125's first injection found a latent production defect, which is the
  argument for the whole task.** The artifact gateway had been broken for a day
  and nothing showed it. Three binaries parse the installation ConfigMap -
  controller manager, event worker, artifact gateway - and `config.Load` uses
  `yaml.UnmarshalStrict`, so an unrecognised field is a hard startup error.
  T119 added `eventWorker` to the ConfigMap and rolled only the two components
  whose *code* had changed; the gateway's had not, so it stayed on its pre-US4
  image and was broken from that moment. A running pod never re-reads its
  config, so the breakage was invisible until something restarted it - which
  the gateway-outage spec did, days later and for unrelated reasons.
- **The general rule, now in the runbook:** adding a field to the ConfigMap is a
  breaking change for every component not yet running an image that knows it,
  and the symptom appears at the next restart rather than at apply time. Roll
  every config-parsing component when the schema changes, not only the ones
  whose code changed, and apply the ConfigMap with or after the images.
- **Settled: decoding stays strict.** Recorded as ADR-0006. Tolerating unknown
  fields would trade a loud failure for a silent one - an operator who writes
  `suricta: true` would get a component that starts cleanly and does something
  other than what they configured, and for a system whose output is evidence a
  sensor quietly running an unchosen setting is worse than one that refuses to
  start. The rolling-upgrade hazard is answered operationally instead: a config
  schema change requires rolling every component that parses the config, not
  only the ones whose code changed, and the ConfigMap is applied with or after
  the images. The ADR is explicit that nothing enforces that ordering
  automatically, and why a static check cannot.

- **A killed failure-injection run leaves the fault in place.** `t.Cleanup`
  covers a failed assertion, a panic and a timeout; it does not cover SIGKILL,
  which runs no deferred code. For these specs what is left behind is not a
  stray object but an injected fault - a NetworkPolicy severing the worker's
  egress, or a Deployment scaled to zero - and an installation can sit in that
  state indefinitely looking like a component that failed on its own. Two
  mitigations: the injectors now clear a leftover of their own before applying,
  so a subsequent run self-heals rather than reporting the previous run's
  damage as its own finding; and `hack/e2e-cleanup.sh` is the one command for a
  human after a killed run.
- **T125 is partially executed.** The gateway injection passed and proved its
  property - a capture requested during a gateway outage still reached
  Completed, so losing the read path does not lose the evidence. The trigger
  source and controller injections are written, compile, gate correctly and are
  not yet executed: the development machine was under memory pressure from
  unrelated work and the harness watchdog killed the runs twice. The controller
  injection in particular should not be run unattended on a shared cluster,
  because a kill mid-run leaves the installation refusing every mutation until
  somebody notices.

- **T129's first real run showed three of five jobs did not work.** Opening the
  PR was the only way to find out - the Security workflow triggers on
  `pull_request` and `push: main`, so a branch push never exercises it, and the
  task had been marked done on the strength of five jobs nobody had run. All
  three failures were environmental rather than findings: `gitleaks-action`
  refuses to run for a GitHub organisation without a paid licence,
  `dependency-review-action` needs the repository's dependency graph enabled,
  and `trivy-action`'s install script exited 1 after resolving the version it
  wanted. Every scanner is now a pinned, checksum-verified binary installed in
  the job, which is how `hack/tools.mk` already treats every other tool; the
  only remaining third-party actions are `actions/checkout` and
  `actions/setup-go`.
- **The secret scan found four things and all four were false positives**, which
  is the answer worth having recorded: two hand-built JWTs whose signature
  segments decode to the literal words "signature-secret-part" and
  "sig-analyst-secret", and two GPG signing-key fingerprints, which are public
  by design - a fingerprint is how a reader verifies a release signature.
- **The first allowlist for those blinded the scanner, and a mutation check
  caught it.** Allowlisting by *path* says "no credential in this file will ever
  be real", which is a promise nobody can keep: with the two test files
  path-allowlisted, a planted AWS key and a planted `api_key` both went
  undetected. The allowlist is scoped to the exact synthetic *values* now, so
  any other secret in the same files is still found - verified by planting a
  non-canonical AWS key and a GitHub PAT, both of which are caught.
  (Note for anyone repeating this: `AKIAIOSFODNN7EXAMPLE` is AWS's own
  documentation key and gitleaks allowlists it internally, so it is useless as
  a mutation.)

- **T127 was mostly already built, and unrun.** `TestAnExpiredCaptureIsDeletedAndRefused`
  covers the exact deadline, deletion from the bucket, the HTTP 410 refusal,
  preserved metadata and the ledger record; `TestShorteningRetentionMovesTheDeadlineFromCompletion`
  covers a shortened deadline being measured from completion rather than from
  now. The latter passes today, in 24s.
- **The gap was the join between them.** The shortening spec asserts the
  deadline *field* moves and stops there. Nothing asserted that a shortened
  deadline is then enforced - a controller that recorded the new date and swept
  on the old one would satisfy every existing assertion while keeping evidence
  a day longer than the retention admin asked for, which is a retention policy
  that silently does not hold. `test/e2e/retention_test.go` closes that, and
  doing so is also the only honest way to validate a 24h period without
  waiting 24h: the CRD floor is 1h and there is no clock hook, so the
  acceleration is a real operator action rather than a test seam.
- **"Upload protection" is deliberately left at integration level.**
  `TestRetentionLeavesAnUnfinishedCaptureAlone` asserts it deterministically. A
  cluster version would have to catch the sweeper inside an upload window
  measured in seconds, and a flaky spec asserting a safety property is worse
  than a reliable one somewhere else.
- **Five e2e specs skip on an unmet *local* prerequisite**, and skips print
  nothing without `-v`. `requireReachableObjectStore` needs
  `minio.trawl-system.svc.cluster.local` to resolve to loopback in `/etc/hosts`
  so a presigned URL can be followed - the signature covers host and port, so
  no other port will do. Without it, the download path, the controller-restart
  spec, the audit-outage spec and both expiry specs skip and the run reports
  success. Same family as the `kustomize` silent skip, but not fixable by a
  dependency: it is a host-level change the person running the suite has to
  make.

- **T127 executed. Both expiry specs passed, each after a real 63-minute
  wait**, and both had never been run before. Expiry landed 9s and <1s after
  their deadlines against a 3-minute allowance, and neither deadline moved
  while being waited on. Evidence in `test/e2e/results/retention.md`, taken
  from the write-once ledger rather than from the CaptureJobs, which the specs
  clean up.
- **Reading that ledger found a defect.** A second intent/outcome pair was
  written eight seconds after a scheduled expiry saying "the capture was
  deleted before its retention deadline". Normal expiry deletes the bytes and
  deliberately keeps the artifact *record*, so `status.artifact` is still set
  on an Expired capture and deleting the CaptureJob re-enters the finalizer's
  expiry path with a message that assumes it got there first. Operationally
  minor - a redundant idempotent delete - but the ledger is write-once and is
  the record of last resort for what happened to collected traffic, and an
  auditor reading it would see a scheduled expiry as an early purge. That is
  the accusation the ledger exists to answer. Message now branches on the
  phase; `TestDeletingAnAlreadyExpiredCaptureDoesNotClaimAnEarlyPurge` is the
  regression test, mutation-checked.

- **T131 found that nine of the quickstart's commands did not exist.** The
  validation document had drifted from the Makefile: `verify-manifests`,
  `query-observations`, `verify-correlation`, `e2e-malformed-observation`,
  `e2e-correlation-timing`, `e2e-traffic`, `e2e-trigger-matrix`,
  `verify-execution-uniqueness` and `test-e2e` were all absent. The capability
  existed under other names in every case but one, so the fix is the document;
  `test-investigation` and `test-acceptance` now take `ARGS` so a section can
  narrow a run without a target of its own. The exception is the performance
  section, which needs T126's `reference_load_test.go` - it is marked
  unexecutable rather than given a command that would fail, because a release
  checklist must not infer those figures from the shorter runs.
- **SC-005 ran: 10 of 10 attempts under budget, p50 2.169s against 3m.**
  Evidence in `test/e2e/results/quickstart.md`.
- **SC-005 is recorded as ten attempts because that is the sample the release
  criterion now names, and the fixture limit remains explicit.** Five fixtures
  carry a Community ID and exactly one of those also carries a Suricata alert,
  so one session supports a signature-to-protocol round trip. The ten supported
  attempts start from each end of those five flows—the same property
  `TestExactPivotReachesTheWholeFlowFromEitherEnd` asserts, resting on Community
  ID being symmetric. This is not relabelled as ten complete
  signature-to-protocol session pairs.
- **The pattern across this phase is worth naming: a gate nobody has executed
  is not a gate.** Six contract tests silently skipping in CI, a pinned
  `govulncheck` nothing invoked, three security jobs that failed the first time
  they ran, two expiry specs never executed, and a validation quickstart whose
  commands did not resolve - all of them looked like coverage and asserted
  nothing.

- **T125 complete: all three new injections pass.** Gateway, trigger source and
  controller, alongside the two pre-existing storage and audit specs it
  deliberately does not duplicate. Evidence in
  `test/e2e/results/failure-isolation.md`.
- **The trigger-source injection took five runs and four failures were the
  test, not the product.** Each is written into the spec because each looked
  like a defect: adding a deny policy does nothing because Kubernetes
  NetworkPolicy is additive-allow; an established keep-alive connection
  survives a policy change; severing *all* egress kills the worker instead of
  blinding it; and the restore failed applying a backup saved as raw
  `kubectl get -o json`, leaving the worker isolated on a live cluster until it
  was put back by hand. **A fault-injection test that does not inject is
  indistinguishable from a system that tolerates the fault** - three of those
  four runs passed their own assertions about having applied the injection.
- **Product finding, carried to readiness rather than fixed: a dead event
  worker leaves every policy reporting `Armed`.** The status tracker treats "no
  word about the source" as disconnected on the principle that absence of
  evidence is not evidence of coverage - but that logic runs inside the worker,
  so a worker that is down cannot apply it, and nothing else writes policy
  status. Ordinary Kubernetes behaviour for a stopped controller; not ordinary
  for a field that is a detection-coverage claim an investigation later relies
  on.

- **T126 ran. SC-002 passed 20/20 (p50 17.6s, p95 39.6s against 2m). SC-003
  passed at the rate that installation produced: 260,034 packets, 29 drops,
  0.0112% over a full hour, tap Active throughout, and roughly 72 packets/s.**
  The run predates the observed-byte counter, so it does not invent a bit rate
  or relabel ambient traffic as 100 Mb/s. The amended criterion asks whether the
  capture boundary held at the measured produced rate, which this evidence
  answers.
- **T132's two release decisions are accepted.** SC-003 uses the installation's
  honestly reported produced rate, and SC-005 uses the ten attempts its fixture
  set supports. Seven known gaps are carried explicitly, each with the decision
  it needs. A checklist that inferred any of it from an adjacent run would be
  the same failure as the gates this phase found unexecuted, in a nicer font.

### Closing readiness gap 6: the PortMirror admission webhook

Not a numbered task. T132 recorded seven gaps and this was the only one that was
a defect rather than a decision, so it was fixed rather than carried.

- **`PortMirror` was the one kind the CRD contract was untrue of.**
  `contracts/crd-api.md` opens by saying all resources "are accepted only in the
  installation-configured system namespace" and that "the validating webhook
  rejects off-namespace resources". PortMirror had no webhook, and the
  controller declining to reconcile an off-namespace mirror was standing in for
  one. The difference is not academic: the API server accepted the object, so it
  existed, and `kubectl get portmirror -A` showed a mirror that read as
  configuration in effect on a switch.

- **No mutating counterpart, deliberately.** The type's only default,
  `direction: Both`, is structural, so the API server applies it while decoding.
  A mutating webhook would have had nothing to do and would have added a second
  `failurePolicy: Fail` call to every create.

- **`provider` and `deviceRef` are immutable, and that is the find.** Revert
  resolves `deviceRef` at deletion time, so repointing a live PortMirror from
  switch A to switch B configures B and makes the eventual delete revert B,
  while A goes on copying traffic to a port with nothing in the cluster
  recording that it does. That is exactly the leftover the finalizer exists to
  prevent, reachable by `kubectl edit` rather than by a crash, and on hardware
  where no `kubectl get` will ever show it.

- **Three defects found while writing it**, each small and each a status lie:
  the reconciler never re-validated a stored spec before configuring hardware,
  though the NetworkTap and CaptureJob reconcilers both do; an off-namespace
  mirror reported `Accepted` as the reason it had been refused; and any failure
  before the device was contacted - invalid spec, wrong namespace, missing
  credential - reported `DeviceReachable=False` about a device that had never
  been asked anything, which sends an operator to the switch for a problem in
  the spec.

- **A device-contention gap is recorded, not fixed.** Nothing stops two
  PortMirrors naming the same `deviceRef`. A RouterOS switch has one global
  `mirror-target`, so each would observe the other's configuration as drift and
  rewrite it every resync - flapping indefinitely, filling the device's own log
  and the audit ledger. The NetworkTap probe-port conflict is the precedent for
  how this should be handled: the controller detects the overlap and reports
  `ProbePortConflict` on whichever resource has the younger claim, rather than
  admission rejecting it. Doing the same here needs a conflict reason and an
  incumbent rule, which is its own change.

**Checkpoint**: All required checks pass, no critical security finding or
unresolved source gap is hidden, and the release has reproducible evidence for the
active specification.

---

## Dependencies & Execution Order

### Phase dependencies

```text
Phase 1 Setup
      │
      ▼
Phase 2 Foundation
      │
      ▼
Phase 3 US1 (MVP)
      ├───────────────┐
      ▼               ▼
Phase 4 US2       Phase 5 US3
      └───────┬───────┘
              ▼
         Phase 6 US4
              │
              ▼
       Phase 7 Release Gates
```

- **Phase 1**: Starts immediately.
- **Phase 2**: Requires Phase 1 and blocks all user stories.
- **US1 / Phase 3**: Requires Phase 2 and is the first deployable MVP.
- **US2 / Phase 4**: Requires US1 for a live source, but its schema/query/dashboard
  work can be developed against fixtures after Phase 2.
- **US3 / Phase 5**: Requires US1 for a live target, but its API/runner/storage/
  gateway work can proceed in parallel with US2 after Phase 2.
- **US4 / Phase 6**: Requires US1 observations/targets, US2 event-source clients,
  and US3 CaptureJob execution/storage.
- **Phase 7**: Requires every story included in the release.

### Within each user story

1. Add tests and confirm they fail for the absent behavior.
2. Add API types and admission rules before controllers/workers consume them.
3. Implement pure parsing, matching, state, and storage logic before orchestration.
4. Implement reconcilers/process wiring and generated manifests.
5. Run contract/integration tests before the end-to-end checkpoint.
6. Do not begin the next dependent release phase until the checkpoint passes.

### User-story requirement coverage

| Story | Requirements | Primary entities/contracts |
|---|---|---|
| US1 | FR-001–FR-012, FR-016, FR-037–FR-045 | NetworkTap, target status, normalized observations, analyzer content |
| US2 | FR-009–FR-016 | SecurityEvent, ProtocolObservation, ClusterFlowEvent, telemetry/dashboard contract |
| US3 | FR-017–FR-025, FR-035–FR-040 | CaptureJob, CaptureArtifact, artifact OpenAPI, audit |
| US4 | FR-026–FR-034, FR-035–FR-040 | CapturePolicy, TriggerSnapshot, PolicyDecision, CaptureJob |

---

## Parallel Opportunities

- Setup ADR and lint tasks T004–T008 and T009a can run concurrently after T001–T003.
- Foundational test tasks T010–T013, T020a, and infrastructure tasks T020, T023,
  T024, and T025a use separate files and can run concurrently.
- US1 normalization, sensor, content, reconciliation, and analyzer-image work
  exposes twelve `[P]` tasks after the story tests are established.
- After US1, US2 and US3 can be staffed concurrently; together they contain nineteen
  `[P]` tasks in distinct investigation and capture subsystems.
- US4 source/matcher/cursor work can run concurrently after its API contract is
  established.
- Cross-cutting audit, security, compatibility, and documentation gates T120–T124
  can run concurrently before the sequential failure/load/release checks.

### Parallel example: User Story 1

```text
T031 Suricata normalization tests  ─▶ T038 Suricata normalizer
T032 Zeek normalization tests      ─▶ T039 Zeek normalizer
T029 workload golden tests         ─▶ T046 Suricata image
                                  └▶ T047 Zeek image
T033a content init tests           ─▶ T047a content fetch/merge
                                  └▶ T047b custom content packaging
```

### Parallel example: User Story 2

```text
T052 correlation tests ─▶ T057 correlation classifier ─▶ T065 investigation dashboard
T054 Hubble tests      ─▶ T059/T060 Hubble client      ─▶ T064 overview dashboard
T051 Hubble schema tests ─▶ T063 Hubble schema extension ─▶ T066 protocol dashboard
```

### Parallel example: User Story 3

```text
T070 runner tests  ─▶ T078/T079/T080 capture runner
T071 storage tests ─▶ T083 storage client
T073 gateway tests ─▶ T088/T089/T090 authorization gateway
T072 controller tests + completed runner/storage ─▶ T084/T085 reconciler
```

### Parallel example: User Story 4

```text
T097 Suricata tests ─▶ T106 matcher ─┐
T098 Hubble tests   ─▶ T107 matcher ─┼─▶ T113 policy engine
T101 cursor tests   ─▶ T110/T111 ────┤
T099/T100 limits    ─▶ T108/T109 ────┘
```

---

## Implementation Strategy

### MVP first: User Story 1

1. Complete T001–T009 including T009a (Setup).
2. Complete T010–T027 including T020a and T025a (Foundation).
3. Complete T028–T050 including T033a, T047a, and T047b (US1).
4. Stop and run the US1 independent test; deploy/demo only if it passes.

This produces the smallest useful Trawl release: declarative passive monitoring,
truthful health, and structured Suricata/Zeek evidence.

### Incremental delivery

1. **MVP**: Setup + Foundation + US1.
2. **Investigation increment**: US2 dashboards, search, correlation, and Hubble
   context; validate independently.
3. **Forensics increment**: US3 manual capture, storage, retention, and authorized
   download; validate independently and in parallel with US2 where possible.
4. **Automation increment**: US4 policies and event-driven capture using the proven
   event and capture paths.
5. **Release candidate**: Phase 7 security, failure, performance, retention,
   quickstart, and readiness gates.

### Commit discipline

- Commit tests with the smallest implementation that makes them pass.
- Keep generated artifacts in the same commit as their source markers/config.
- Do not combine API contract changes with unrelated analyzer/dashboard work.
- At every checkpoint, preserve a runnable vertical slice and a documented rollback.

## Notes

- `[P]` means the task is file- and dependency-independent within its ready phase;
  it does not waive required reviews or tests.
- No task implements pod injection, TLS decryption, dynamic rule/script management,
  schedule/anomaly/generic-flow triggers, inline enforcement, or packet replay.
- Capture files and credentials are never committed as fixtures; tests generate
  synthetic packets and ephemeral secrets.
- `tasks.md` is implementation work ordering, not permission to deploy to a
  production cluster or purge retained evidence.
