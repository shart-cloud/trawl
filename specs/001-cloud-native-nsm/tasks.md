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
- [ ] T034 [US1] Add a failing cluster acceptance test for active, updated, deleted, durable mutation audit, audit-ledger outage fail-closed behavior, missing-interface, disappearing-target, analyzer-failure, and recovery scenarios in `test/e2e/networktap_test.go`

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
- [ ] T050 [US1] Implement synthetic baseline/duplicate traffic fixtures and make the NetworkTap acceptance test prove schema conformance, duplicate visibility, verified durable mutation audit, audit-outage fail-closed control with unaffected monitoring, and first structured observation within 15 minutes without host installation or packet-path mutation in `test/e2e/traffic/baseline.go` and `test/e2e/networktap_test.go`

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

- [ ] T051 [P] [US2] Extend the US1 Draft 2020-12 contract tests with Hubble observations, every supported subtype, and forbidden raw/sensitive fields in `test/contract/observation_schema_test.go`
- [ ] T052 [P] [US2] Add failing exact, direction-normalized, clock-skew, ambiguous, and no-match correlation tests in `internal/observation/correlation_test.go`
- [ ] T053 [P] [US2] Add failing real-Loki tests for time, tap, target, type, severity, rule, Community ID, endpoint, and fallback queries with ingestion-latency measurement in `test/integration/loki_queries_test.go`
- [ ] T054 [P] [US2] Add failing Hubble TLS/GetFlows/reconnect/lost-event/allowed/denied normalization tests against a gRPC fixture in `test/integration/hubble_observation_test.go`
- [ ] T055 [P] [US2] Add failing dashboard contract tests for bounded labels, required panels, exact/approximate badges, safe links, query ranges, and supported schema fields in `test/contract/grafana_dashboards_test.go`
- [ ] T056 [US2] Add a failing end-to-end investigation test covering the observation-only overview, exact pivot in both directions, fallback pivot, every protocol subtype, Hubble context, and 30-second searchability in `test/e2e/investigation_test.go`

### Implementation for User Story 2

- [ ] T057 [US2] Implement exact Community ID and direction-normalized time/attribute correlation classification with explicit ambiguity results in `internal/observation/correlation.go`
- [ ] T058 [US2] Define reviewed LogQL query templates for overview, signature detail, exact pivot, approximate pivot, protocol filters, and Hubble timelines in `config/grafana/queries/trawl.logql`
- [ ] T059 [US2] Implement a TLS-authenticated Hubble Observer GetFlows client with bounded filters, reconnect backoff, event-time watermarks, and lost-event signals in `internal/events/hubble/client.go`
- [ ] T060 [US2] Normalize Hubble endpoints, namespaces/workloads, verdicts, drop reasons, observation points, timestamps, and safe flow fields into cluster-flow observations in `internal/events/hubble/normalize.go`
- [ ] T061 [US2] Wire leader election, Hubble observation streaming, normalized stdout output, probes, metrics, and graceful reconnect in `cmd/event-worker/main.go`
- [ ] T062 [US2] Deploy the observation-mode event worker with Hubble CA/client mounts, read-only Loki configuration, Restricted security context, RBAC, and egress NetworkPolicy in `config/manager/event-worker.yaml` and `config/networkpolicy/event-worker.yaml`
- [ ] T063 [US2] Extend embedded normative-schema validation to Hubble records and keep Alloy structured-metadata mappings synchronized in `internal/observation/schema.go` and `config/alloy/trawl-observations.alloy`
- [ ] T064 [P] [US2] Provision the independently complete observation-only Trawl Overview dashboard for observation volume, signatures, protocols, Hubble verdicts, tap health, and suspected-duplicate indicators in `config/grafana/dashboards/trawl-overview.json`
- [ ] T065 [P] [US2] Provision the Alert Investigation dashboard with exact Community ID and visibly approximate fallback pivots in `config/grafana/dashboards/alert-investigation.json`
- [ ] T066 [P] [US2] Provision the Protocol Analysis dashboard for connection, DNS, HTTP, TLS, certificate, file, notice, and weird records in `config/grafana/dashboards/protocol-analysis.json`
- [ ] T067 [US2] Add deterministic investigation fixtures and make schema, Loki, Hubble, dashboard, and end-to-end investigation tests pass in `test/fixtures/observations/` and `test/e2e/investigation_test.go`

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

- [ ] T068 [P] [US3] Add failing CaptureJob API tests for configured-namespace enforcement, defaults, bounds, manual/policy caller unions, execution immutability, authorized retention-only updates, durable-audit failure, and non-resurrection in `api/v1alpha1/capturejob_types_test.go`
- [ ] T069 [P] [US3] Add failing lifecycle tests for every legal/illegal transition, observed facts, zero-packet completion, failure reasons, downloadability, and expiry in `internal/capture/state_test.go`
- [ ] T070 [P] [US3] Add failing dumpcap-runner tests for BPF dry-run before socket open, duration/size first-bound stop, snaplen, cancellation, sanitized failures, and <=1MiB overshoot in `internal/capture/runner_test.go`
- [ ] T071 [P] [US3] Add failing real-MinIO tests for stable object keys, conditional upload, manifest/checksum verification, missing/mismatch handling, presign ceiling, and idempotent delete in `test/integration/artifact_storage_test.go`
- [ ] T072 [P] [US3] Add failing envtest cases for target resolution, stable Job/reporter creation, reporter field ownership and progress patches, existing Job/object adoption, storage failure, audit failure, controller restart, and one terminal result in `internal/controller/capturejob_controller_test.go`
- [ ] T073 [P] [US3] Add failing OpenAPI/handler/CLI tests for TokenReview audience, `capturejobs/download` SubjectAccessReview, enumeration resistance, lifecycle responses, no-store headers, short redirects, and durable audit acknowledgement before redirect in `internal/gateway/handler_test.go` and `internal/gateway/client_test.go`
- [ ] T074 [P] [US3] Add failing fake-clock tests for exact deadline denial, authorized shortening/extension, upload protection, hourly deletion retry, 24-hour bound, and metadata preservation in `internal/controller/retention_test.go`
- [ ] T075 [US3] Add a failing end-to-end manual capture matrix for reporter-driven progress, successful CLI download, invalid-filter, inactive-source, unavailable-target, zero-packet, full-storage, audit outage, restart, unauthorized-download, and expiry cases in `test/e2e/manual_capture_test.go`

### Implementation for User Story 3

- [ ] T076 [US3] Define CaptureJob execution, policy snapshot, artifact, failure, phase, condition, print-column, status-subresource, and validation types in `api/v1alpha1/capturejob_types.go`
- [ ] T077 [US3] Implement CaptureJob defaulting and validation for configured-namespace enforcement, caller identity, manual/policy fields, execution immutability, bounded pre-expiry retention changes, controlled delete policy, and durable audit acknowledgement in `internal/admission/capturejob_webhook.go`
- [ ] T078 [P] [US3] Implement duration/size/snaplen parsing, supported placeholder-free manual BPF validation requests, and safe runner arguments in `internal/capture/bounds.go` and `internal/capture/filter.go`
- [ ] T079 [P] [US3] Implement the artifact manifest, stable namespace/UID object key, SHA-256 calculation, packet-count parsing, and verification comparison in `internal/capture/manifest.go`
- [ ] T080 [US3] Implement the capture runner sequence plus atomic versioned runner/reporter protocol for target/interface checks, BPF dry-run, post-socket `CaptureStarted`, bounded dumpcap execution, pre-upload `CaptureEnded`, compact terminal result, conditional upload, and sanitized exits in `internal/capture/runner.go` and `internal/capture/reporter.go`
- [ ] T081 [US3] Wire capture and unprivileged reporter modes, bounded shared-file validation, field-owned status patches, signal handling, metrics, and exit codes in `cmd/capture-runner/main.go`; mount no Kubernetes API credentials in capture mode
- [ ] T082 [US3] Build the digest-pinned capture-runner image with reviewed dumpcap/libpcap, non-root defaults, writable bounded work volume, and source checksums in `images/capture-runner/Containerfile` and `images/capture-runner/SOURCES.lock`
- [ ] T083 [P] [US3] Extend the foundational private MinIO/S3 client with artifact manifest metadata, presign, idempotent delete, expiry verification, timeouts, TLS, and safe errors in `internal/storage/s3.go`
- [ ] T084 [US3] Implement deterministic node-pinned Kubernetes Job rendering with direct interface access, ephemeral-storage bounds, explicit capture-only capabilities, shared progress `emptyDir`, unprivileged reporter sidecar, capture-container token suppression, reporter projected token, resource-name-scoped status Role, and owner reference in `internal/controller/capturejob_workload.go`
- [ ] T085 [US3] Implement CaptureJob reconciliation, active tap/target resolution, Job observation/adoption, reporter-owned progress consumption, S3 HEAD verification, durable audit before lifecycle commits, conditions, retries, and terminal convergence in `internal/controller/capturejob_controller.go`
- [ ] T086 [US3] Implement the guarded lifecycle transition and artifact-downloadability logic used by the reconciler and gateway in `internal/capture/state.go`
- [ ] T087 [US3] Implement deadline calculation, immediate download denial, upload-aware hourly deletion, object absence verification, retry conditions, and `Expired` transition in `internal/controller/retention.go`
- [ ] T088 [P] [US3] Implement audience-bound Kubernetes TokenReview and resource-name/subresource SubjectAccessReview clients with deny-by-default caching in `internal/authz/kubernetes.go`
- [ ] T089 [US3] Implement the artifact gateway download handler and CLI client library with live CaptureJob/object verification, five-minute/deadline presign calculation, enumeration-safe errors, no-store responses, rate limits, and durable audit acknowledgement before redirect in `internal/gateway/handler.go` and `internal/gateway/client.go`
- [ ] T090 [US3] Wire TLS serving, auth/audit/storage clients, probes, metrics, request IDs, graceful shutdown, and log redaction in `cmd/artifact-gateway/main.go`, and implement bearer-producing kubeconfig-exec or token-stdin download without credential arguments in `cmd/trawlctl/main.go`
- [ ] T091 [US3] Deploy the gateway and capture reporter permissions with explicit ServiceAccounts, resource-name-scoped reporter status Roles, `capturejobs/download` roles, TokenReview/SubjectAccessReview access, artifact-only storage Secret mounts, audit-sink mTLS, TLS, and NetworkPolicies in `config/gateway/deployment.yaml` and `config/rbac/artifact-gateway-role.yaml`
- [ ] T092 [US3] Generate and review the CaptureJob CRD/cluster-wide namespace-rejecting webhook/namespaced RBAC, manual analyst and retention-admin roles, successful/invalid samples, and capture image digest patch in `config/crd/bases/trawl.cloud_capturejobs.yaml`, `config/rbac/capturejob-roles.yaml`, and `config/samples/`
- [ ] T093 [US3] Extend Trawl Overview with recent capture activity and add execution lifecycle, artifact health, retention, storage usage, and non-secret copyable `trawlctl` commands to `config/grafana/dashboards/trawl-overview.json` and `config/grafana/dashboards/capture-management.json`
- [ ] T094 [US3] Complete real dumpcap/reporter/MinIO/audit-ledger/gateway/CLI integration fixtures, including checksum comparison and secret-leak assertions, in `test/integration/manual_capture_test.go`
- [ ] T095 [US3] Make the full manual capture/CLI matrix pass and record sanitized lifecycle and timing evidence in `test/e2e/manual_capture_test.go` and `test/e2e/results/manual-capture.md`

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

- [ ] T096 [P] [US4] Add failing CapturePolicy API tests for configured-namespace enforcement, closed trigger unions, severity/reason filters, thresholds, typed placeholders, capture/rate/retention bounds, defaults, armed state, CRUD transitions, delete behavior, and durable-audit failure in `api/v1alpha1/capturepolicy_types_test.go`
- [ ] T097 [P] [US4] Add failing pure Suricata match and safe typed-template rendering tests for severity, rule, category, flow fields, non-match reasons, and final BPF validation in `internal/policy/suricata_test.go`
- [ ] T098 [P] [US4] Add failing Hubble drop match and rolling-threshold tests for reason, namespace, count/window, clock skew, replay, and source gaps in `internal/policy/hubble_test.go`
- [ ] T099 [P] [US4] Add failing canonical direction-neutral flow key, cooldown bucket, deterministic name, same-policy, and cross-policy duplicate tests in `internal/policy/dedup_test.go`
- [ ] T100 [P] [US4] Add failing persisted hourly-limit, active-count, policy-generation, restart-rebuild, and clock-boundary tests in `internal/policy/rate_limit_test.go`
- [ ] T101 [P] [US4] Add failing Loki overlap cursor tests for timestamp ties, fingerprints, safe replay, cursor loss, malformed alerts, query failure, and lag/gap reporting in `internal/events/loki/cursor_test.go`
- [ ] T102 [P] [US4] Add failing event-worker integration tests for concurrent policies, durable audit before create, audit outage, create-or-get races, leader handoff, CaptureJob snapshots, status counters, policy deletion, and independent failures in `test/integration/event_worker_test.go`
- [ ] T103 [US4] Add a failing end-to-end automatic trigger matrix for signature/drop matches, thresholds, non-matches, duplicates, cross-policy collapse, hourly limits, reconnect gaps, and restarts in `test/e2e/automatic_capture_test.go`

### Implementation for User Story 4

- [ ] T104 [US4] Define CapturePolicy trigger/capture/rate spec, runtime counters, phases, conditions, print columns, status subresource, defaults, and structural/CEL validation markers in `api/v1alpha1/capturepolicy_types.go`
- [ ] T105 [US4] Implement CapturePolicy validation/defaulting for configured-namespace enforcement, same-namespace tap references, trigger unions, typed placeholders, bounds, retention ceiling, operator identity, and durable audit acknowledgement in `internal/admission/capturepolicy_webhook.go`
- [ ] T106 [P] [US4] Implement deterministic Suricata signature matching, decision reasons, safe trigger snapshots, and typed filter rendering in `internal/policy/suricata.go`
- [ ] T107 [P] [US4] Implement denied Hubble flow matching and bounded rolling threshold windows with replay-aware event identity in `internal/policy/hubble.go`
- [ ] T108 [US4] Implement canonical direction-neutral five-tuple keys, cooldown buckets, deterministic CaptureJob names, and persisted create-or-get deduplication in `internal/policy/dedup.go`
- [ ] T109 [US4] Implement hourly/active counts rebuilt from CaptureJobs, cooldown decisions, and policy-generation-aware status accounting in `internal/policy/rate_limit.go`
- [ ] T110 [P] [US4] Implement atomic ConfigMap cursor persistence, overlap queries, fingerprint replay suppression, lag, and known-gap state in `internal/events/loki/cursor.go`
- [ ] T111 [P] [US4] Implement bounded Loki range queries and normalized Suricata alert decoding without raw event logging in `internal/events/loki/alerts.go`
- [ ] T112 [P] [US4] Extend the Hubble client with threshold-window replay, reconnect watermarks, and explicit unrecoverable loss reporting in `internal/events/hubble/client.go`
- [ ] T113 [US4] Implement policy indexing, independent evaluation, target resolution, snapshot/bounds resolution, durable audit acknowledgement, CaptureJob construction, and decision emission in `internal/policy/engine.go`
- [ ] T114 [US4] Implement CapturePolicy status/condition reconciliation, monotonic decision counters, last execution/suppression references, source health, and retry isolation in `internal/policy/status.go`
- [ ] T115 [US4] Wire Loki alert polling, Hubble drop evaluation, policy cache watches, mTLS audit client, leader election, persistent cursors, metrics, and graceful handoff into `cmd/event-worker/main.go`
- [ ] T116 [US4] Grant the event worker only read/watch NetworkTap/CapturePolicy/CaptureJob, create CaptureJob, patch CapturePolicy status, cursor ConfigMap permissions, and egress to the audit sink in `config/rbac/event-worker-role.yaml` and update `config/manager/event-worker.yaml`
- [ ] T117 [US4] Generate and review the CapturePolicy CRD/cluster-wide namespace-rejecting webhook/namespaced RBAC plus armed/disarmed Suricata and Hubble samples with no deferred trigger types in `config/crd/bases/trawl.cloud_capturepolicies.yaml` and `config/samples/`
- [ ] T118 [US4] Add policy phase, decision counters, source gaps, active captures, cooldown/rate state, and suppression references to `config/grafana/dashboards/capture-management.json`
- [ ] T119 [US4] Make unit, integration, restart, and end-to-end automatic trigger matrices pass and record sanitized count evidence in `test/e2e/automatic_capture_test.go` and `test/e2e/results/automatic-capture.md`

**Checkpoint**: All four user stories are functional. Automatic capture reuses the
same bounded, authorized execution path proven by US3.

---

## Phase 7: Polish & Cross-Cutting Release Gates

**Purpose**: Verify security, failure isolation, compatibility, performance,
operations, supply chain, and the complete quickstart before release.

- [ ] T120 [P] Add audit completeness and durability tests for every required mutation, policy decision, transition, download decision, retention change, and expiry action, including intent/outcome pairs, idempotent retry, conflicting keys, MinIO/Loki outages, cursor overlap, duplicate-copy collapse, replay, bounded ledger retention, and fail-closed user actions in `test/integration/audit_test.go`
- [ ] T121 [P] Add static security tests that reject off-namespace Trawl resources, wildcard RBAC, unexpected host namespaces/capabilities, service-account token leakage, floating tags, hostPath, public buckets, browser download links, and secret-bearing telemetry in `test/contract/security_manifests_test.go`
- [ ] T122 [P] Add stored `v1alpha1` fixture round-trip, additive-defaulting, older-controller rollback, CRD storage-version, and uninstall-preservation tests in `test/integration/upgrade_rollback_test.go`
- [ ] T123 [P] Document tap/analyzer health, packet loss/duplication, malformed records, trigger gaps, audit-ledger/replay backlog, storage/retention failure, and restart recovery procedures in `docs/src/content/docs/operations/runbook.md`
- [ ] T124 [P] Document privileges, RBAC roles, BPF/filter trust boundary, evidence classification, local download handling, audit review, and purge approval in `docs/src/content/docs/security/evidence-handling.md`
- [ ] T125 Run analyzer, controller, trigger, Loki, Hubble, MinIO, audit sink/replay, gateway, and retention failure injection while asserting durable audit or fail-closed user actions and passive unaffected monitoring in `test/e2e/failure_isolation_test.go`
- [ ] T126 Run the 100 Mb/s 60-minute reference test plus at least 20 timed valid tap create/update trials and enforce first-observation <=15m, 95% reconciliation <=2m, packet-loss, ingestion-latency, capture-start/store, bound-overshoot, and trigger-count thresholds in `test/e2e/reference_load_test.go`
- [ ] T127 Run exact deadline-denial and accelerated 24-hour deletion validation with upload protection and preserved metadata in `test/e2e/retention_test.go`
- [ ] T128 Generate SBOMs, provenance, vulnerability results, upstream source verification, rule/script hashes, and immutable image digests in `dist/supply-chain/manifest.json`
- [ ] T129 Configure release-blocking Go, container, manifest, dependency, and secret scanning with reviewed suppressions and expiry dates in `.github/workflows/security.yml` and `security/suppressions.yaml`
- [ ] T130 Regenerate CRDs, RBAC, webhooks, install bundle, examples, observation schema embedding, and dashboards and prove a clean drift check in `dist/install.yaml` and `test/contract/generated_artifacts_test.go`
- [ ] T131 Execute every command and expected outcome plus the defined 20-attempt exact-correlation timing protocol in `specs/001-cloud-native-nsm/quickstart.md` on the representative cluster and save only sanitized durations/counts in `test/e2e/results/quickstart.md`
- [ ] T132 Complete the constitutional, security, operational, and measurable-outcome release checklist with links to passing evidence in `docs/release/readiness.md`

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
