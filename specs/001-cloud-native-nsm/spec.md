# Feature Specification: Trawl MVP

**Feature Branch**: `001-cloud-native-nsm`

**Created**: 2026-08-29

**Status**: Draft

**Input**: User description: "Translate the high-level Trawl architecture in the repository's root `spec.md` into a Spec Kit feature specification."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Activate Passive Network Monitoring (Priority: P1)

As a cluster operator, I can declare a physical-mirror or node-level traffic source, select the required forms of analysis, and see whether monitoring is healthy so that network activity is analyzed without changing the immutable host operating system.

**Why this priority**: A healthy, declaratively managed traffic source is the foundation for every detection, investigation, and capture workflow. It is the smallest useful release because it delivers continuous network visibility on its own.

**Independent Test**: Configure one traffic source in a test cluster, generate known DNS, HTTP, and TLS traffic across it, and verify that the source becomes active and produces both signature-based security events and protocol metadata.

**Acceptance Scenarios**:

1. **Given** an eligible sensor target and a valid passive traffic-source declaration, **When** the operator applies the declaration, **Then** monitoring starts on the selected target and the source reports an active state, matched targets, and recent packet activity.
2. **Given** an active traffic source, **When** known test traffic crosses that source, **Then** the enabled analysis modes produce structured observations attributed to the source and target where the traffic was observed.
3. **Given** a declaration that references a missing interface or matches no eligible target, **When** the system evaluates it, **Then** it does not report the source as active and exposes an actionable degraded or error condition.
4. **Given** an active traffic source, **When** the operator changes its enabled analysis modes or operating limits, **Then** the system converges to the new desired state and reports the outcome without requiring host access.
5. **Given** an active traffic source, **When** the operator deletes it, **Then** monitoring for that source stops and only resources owned by that source are removed.

---

### User Story 2 - Investigate Security Activity (Priority: P2)

As a security learner or analyst, I can review detections, connections, DNS, web, TLS, file, and cluster-flow activity together and pivot between related records so that I can reconstruct what happened during an exercise or incident.

**Why this priority**: The platform's primary learning and operational value comes from turning raw traffic into searchable evidence and making complementary observations easy to correlate.

**Independent Test**: Generate a test session that creates both a signature event and protocol observations, then use the shared correlation value and traffic attributes to locate all related evidence from a single investigation view.

**Acceptance Scenarios**:

1. **Given** analyzed network activity, **When** an analyst opens the overview, **Then** they can see traffic volume, detections by severity and category, allowed and denied flows, and source health for a selected time range.
2. **Given** a signature event with a shared flow-correlation value, **When** the analyst pivots on that value, **Then** matching connection and protocol observations are returned without requiring the analyst to manually reconstruct the flow tuple.
3. **Given** records without a shared correlation value, **When** the analyst searches by time range and source/destination attributes, **Then** related records can still be found and the results distinguish exact correlation from attribute-based matches.
4. **Given** DNS, web, TLS, certificate, connection, or file-transfer observations, **When** the analyst filters by observation type and relevant fields, **Then** the matching structured details are available for inspection.

---

### User Story 3 - Collect a Bounded Forensic Capture (Priority: P3)

As an analyst, I can request a packet capture against an active traffic source with explicit traffic and size bounds, follow its progress, and retrieve the completed artifact so that I can examine packets for a focused investigation.

**Why this priority**: Packet-level evidence is essential for training and forensics, but it depends on a healthy monitoring source and is useful even before automated triggering exists.

**Independent Test**: Start a filtered capture against a test source, generate matching and non-matching traffic, and verify that the completed artifact contains matching traffic, respects all configured bounds, and is retrievable with accurate metadata.

**Acceptance Scenarios**:

1. **Given** an active traffic source, **When** an authorized analyst requests a manual capture with valid filter, duration, packet-length, and maximum-size values, **Then** one capture execution starts on an eligible target and reports lifecycle progress.
2. **Given** an in-progress capture, **When** its duration or maximum size is reached, **Then** collection stops at the first reached bound and the artifact proceeds to durable storage.
3. **Given** a successfully stored capture, **When** the analyst views its record, **Then** the record and capture overview report its time range, packet count, size, source, filter, storage state, retention deadline, and a copyable authenticated CLI/API download action.
4. **Given** an invalid filter, inactive source, unavailable target, or storage failure, **When** the request is processed, **Then** it fails safely with a specific reason and never reports a nonexistent artifact as complete.

---

### User Story 4 - Trigger Captures from Security Events (Priority: P4)

As an operator, I can arm policies that start focused captures when qualifying detection or cluster-flow events occur, with deduplication and rate limits, so that high-value packet evidence is collected without an analyst watching continuously.

**Why this priority**: Event-driven capture is the platform's core automation benefit, but it can be delivered after manual capture proves the capture lifecycle and storage path.

**Independent Test**: Arm one detection policy and one denied-flow policy, emit matching and non-matching events, and verify that only matching events create bounded capture executions with preserved trigger context and enforced rate limits.

**Acceptance Scenarios**:

1. **Given** an armed detection policy with severity and optional rule filters, **When** a matching event arrives, **Then** one bounded capture execution is created with the event's relevant identities and traffic attributes recorded as trigger context.
2. **Given** an armed denied-flow policy with reason, scope, count, and time-window criteria, **When** the threshold is met, **Then** one capture execution is created for the implicated traffic.
3. **Given** a non-matching event, **When** policies are evaluated, **Then** no capture is created and policy evaluation remains observable.
4. **Given** repeated equivalent events inside a policy's cooldown window, **When** they are evaluated, **Then** duplicate captures are suppressed and the policy records that suppression.
5. **Given** a policy at its hourly limit, **When** another matching event arrives, **Then** no capture is created until the limit permits it and the policy exposes its rate-limited state.

### Edge Cases

- Mirrored or overlay traffic may contain duplicate packets. The sensor keeps raw observations, uses a bounded rolling fingerprint window to mark suspected duplicates without discarding evidence, and exposes duplicate counts and status. The MVP does not create an `Incident` entity, so dashboards label these values as observation counts and never imply that each observation is a distinct incident.
- A target or interface may disappear after a source becomes active; the source must leave the active state, report the affected target, and recover automatically when the dependency returns.
- One analysis mode may fail while another remains healthy; the source must report a degraded state that identifies the failed capability while unaffected analysis continues.
- Malformed or unsupported analyzer records must be quarantined or rejected with an observable count and must not stop valid records from being processed.
- A trigger can arrive after relevant packets have already passed. The resulting artifact contains post-trigger traffic only; the system must make the actual capture start time clear and must not imply that pre-trigger packets are present.
- Several policies may match one event. Each policy is evaluated independently, while equivalent capture requests for the same source and traffic inside a deduplication window are collapsed.
- A capture may receive no matching packets. It still completes with a zero-packet result rather than being reported as a failed capture.
- If the system restarts during capture or upload, the capture record must converge to a truthful terminal state or resume safely without creating multiple artifacts for one execution.
- Retention processing must not remove an artifact while it is still being uploaded; after expiry, new downloads must be denied and record status must show that the artifact expired.
- Clocks can differ between event producers. Correlation must preserve original event timestamps and identify the system observation time so analysts can account for skew.
- Packet captures can contain credentials and personal data. Unauthorized users must not be able to create, enumerate, download, or extend retention for captures.

## Requirements *(mandatory)*

### Scope Boundaries

This specification covers the first independently deployable release of passive cluster and physical-network monitoring:

- Declarative management of physical-mirror and node-level traffic sources.
- Continuous signature-based detection and protocol-rich traffic analysis.
- Search, overview, health, and cross-source investigation workflows.
- Manual, post-trigger detection-event, and post-trigger denied-flow captures.
- Capture bounds, deduplication, rate limiting, durable storage, download, and retention.
- Automated upstream rule and script refresh via init containers, and git-managed custom detection content overlaid from OCI artifacts.

The following are explicitly out of scope for this feature and require later specifications:

- Inline traffic blocking, rule promotion to prevention, and a prevention kill switch.
- Decryption using private keys, session keys, or cluster secrets.
- Per-workload capture injection and automatic mutation of application workloads.
- CRD-based detection content lifecycle, user-authored rule promotion workflows, and custom script packaging APIs.
- Scheduled baseline capture, anomaly-driven capture, runtime-security triggers, and packet replay.
- Enterprise multi-tenancy, internet-facing access, and sustained multi-gigabit production traffic.
- Browser single sign-on or bearer-token injection for packet downloads; the MVP exposes authenticated CLI/API retrieval and never embeds credentials or presigned URLs in Grafana.

### Functional Requirements

#### Traffic-source management

- **FR-001**: The system MUST let an authorized operator create, view, update, and delete declarative traffic-source definitions in the installation's configured system namespace without accessing the host operating system; Trawl resources submitted to any other namespace MUST be rejected.
- **FR-002**: A traffic-source definition MUST identify exactly one supported source type: a physical mirror interface on a selected target or a node interface on selected targets.
- **FR-003**: A traffic-source definition MUST support passive operation only and MUST reject requests for inline traffic modification in this release.
- **FR-004**: A traffic-source definition MUST allow the operator to enable signature-based detection, protocol-rich analysis, or both, and to declare resource bounds for each enabled analysis mode.
- **FR-005**: The system MUST validate a traffic-source definition before activating it and MUST report field-specific reasons for invalid source type, target selection, interface, analysis selection, or resource bounds.
- **FR-006**: The system MUST continuously reconcile actual monitoring with the declared traffic-source state after creation, update, component restart, or target availability changes.
- **FR-007**: Each traffic source MUST report one of `Pending`, `Active`, `Degraded`, or `Error`, plus matched targets, enabled analysis health, last observed packet time, and actionable conditions.
- **FR-008**: Deleting a traffic source MUST stop new monitoring for that source and remove only monitoring resources owned by it; historical observations and captures remain governed by their retention policies.

#### Analysis and investigation

- **FR-009**: The system MUST produce structured signature events and structured connection, DNS, web, TLS, certificate, file-transfer, notice, and unusual-traffic observations when the corresponding traffic is present.
- **FR-010**: Every observation MUST include its event time, system observation time, traffic-source identity, observing target, observation type, and available source/destination network attributes.
- **FR-011**: Related signature and protocol observations MUST carry the same standardized flow-correlation value whenever both analysis modes can derive one from the traffic.
- **FR-012**: The system MUST preserve severity, rule identity, category, message, and relevant flow attributes for every signature event that provides those fields.
- **FR-013**: The system MUST make valid observations searchable by time range, traffic source, observing target, observation type, severity, rule identity, correlation value, and available traffic attributes.
- **FR-014**: The system MUST provide an overview of detection trends, connection and protocol activity, allowed and denied cluster flows, and traffic-source health for a selectable time range. The bounded-capture slice MUST extend that overview with recent capture activity when CaptureJob becomes available.
- **FR-015**: The system MUST distinguish exact correlation-value matches from approximate time-and-attribute matches in investigation results.
- **FR-016**: A malformed or unsupported input record MUST NOT prevent valid records from being processed, and its rejection MUST be reflected in an observable error count.

#### Capture execution and storage

- **FR-017**: An authorized analyst MUST be able to request a manual capture against an active traffic source and eligible target.
- **FR-018**: Every capture request MUST define a positive duration and maximum artifact size, and MAY define a traffic filter and captured packet length.
- **FR-019**: The system MUST validate capture filters and bounds before packet collection begins; invalid input MUST fail without starting a capture.
- **FR-020**: A capture execution MUST transition through truthful `Pending`, `Capturing`, `Storing`, and terminal `Completed`, `Failed`, or `Expired` states.
- **FR-021**: Packet collection MUST stop when the first configured duration or maximum-size bound is reached.
- **FR-022**: The system MUST persist each successful capture in durable storage and record the capture source, target, filter, requested and actual time range, packet count, size, storage state, integrity checksum, and retention deadline.
- **FR-023**: Authorized analysts MUST be able to download a completed, unexpired capture through the authenticated gateway API or supported CLI; unauthorized, incomplete, failed, or expired captures MUST NOT be downloadable. Grafana MUST expose only a non-secret copyable CLI/API action in this release.
- **FR-024**: Storage or upload failure MUST result in a failed execution with an actionable reason and MUST NOT produce a completed record or download action for a missing artifact.
- **FR-025**: Retention processing MUST remove expired capture artifacts within 24 hours of their retention deadline, preserve non-sensitive execution metadata for audit, and mark the execution `Expired`.

#### Event-driven capture

- **FR-026**: An authorized operator MUST be able to create, view, update, arm, disarm, and delete capture policies.
- **FR-027**: A capture policy MUST reference an existing traffic source and define exactly one supported automatic trigger type: signature event or denied cluster flow.
- **FR-028**: Signature-event policies MUST support matching by severity and MAY narrow matching by rule identity or category.
- **FR-029**: Denied-flow policies MUST support matching by denial reason and MAY narrow matching by source scope or a count threshold within a time window.
- **FR-030**: Each capture policy MUST define the same capture bounds required for a manual request, artifact retention, a maximum captures-per-hour limit, and a cooldown interval.
- **FR-031**: When an armed policy matches, the system MUST create at most one capture execution for the equivalent source and traffic within the cooldown window and MUST begin capture only on an eligible target that can observe the implicated traffic.
- **FR-032**: A policy-created capture execution MUST preserve an immutable snapshot of the triggering event, matched policy identity and version, and resolved capture parameters.
- **FR-033**: Policy evaluation MUST expose the policy's armed state, total captures, last trigger time, active capture count, rate-limit state, and counts of non-matches, duplicates, and suppressed triggers.
- **FR-034**: Failure to create a policy-requested capture MUST be observable on both the policy and the attempted execution and MUST NOT stop other policies from being evaluated.

#### Safety and operability

- **FR-035**: The system MUST restrict traffic-source changes, policy changes, capture creation, capture enumeration, capture download, and retention changes to explicitly authorized identities.
- **FR-036**: Before completing a traffic-source or policy mutation, manual or automatic capture request, successful artifact download authorization, retention change, capture lifecycle transition, or artifact expiration, the system MUST durably commit an idempotent audit event to the private audit ledger. User-initiated mutations and downloads MUST fail closed when that commit cannot be verified; this failure MUST NOT affect monitored traffic.
- **FR-037**: The system MUST never modify, block, delay, or redirect monitored traffic in this release, including when monitoring or capture components fail.
- **FR-038**: A failure associated with one traffic source, analysis mode, capture, or policy MUST NOT prevent healthy independent sources and policies from operating.
- **FR-039**: Operational status MUST expose packet loss where available, suspected duplicate observations, analysis failures, rejected records, trigger suppression, capture failures, storage failures, audit-delivery failures, and retention failures without exposing packet payloads or credentials.
- **FR-040**: Restarting a control component MUST preserve declared sources, policies, execution records, and artifact references and MUST converge each non-terminal operation to a single truthful outcome.

#### Analyzer content management

- **FR-041**: The system MUST refresh upstream detection rules and analysis scripts from configured feeds on each analyzer pod startup without requiring an image rebuild or CI pipeline.
- **FR-042**: The system MUST support an optional OCI artifact reference per analyzer containing site-specific rules, scripts, and configuration that overlay the upstream content at startup.
- **FR-043**: A custom content artifact MUST be validated (syntax-checked) before packaging and MUST NOT prevent the analyzer from starting with upstream-only content if the custom artifact is missing or corrupt.
- **FR-044**: The operator MUST trigger rolling restarts of analyzer workloads on a configurable schedule to pick up upstream content updates.
- **FR-045**: Analyzer health status MUST report the upstream feed timestamp and custom content artifact digest when present, so operators can verify content currency.

### Key Entities

- **Traffic Source**: A declarative request to observe packets from one physical-mirror or node-level location. It contains source selection, enabled analysis modes, operating bounds, desired state, and current health.
- **Security Event**: A structured signature-based detection with severity, rule identity, message, traffic attributes, timestamps, and an optional shared flow-correlation value.
- **Protocol Observation**: Structured metadata about a connection or protocol exchange, including its observation type, traffic attributes, timestamps, protocol-specific fields, and an optional shared flow-correlation value.
- **Cluster Flow Event**: An existing cluster-network observation used for context or denied-flow triggers, including verdict, reason, source/destination scope, traffic attributes, and timestamps.
- **Capture Policy**: An operator-managed rule that maps one trigger definition to bounded capture behavior, retention, cooldown, hourly limit, and operational status.
- **Capture Execution**: One immutable packet-collection attempt, whether requested manually or by policy. It records source, target, resolved limits, lifecycle, trigger context, results, failure reason, and artifact reference.
- **Capture Artifact**: The sensitive packet file produced by a successful execution, with size, checksum, storage state, authorization boundary, and retention deadline.
- **Audit Event**: A non-payload, idempotently keyed record of a security-sensitive configuration, capture, download, retention, transition, or expiration action and the identity that performed it. The private object-store ledger is authoritative; Loki is its searchable delivery target.
- **Analyzer Content**: Upstream detection rules and scripts refreshed at pod startup, optionally overlaid with site-specific custom content from a versioned OCI artifact. Content currency is observable through analyzer health status.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A cluster operator can declare one valid traffic source and observe its first structured test-traffic record within 15 minutes, without logging into or modifying a cluster host.
- **SC-002**: At least 95% of valid traffic-source creations and updates reach `Active` or an actionable non-active state within 2 minutes in the reference homelab.
- **SC-003**: During a 60-minute test at 100 Mb/s sustained observed traffic, active sources remain available and report less than 1% packet loss at the capture boundary.
- **SC-004**: At least 95% of valid structured security and protocol observations become searchable within 30 seconds of being emitted by an analyzer.
- **SC-005**: Across 20 timed attempts using ten deterministic correlated sessions—one attempt beginning from each record direction per session—an analyst finds the exact matching signature or protocol observation in under 3 minutes in at least 18 attempts. Timing begins when the source record opens and ends when the exact-match record is displayed; only durations and pass/fail results are retained as evidence.
- **SC-006**: At least 95% of valid manual capture requests begin packet collection within 10 seconds, and their artifact becomes downloadable within 60 seconds after collection ends when storage is healthy.
- **SC-007**: In boundary tests, 100% of captures stop at the first duration or maximum-size limit and no completed artifact exceeds its configured maximum size by more than 1 MiB.
- **SC-008**: In trigger tests, 100% of qualifying events create no more than one capture inside the cooldown window, 100% of non-qualifying events create none, and hourly limits are never exceeded.
- **SC-009**: In restart and single-component failure tests, unaffected traffic sources continue operating and every in-flight capture converges to exactly one terminal record without duplicate artifacts.
- **SC-010**: 100% of expired artifacts reject new download attempts at their retention deadline and are removed from durable storage within 24 hours.
- **SC-011**: During acceptance testing, 100% of invalid source definitions, filters, capture bounds, and unavailable dependencies produce an actionable status or error and never produce a false `Active` or `Completed` state.

## Assumptions

- The target is a trusted, single-organization homelab used by a small number of authorized operators and security learners; internet-facing and adversarial multi-tenant access are out of scope.
- The deployment environment is an existing immutable Kubernetes cluster. All monitoring, control, analysis, and capture functions run as managed workloads; no host package installation or interactive host access is available.
- The environment already provides cluster flow telemetry, centralized log search and visualization, and durable object storage. The technical plan will bind these capabilities to the specific products documented in the root architecture.
- A physical port mirror and dedicated receiving interface are configured outside this feature before a physical-mirror traffic source can become active.
- Signature-based security events and protocol observations must remain compatible with the data and investigation concepts taught in the target network-monitoring coursework. Exact analyzer products, images, rule feeds, and scripts belong in the technical plan.
- Automatic captures are post-trigger only. This release does not maintain a rolling packet buffer and cannot recover packets observed before collection starts.
- Upstream rule and script refresh at pod startup plus git-managed custom content packaged as an OCI artifact are sufficient for this release; a CRD-based detection content lifecycle API requires a later feature.
- Capture artifacts may contain credentials, personal data, and application payloads and are therefore treated as sensitive forensic evidence.
- Event producers and cluster nodes have synchronized clocks within the tolerance established by the deployment environment, while both producer and observation timestamps are retained for investigations.
- Default retention is 30 days for event-driven and manual forensic captures unless an authorized operator selects a shorter period allowed by deployment policy.
- All Trawl custom resources are accepted only in the installation-configured system namespace, `trawl-system` by default. Cluster-wide CRD discovery does not imply cluster-wide reconciliation or privileged workload creation.
- Analyzer pods require outbound network access to configured upstream rule and script feeds at startup. Custom detection content is pre-validated and packaged as an OCI artifact in a cluster-accessible registry.

### Dependencies

- A functioning cluster control plane capable of persisting declarative resources and status.
- Eligible nodes and interfaces that can observe the requested traffic without changing its path.
- A source of cluster-flow verdicts for overview and denied-flow triggers.
- Centralized storage and query capabilities for structured observations.
- Durable artifact storage that supports authenticated upload, download, expiration, and integrity verification.
- A separate private audit-ledger bucket that supports versioning, conditional
  creation, backend-enforced write-once retention, and bounded lifecycle cleanup.
- External network configuration that delivers mirrored traffic to the declared physical interface.
- Outbound network access from analyzer init containers to upstream detection feeds (ET Open, community script repositories).
- An OCI-compatible registry accessible from the cluster for custom detection content artifacts, when site-specific content is configured.
