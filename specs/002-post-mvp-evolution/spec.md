# Feature Specification: Post-MVP Evolution

**Feature Branch**: `002-post-mvp-evolution`

**Created**: 2026-09-13

**Status**: Draft

**Input**: User description: "Translate the post-MVP evolution plan in `docs/src/content/docs/roadmap.md` into a Spec Kit program specification covering all nine workstreams, their dependency order, and the decisions each forces."

## Program Note

This specification covers a **program of nine workstreams**, not a single
increment. Each user story below is sized to become its own
`specs/NNN-*/` feature with its own plan and tasks. The stories are
independently testable and are ordered by the dependency graph in
`docs/src/content/docs/roadmap.md`, not by appetite.

The program exists as one specification because the sequencing is the load-
bearing decision. Several items are cheap now and expensive later, and two are
worthless if built in the wrong order. A per-workstream specification written in
isolation would lose that, and the ordering constraints would be rediscovered
during implementation.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Trust Every Coverage Claim (Priority: P1)

As an analyst reading a resource six weeks after an incident, I can rely on
every state field to describe what was actually true at that time, so that an
investigation does not rest on a claim the system was never in a position to
make.

**Why this priority**: Two of the MVP's recorded debts are status lies, which is
the failure class this project is most careful about everywhere else. Every
workstream below adds state fields; adding them on top of an untrustworthy base
compounds the problem. This story also closes the device-contention gap before
the provider count grows in Story 7.

**Independent Test**: Sever the event worker's connectivity and confirm the
affected policies stop claiming coverage. Declare two mirror configurations
naming the same device and confirm exactly one holds the device while the other
reports a specific conflict reason, with no repeated device mutation in the
audit ledger.

**Acceptance Scenarios**:

1. **Given** armed capture policies and a healthy event worker, **When** the worker stops or loses its trigger source, **Then** an independent component marks every affected policy with a specific stale-heartbeat reason rather than leaving it claiming coverage.
2. **Given** one mirror configuration already in effect on a device, **When** a second configuration naming the same device is created, **Then** the incumbent keeps the device, the younger claim reports a specific conflict reason, and neither resource rewrites the device on subsequent reconciles.
3. **Given** an acceptance environment missing a required host prerequisite, **When** the acceptance suite runs, **Then** the affected specs fail with the remedy stated in the message rather than skipping silently.
4. **Given** the repository's required status checks, **When** a security gate fails, **Then** the change is blocked rather than advisory.
5. **Given** the contributor and agent guidance documents, **When** a reader follows them, **Then** they describe the system as built, including the audit ledger, fabric providers, observation envelope, analyzer content model, and suppression workflow.

---

### User Story 2 - Distinguish When Something Happened From When It Was Learned (Priority: P2)

As an operator and as a downstream consumer, I can tell the time an observed
event occurred apart from the time the system learned about it, so that
out-of-order and late-arriving records are handled correctly instead of being
mistaken for a burst of live activity.

**Why this priority**: Small now, a migration later. Today there are exactly two
producers and a known set of consumers. Stories 3, 8 and 10 all introduce
records that are late by construction, and each of them would otherwise
rediscover this problem separately and inconsistently.

**Independent Test**: Submit a batch of observations carrying old event times to
a live pipeline and assert that the read cursor, the duplicate-suppression
window and the capture rate accounting each behave as specified, with no records
lost and no captures triggered by replay alone.

**Acceptance Scenarios**:

1. **Given** the observation envelope, **When** a producer emits a record, **Then** the record carries both the time the event occurred and the time the system ingested it, and consumers state which one governs their behaviour.
2. **Given** a stream of live observations, **When** a batch of older observations is interleaved, **Then** the read cursor advances without losing either the live or the late records.
3. **Given** a capture policy with a cooldown and an hourly limit, **When** a batch of late observations arrives that would have qualified when they occurred, **Then** the rate accounting behaves per the recorded decision and a replay alone does not exhaust the limit.
4. **Given** duplicate suppression over a bounded window, **When** a record already seen is re-delivered later than the live window, **Then** the system recognises it as a duplicate up to the specified lateness bound.
5. **Given** a record produced by re-analysis rather than first-pass live output, **When** an analyst inspects it, **Then** the record is distinguishable as such.
6. **Given** a record later than the maximum tolerated lateness, **When** it arrives, **Then** it is marked as exceeding the bound rather than silently accepted or silently dropped.

---

### User Story 3 - Retrieve the Packets That Preceded a Detection (Priority: P3)

As an analyst, I can obtain the packets from before a detection fired, not only
those captured after it, so that I can examine the activity that caused the
alert rather than its aftermath.

**Why this priority**: The biggest functional gap in the product. Today a policy
fires on an alert and then starts capturing, so the packets that caused the
alert are already gone. This is the capability comparable platforms have and
Trawl does not, and it is the substrate Stories 4, 8 and 10 build on.

**Independent Test**: Generate traffic that triggers a detection, request an
extract spanning a window that begins before the trigger, and verify the
resulting artifact contains the pre-trigger packets and that its record states
the window actually covered.

**Acceptance Scenarios**:

1. **Given** an active traffic source maintaining a continuous bounded buffer, **When** an analyst or a policy requests an extract for a window spanning before and after a reference time, **Then** an artifact covering that window is produced through the existing storage, authorization, retention and ledger path.
2. **Given** a requested window fully retained in the buffer, **When** the extract completes, **Then** the record reports the window as complete.
3. **Given** a requested window that has partially rolled out of the buffer, **When** the extract completes, **Then** the record reports the window requested, the window actually covered, and a distinct truncated outcome — never a short artifact presented as whole.
4. **Given** a requested window entirely older than the buffer, **When** the request is evaluated, **Then** it reports a distinct expired outcome and produces no artifact claiming coverage.
5. **Given** a configured buffer size budget, **When** the buffer reaches it, **Then** the oldest data is displaced, writing never stops, storage pressure is reported, and the host filesystem is never exhausted.
6. **Given** a restart of the component maintaining the buffer, **When** it recovers, **Then** the resulting gap in retained coverage is discoverable rather than presented as continuous.

---

### User Story 4 - Re-Analyze Stored Traffic (Priority: P4)

As an analyst or content author, I can run a chosen analyzer at a pinned content
version over traffic already stored, so that I can replay exercises, reprocess
evidence, and compare what today's detection content finds in traffic collected
earlier.

**Why this priority**: Delivered with Story 3 as one increment because both rest
on the same source abstraction. It converts three separately-scoped items —
packet replay, bucket reprocessing, and detection regression testing — into one
capability, and it is the execution surface Story 9 requires.

**Independent Test**: Run an analyzer over a stored artifact at two different
pinned content versions and diff the resulting observations, confirming both
runs are attributable to their content version and both are recorded in the
ledger.

**Acceptance Scenarios**:

1. **Given** a stored capture artifact, a buffer extract window, or an object in durable storage, **When** an analyst requests analysis with a pinned analyzer content version, **Then** the analysis runs and emits observations attributed to that source and content version.
2. **Given** two analysis runs over the same traffic at different content versions, **When** an analyst compares them, **Then** the differing observations are identifiable and each is attributable to its content version.
3. **Given** any analysis run, **When** it completes or fails, **Then** the ledger records what was analyzed, by whom, with what content, and to what outcome.
4. **Given** traffic whose connection spans a boundary between stored segments, **When** analysis produces connection records, **Then** records affected by a segment boundary state that they are, rather than being presented as whole connections.
5. **Given** an analysis run over a source that is missing, expired, or unreadable, **When** it is evaluated, **Then** it fails with a specific reason and emits no observations implying coverage.

---

### User Story 5 - Store Evidence on a Second Storage Provider (Priority: P5)

As an operator, I can hold evidence on a storage provider other than the one the
MVP was built against, with the same write-once guarantee, so that the platform
is not bound to a single vendor's primitives.

**Why this priority**: The interface revision must happen before the second
implementation exists, not after. Writing a second backend against the current
interface would either weaken the ledger's guarantee silently or accumulate
per-provider special cases, and the credential model change touches every
component that parses configuration.

**Independent Test**: Run the existing storage conformance suite against a
second provider implementation and confirm every write-once, conditional-write,
version-identity and authorized-read guarantee holds, or is explicitly refused
at configuration time rather than silently degraded.

**Acceptance Scenarios**:

1. **Given** the storage abstraction, **When** it is revised, **Then** it expresses only guarantees every intended provider can actually hold, and the conformance suite passes against the original provider unchanged.
2. **Given** a second provider implementation, **When** the conformance suite runs against it, **Then** every write-once and retention guarantee is demonstrated, not assumed.
3. **Given** a provider that cannot hold a required guarantee, **When** it is configured, **Then** the configuration is refused with a specific reason rather than accepted with a weaker guarantee.
4. **Given** a deployment using platform-issued workload identity rather than static credentials, **When** components start, **Then** they obtain storage access without a long-lived secret on disk.
5. **Given** a configuration schema change, **When** it is released, **Then** every component that parses configuration is identified and rolled together, and a stale configuration fails loudly at startup rather than at first use.

---

### User Story 6 - Capture at Higher Rates Without the Host Network Stack (Priority: P6)

As an operator, I can have a mirror-fed traffic source collect packets through a
kernel-bypass path, and see which mode was actually achieved, so that throughput
improves without the platform overstating what it obtained.

**Why this priority**: Justified by the buffer that consumes the packets, so it
follows Story 3. The safety constraint is the reason it needs an API change
rather than a documentation note.

**Independent Test**: Enable the bypass path on a mirror source and confirm the
achieved mode is reported; attempt to enable it on a node-level source and
confirm the request is refused before it can take the node off the network.

**Acceptance Scenarios**:

1. **Given** a mirror-fed traffic source, **When** an operator enables kernel-bypass capture, **Then** capture proceeds and the source reports the mode actually achieved, not the mode requested.
2. **Given** a node-level traffic source, **When** an operator attempts to enable kernel-bypass capture, **Then** the request is rejected at admission with a specific reason, because the mode would remove the interface from host use.
3. **Given** hardware or driver support insufficient for the highest mode, **When** capture starts, **Then** it falls back, remains available, and reports the reduced mode rather than reporting the requested one.
4. **Given** a source reporting a specific achieved mode, **When** an operator reads its state, **Then** they can determine the mode without host or container shell access.

---

### User Story 7 - Mirror Traffic on Cloud Infrastructure (Priority: P7)

As an operator, I can declare packet mirroring on cloud network infrastructure
using the same resource and revert discipline as physical switches, so that the
platform's declarative mirroring is not limited to hardware I can reach on a
local network.

**Why this priority**: Independent of the rest of the graph and needs only the
device-contention rule from Story 1. It is the item that makes the platform
legible to an audience beyond the homelab, so it can be pulled earlier if that
audience matters.

**Independent Test**: Declare a mirror against a cloud provider, verify traffic
reaches the target, delete the resource, and verify the provider-side
configuration is fully removed and every mutation appears in the ledger.

**Acceptance Scenarios**:

1. **Given** credentials for a supported cloud provider, **When** an operator declares a mirror, **Then** the provider-side configuration is created and the resource reports it as in effect only once verified.
2. **Given** a mirror in effect, **When** the resource is deleted, **Then** the provider-side configuration is reverted before the resource is removed, and no mirroring is left running.
3. **Given** any provider-side mutation, **When** it occurs, **Then** it is recorded in the write-once ledger with enough detail to reconstruct what changed.
4. **Given** a mirror whose provider or device reference an operator attempts to change, **When** the change is submitted, **Then** it is rejected, because revert resolves the reference at deletion time and repointing would strand a running mirror.
5. **Given** a provider whose mirroring is metered, **When** a mirror is in effect, **Then** the operator can determine from the resource that it is generating volume.

---

### User Story 8 - Trigger Retrospective Capture From Late Flow Records (Priority: P8)

As an operator, I can act on flow records that arrive minutes after the traffic
they describe by extracting the packets for the window they name, so that a
signal learned late still yields evidence.

**Why this priority**: Useless as a live trigger and excellent as a
retrospective one, so it depends on Story 3 for the buffer and Story 2 for the
time model. Every record it handles is late by construction.

**Independent Test**: Deliver a batch of flow records describing traffic from
several minutes earlier, including a re-delivery of records already processed,
and confirm exactly one extract per qualifying window and no duplicate work.

**Acceptance Scenarios**:

1. **Given** a configured late flow source, **When** records appear describing traffic from earlier, **Then** qualifying records cause extraction of the buffer window the record describes.
2. **Given** records re-delivered after already being processed, **When** they are consumed, **Then** no duplicate extraction occurs.
3. **Given** records arriving out of order, **When** they are consumed, **Then** the source's progress marker does not advance past unprocessed records.
4. **Given** a qualifying record whose window has already rolled out of the buffer, **When** extraction is attempted, **Then** it reports the expired outcome from Story 3 rather than producing an empty artifact.
5. **Given** flow records describing infrastructure-level rather than cluster-level activity, **When** they are stored, **Then** that distinction is preserved rather than flattened into cluster flow records.

---

### User Story 9 - Analyze Encrypted Traffic Where Key Material Permits (Priority: P9)

As an analyst with the appropriate grant, I can supply session key material to
an analysis run and obtain decrypted protocol detail, so that encrypted sessions
are not entirely opaque — while key material remains custodied and every use is
accountable.

**Why this priority**: Last of the major workstreams and dependent on Story 4's
execution surface. The reframe from server private keys to session key material
is what makes it worth building at all.

**Independent Test**: Run an analysis over a capture with matching session key
material and confirm decrypted protocol detail is produced, the use is
ledgered, and an identity holding only capture-read access cannot perform it.

**Acceptance Scenarios**:

1. **Given** a stored capture and matching session key material, **When** an authorized analyst requests analysis with decryption, **Then** decrypted protocol observations are produced for the sessions the material covers.
2. **Given** an identity authorized to read captures but not to decrypt them, **When** they request analysis with decryption, **Then** it is refused, because reading a capture and reading its plaintext are separate grants.
3. **Given** any analysis run supplied with key material, **When** it runs, **Then** the ledger records who decrypted what, a non-secret identifier for the material used, and when.
4. **Given** key material supplied to a run, **When** the run ends, **Then** the material does not persist in durable storage, an image layer, logs, status, or metrics.
5. **Given** key material covering only some sessions in a capture, **When** analysis completes, **Then** the coverage achieved is reported rather than implying the whole capture was decrypted.

---

### User Story 10 - Retrieve the Packets for One Flow (Priority: P10)

As an analyst, I can ask for the packets belonging to a single correlated flow
rather than downloading a whole artifact, so that pivoting from an observation
to its packets does not require retrieving unrelated traffic.

**Why this priority**: Research first. It is the natural capability given
existing correlation, envelope and authorization pieces, but both hard parts —
indexing over a rolling buffer, and an authorization grant finer than the
platform's access control can express — need answers before it can be scoped.

**Independent Test**: From an observation carrying a flow correlation value,
request that flow's packets and confirm the returned packets belong to that flow
and only that flow, and that the request is authorized and ledgered at flow
granularity.

**Acceptance Scenarios**:

1. **Given** an observation carrying a flow correlation value, **When** an authorized analyst requests the packets for that value, **Then** only packets belonging to that flow are returned.
2. **Given** a per-flow request, **When** it is authorized, **Then** the decision is made at flow granularity and recorded in the ledger with the flow identified.
3. **Given** a flow index maintained over a rolling buffer, **When** the buffer is under sustained write load, **Then** indexing does not become the limiting factor on retained coverage.
4. **Given** a flow whose packets have partially rolled out of the buffer, **When** they are requested, **Then** the response states the coverage returned rather than implying completeness.

---

### User Story 11 - Manage Physical Mirroring Through SSH (Priority: P3)

As an operator, I can use PortMirror on a supported SSH-managed switch when
the HTTPS API is unavailable. Trawl configures, reads back, audits, and removes
the mirror through the existing resource lifecycle.

**Independent Test**: Configure, re-reconcile, and delete a mirror on an
emulator or disposable device for the first built-in profile. Wrong host keys,
unknown models, and unsupported mirror shapes cause zero writes.

**Acceptance Scenarios**:

1. **Given** a supported profile and pinned host key, **When** a PortMirror is declared, **Then** Active follows readback of sources, direction, and target.
2. **Given** a repeated reconcile or partial device write, **When** Trawl retries, **Then** it converges without unrelated edits or repeated effective changes.
3. **Given** deletion, **When** revert completes, **Then** the mirror is absent on readback and mutations appear in the existing ledger.
4. **Given** an unsupported capability or host-key mismatch, **When** evaluated, **Then** Trawl refuses with a specific reason before writing.
5. **Given** a resource or Secret, **When** inspected, **Then** neither can supply arbitrary shell commands or templates.

---

### User Story 12 - Attribute Node Traffic to Pods Without Guessing (Priority: P4)

As an analyst, I can see a verified pod identity and its evidence source on
node-local flows. A reused pod name or address cannot change historical identity.

**Independent Test**: Generate node-local flows, replace a pod with another
using the same name, and include ambiguous or translated traffic. Verify the
correct pod UID where evidence suffices and unknown otherwise.

**Acceptance Scenarios**:

1. **Given** a corroborated node-local flow, **When** normalized, **Then** the endpoint carries pod UID, namespace, name, attribution source, and occurrence time.
2. **Given** pod replacement or address reuse, **When** older records are read, **Then** they retain the old UID.
3. **Given** NAT, shared addresses, missing metadata, or conflicting matches, **When** attribution runs, **Then** it reports unknown or ambiguous rather than guessing by IP or name.
4. **Given** a physical-switch mirror without corroborating cluster evidence, **When** packets arrive, **Then** no cgroup-based pod claim is made.

---

### Edge Cases

- What happens when a buffer extract is requested for a window that begins before the component maintaining the buffer last restarted?
- How does the system handle a late record whose event time precedes the earliest data any buffer still retains?
- What happens when two analysis runs write observations for the same traffic at the same content version concurrently?
- How does the system behave when a storage provider accepts a write-once setting but silently applies a weaker scope than requested?
- What happens when kernel-bypass capture is enabled on an interface that a later node reconfiguration promotes to host use?
- How does the system handle a cloud mirror whose provider-side configuration was deleted or altered outside the platform?
- What happens when a late flow source's progress marker is older than the provider's own retention of those records?
- How does the system handle key material that is malformed, expired, or matches no session in the capture?
- What happens to an in-flight analysis run when its pinned analyzer content version is deleted from the registry?
- How is a buffer extract handled when the request is valid but the node holding that buffer is unreachable?

## Requirements *(mandatory)*

### Scope Boundaries

This program does **not** include:

- **Inline prevention or traffic modification.** The passive-only constraint is unchanged. Adding a second traffic-handling mode requires a separate approved specification, per Constitution Principle I.
- **A resource holding detection rule or script text.** Digest-pinned content distributed through the existing content model supersedes it. This item from the original architecture document is closed as done differently, not carried.
- **Injecting capture containers into user workloads.** Superseded by time-bound Pod UID attribution from corroborated cluster flow metadata, with a node-local kernel signal considered only after a feasibility spike. This requires no workload mutation or restart.
- **Server-private-key decryption as a primary path.** It recovers a shrinking remnant of modern traffic while carrying the full custody burden of something that works. It may be added last or never.
- **Schedule-based, anomaly-based, and runtime-security-triggered capture.** Dropped from the current program; a future proposal would need its own specification.

### Functional Requirements

**Truthful state and carried gaps**

- **FR-001**: A component independent of the event worker MUST hold the worker's liveness signal and MUST mark every affected policy with a specific stale reason when that signal lapses.
- **FR-002**: The system MUST detect two mirror configurations claiming the same device, MUST allow the incumbent to retain it, and MUST report a specific conflict reason on the younger claim.
- **FR-003**: A conflicted mirror configuration MUST NOT mutate the device, so that contention cannot produce repeated device writes or repeated ledger entries.
- **FR-004**: Acceptance specs with unmet environmental prerequisites MUST fail with the remedy stated, and MUST NOT skip silently.
- **FR-005**: Security gates MUST be required for merge rather than advisory.
- **FR-006**: Contributor and agent guidance MUST describe the system as built, including the audit ledger, fabric providers, observation envelope, analyzer content model, and suppression workflow.

- **FR-006a**: The acceptance environment MUST include a traffic source capable of driving a tapped interface at the reference rate, so that the throughput criterion is verified rather than assumed (D-002).

**Observation time model**

- **FR-007**: The observation envelope MUST carry the time an event occurred separately from the time the system ingested it.
- **FR-008**: Every consumer of the envelope MUST state which time governs its behaviour, and that choice MUST be recorded as a decision rather than left implicit.
- **FR-009**: Read cursors MUST advance without losing either live or late records when the two are interleaved.
- **FR-010**: Duplicate suppression MUST recognise a previously seen record re-delivered later than the live window, up to a specified maximum lateness.
- **FR-011**: The system MUST define a maximum tolerated lateness and MUST mark records exceeding it rather than silently accepting or discarding them.
- **FR-012**: An observation produced by re-analysis MUST be distinguishable from first-pass live output.
- **FR-013**: Capture rate limiting and cooldown accounting MUST behave per FR-008's recorded decision, and a batch of late records MUST NOT alone exhaust limits that exist to bound live capture.

**Continuous buffer and retrospective extraction**

- **FR-014**: Traffic sources MUST be able to maintain a continuous bounded buffer of captured packets.
- **FR-015**: Capture requests MUST support extraction of a window spanning time before a reference point, in addition to the existing collect-from-now behaviour.
- **FR-016**: An extract record MUST report the window requested and the window actually covered.
- **FR-017**: The system MUST distinguish a complete extract, a truncated extract, and a window entirely outside retained coverage as separate outcomes, and MUST NOT present a partial extract as complete.
- **FR-018**: The buffer MUST operate within a configured size budget, MUST displace oldest data rather than refusing to write, and MUST report storage pressure.
- **FR-019**: The buffer MUST NOT be able to exhaust host storage.
- **FR-020**: A gap in retained coverage caused by restart or failure MUST be discoverable rather than presented as continuous.
- **FR-021**: Extracted artifacts MUST flow through the existing storage, authorization, retention and ledger path without a parallel mechanism.

**Analysis over stored traffic**

- **FR-022**: Analysts MUST be able to run a selected analyzer at a pinned content version over a stored artifact, a buffer extract window, or an object in durable storage.
- **FR-023**: Observations from such a run MUST be attributable to their source and to the content version that produced them.
- **FR-024**: Every analysis run MUST produce a ledger record of what was analyzed, by whom, with what content, and to what outcome.
- **FR-025**: Records affected by a boundary between stored segments MUST state that they are, rather than being presented as whole.
- **FR-026**: An analysis run over a missing, expired, or unreadable source MUST fail with a specific reason and MUST NOT emit observations implying coverage.
- **FR-027**: Analysts MUST be able to compare runs over the same traffic at different content versions and identify the differences.

**Storage portability**

- **FR-028**: The storage abstraction MUST express only guarantees every intended provider can hold, and MUST be revised before a second provider is implemented.
- **FR-029**: Each provider implementation MUST demonstrate the write-once and retention guarantees through the shared conformance suite rather than by assertion.
- **FR-030**: A provider unable to hold a required guarantee MUST be refused at configuration time with a specific reason, and MUST NOT be accepted with a silently weaker guarantee.
- **FR-031**: The system MUST support platform-issued workload identity for storage access without a long-lived credential on disk.
- **FR-032**: A configuration schema change MUST identify every component that parses configuration, and a stale configuration MUST fail at startup rather than at first use.

**Kernel-bypass capture**

- **FR-033**: Mirror-fed traffic sources MUST support a kernel-bypass capture path.
- **FR-034**: Kernel-bypass capture MUST be rejected at admission for node-level sources, because it removes the interface from host use.
- **FR-035**: A source using kernel-bypass capture MUST report the mode actually achieved, not the mode requested.
- **FR-036**: A fallback to a lesser mode MUST keep capture available and MUST be visible without host or container shell access.

**Cloud mirroring**

- **FR-037**: The fabric abstraction MUST support cloud packet-mirroring providers using the same resource and revert discipline as physical devices.
- **FR-038**: Provider-side configuration MUST be reverted before the resource is removed.
- **FR-039**: Every provider-side mutation MUST be recorded in the write-once ledger.
- **FR-040**: A mirror's provider and device reference MUST remain immutable, because revert resolves the reference at deletion time.
- **FR-041**: Where a provider meters mirroring, the resource MUST report observed mirrored volume, so that metered spend is discoverable. It MUST NOT report a monetary figure, which it cannot know truthfully (D-003).

**Late flow sources**

- **FR-042**: The system MUST consume flow records that arrive after the traffic they describe and MUST trigger extraction of the window each record names.
- **FR-043**: Re-delivered records MUST NOT cause duplicate extraction.
- **FR-044**: A late flow source's progress marker MUST NOT advance past unprocessed records.
- **FR-045**: Infrastructure-level flow records MUST retain that distinction rather than being flattened into cluster-level flow records.

**Decryption key material**

- **FR-046**: Analysis runs MUST accept session key material as an input.
- **FR-047**: Reading a capture and reading its decrypted content MUST be separate authorizations, and the finer grant MUST be verified explicitly rather than inferred.
- **FR-048**: Every use of key material MUST be recorded in the ledger with the identity, a non-secret material identifier or fingerprint, the target, and the time; raw key material MUST NOT enter the ledger.
- **FR-049**: Key material MUST NOT persist in durable storage, image layers, logs, status fields, metrics, or error messages.
- **FR-050**: Where key material covers only part of a capture, the coverage achieved MUST be reported rather than implied to be total.

**Flow-addressable retrieval**

- **FR-051**: Analysts MUST be able to request the packets belonging to a single correlated flow rather than a whole artifact.
- **FR-052**: A per-flow request MUST be authorized at flow granularity and recorded in the ledger with the flow identified.
- **FR-053**: Flow indexing MUST NOT become the limiting factor on retained buffer coverage.
- **FR-054**: A per-flow response covering only part of a flow MUST state the coverage returned.

**Program-level**

- **FR-055**: Each workstream that introduces a gate MUST also demonstrate that the gate executes, because a gate nobody has run is not a gate.
- **FR-056**: The cumulative API changes across this program MUST be released as one deliberate version promotion with a conversion path, rather than as a sequence of independent breaking changes to the existing version.

**SSH-managed physical mirroring**

- **FR-057**: SSH mirrors MUST use PortMirror and the existing fabric provider contract with built-in reviewed device profiles, never operator-supplied shell commands.
- **FR-058**: SSH MUST verify a pinned host key and refuse unknown keys before device mutation; credentials come from the referenced Secret.
- **FR-059**: Each profile MUST read back sources, direction, and target, configure and revert idempotently, and ledger device mutations.
- **FR-060**: Unsupported device models, firmware, port layouts, and mirror capabilities MUST be refused before writing.

**Pod attribution**

- **FR-061**: Attributed endpoints MUST carry immutable pod UID, namespace, name, attribution source, and occurrence time; unknown or ambiguous attribution MUST be explicit.
- **FR-062**: Node-local packet observations MAY inherit identity only from temporally and directionally corroborated flows or verified node-local kernel signals; IP or pod name alone MUST NOT establish identity.
- **FR-063**: Physical-switch mirrored packets MUST NOT be assigned cgroup identity from the packet itself; independent cluster evidence is required for a pod link.
- **FR-064**: Attribution MUST NOT mutate application workloads or require restarts. Any new kernel collector requires separate privilege and data-access review.


### Key Entities

- **Observation envelope**: The normative record every analyzer output is normalized into. Gains a separate occurrence time and ingestion time, a lateness marker, and a re-analysis indicator.
- **Continuous buffer**: A bounded, continuously written store of recent packets held at a traffic source. Characterized by its size budget, the span of time it currently retains, and its displacement behaviour.
- **Extraction window**: A requested time span against a buffer. Carries both the requested span and the span actually covered, and resolves to a complete, truncated, or expired outcome.
- **Analysis run**: An execution of a pinned analyzer over a defined source, optionally with key material, producing observations and a ledger record.
- **Analysis source**: A stored capture artifact, a buffer extraction window, or an object in durable storage.
- **Storage provider**: An implementation of the evidence store. Characterized by the write-once, conditional-write, version-identity and authorized-read guarantees it can hold.
- **Fabric provider**: An implementation of device mirroring, physical or cloud. An SSH profile adds vendor-specific commands to a shared, host-key-verified transport.
- **Late flow source**: A provider of flow records delivered after the traffic they describe. Characterized by a progress marker, a lateness tolerance, and re-delivery idempotency.
- **Key material**: Session secrets supplied to an analysis run. Characterized by its form, the sessions it covers, and a custody lifetime bounded by the run.
- **Flow reference**: A correlation value addressing one flow across observations and packets.
- **Pod attribution**: A time-bound endpoint identity with pod UID, provenance, and an explicit unknown or ambiguous state when ownership cannot be established.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: In failure-injection tests, 100% of policies owned by a stopped or disconnected event worker report a stale reason within 5 minutes, and none continue to claim coverage.
- **SC-002**: In contention tests, two configurations naming one device produce exactly one device configuration, zero repeated device mutations across at least 10 reconcile cycles, and a specific conflict reason on the younger claim.
- **SC-003**: Zero acceptance specs skip silently for unmet environmental prerequisites; 100% of such prerequisites fail with the remedy stated.
- **SC-003a**: During a 60-minute run at the reference rate driven by the acceptance traffic generator, active sources remain available, report observed bytes and packets, and report less than 1% loss at the capture boundary.
- **SC-004**: When a batch of at least 1,000 observations with event times at least 20 minutes old is interleaved with live traffic, zero records are lost from the cursor, 100% of re-delivered duplicates within the lateness bound are suppressed, and zero captures are triggered by the replay alone.
- **SC-005**: For extraction requests where the window is fully retained, at least 95% produce an artifact containing the pre-reference-point traffic, and 100% of records report the window actually covered.
- **SC-006**: In boundary tests, 100% of partially retained windows report a truncated outcome and 100% of fully expired windows report an expired outcome; zero partial extracts are reported as complete.
- **SC-007**: Under sustained capture at the reference rate for 60 minutes, the buffer stays within its configured size budget, host storage is never exhausted, and retained coverage never silently falls below the configured span without being reported.
- **SC-008**: Analysis runs over the same stored traffic at two content versions produce observations 100% attributable to their content version, and both runs appear in the ledger.
- **SC-009**: The storage conformance suite passes against every supported provider, and 100% of configurations naming a provider that cannot hold a required guarantee are refused at startup with a specific reason.
- **SC-010**: 100% of attempts to enable kernel-bypass capture on a node-level source are rejected at admission, and 100% of sources using it report the achieved mode without host or container shell access.
- **SC-011**: For every supported cloud mirroring provider, 100% of deleted mirrors leave no provider-side configuration in effect, and 100% of provider-side mutations appear in the ledger.
- **SC-012**: When flow records are re-delivered, 100% of qualifying windows produce exactly one extraction and zero duplicates.
- **SC-013**: 100% of decryption attempts by an identity holding only capture-read access are refused; 100% of successful decryptions appear in the ledger; zero key material appears in logs, status, metrics, or durable storage in audit scans.
- **SC-014**: Per-flow retrieval returns only packets belonging to the requested flow in 100% of tests, and every request is authorized and ledgered at flow granularity.
- **SC-015**: Every gate introduced by this program is demonstrated to execute and to fail when its condition is violated, with zero gates passing solely because they never ran.
- **SC-016**: The cumulative API changes are released as a single version promotion, with 100% of existing resources converting without manual manifest edits.
- **SC-017**: The first SSH profile verifies every Active claim by readback, leaves no mirror after deletion, and performs zero writes on host-key or capability refusal.
- **SC-018**: In pod replacement, address reuse, NAT, and conflicting-metadata tests, zero observations receive a wrong pod UID and unresolved endpoints report unknown or ambiguous.

## Assumptions

- The passive-only constraint, the truthful-status rule, the evidence-integrity model, and the executed-gate rule from the MVP carry forward unchanged and are not restated per workstream.
- Workstreams become separate feature directories; this specification governs their ordering and their shared constraints, not their internal design.
- The recommended sequence assumes the dependency graph is binding: the time model precedes the buffer, the buffer precedes late flow sources and flow-addressable retrieval, the storage interface revision precedes the second provider, and the device-contention rule precedes additional fabric providers.
- Cloud mirroring is independent of the rest of the graph and is pulled earlier under D-001 without disturbing the other orderings.
- Capture rate limiting and cooldown accounting are expected to run on ingestion time rather than occurrence time, because their purpose is bounding load on the cluster now. This is recorded as the working assumption for FR-008's decision and is subject to the ADR that settles it.
- The dedicated buffer writer is the expected outcome over reusing an analyzer's own packet logging, because the buffer becomes the system's evidence substrate rather than one analyzer's feature. Prototyping the analyzer-owned version first to learn the ergonomics is acceptable provided it is discarded.
- Whether an analyzer retains flow state across sequentially submitted stored files is unverified and materially affects the segment-boundary design. It is treated as unverified until tested.
- Storage providers beyond the MVP's are assumed to be the two major alternatives; a provider requiring a fundamentally different evidence model is out of scope.
- Detection latency for analysis over stored segments is bounded below by segment duration, and this is accepted rather than engineered away, because the live trigger path remains in place alongside the buffer.
- Key material is assumed to come from session secrets rather than server private keys; support for the latter is not assumed to be built.

### Dependencies

- The existing observation envelope, its compatibility rules, and the two current producers.
- The existing capture lifecycle, artifact storage, authorizing gateway, retention sweep, and write-once ledger, all reused rather than duplicated.
- The existing analyzer content model with pinned content versions, which supplies the attribution that makes comparison across versions meaningful.
- The existing storage abstraction and its conformance suite.
- The existing fabric provider abstraction and its revert discipline.
- The existing admission validation surface, which is where the kernel-bypass safety constraint and the mirror immutability rules are enforced.
- Node-local storage on sensor hosts sufficient for the configured buffer budget.
- Provider credentials and platform-issued workload identity for each cloud provider brought in scope.

## Resolved Decisions

These were the three open decisions in the source roadmap. Each is resolved
here; each changes something concrete downstream.

### D-001: Primary audience is a portfolio and conference artifact

The system must be impressive and explicable to people who have never seen it.
This resolves the relative ordering the roadmap deliberately hedged.

**Consequence**: the two workstreams that read as novel to an outside audience —
cloud packet mirroring (US7) and kernel-bypass capture (US6) — move ahead of the
continuous buffer (US3/US4) in the delivery sequence, despite the buffer being
the larger functional gap. Storage portability (US5) and flow-addressable
retrieval (US10) move later; neither demonstrates well and US10 was research-
gated regardless.

**Cost, recorded rather than hidden**: the roadmap sequenced kernel-bypass
capture after the buffer because the buffer is the fan-out point that lets both
analyzers share one capture path. Delivered earlier, kernel-bypass capture
benefits the signature analyzer only, and the second analyzer continues on the
existing path until the buffer exists. This is accepted, not solved.

### D-002: Acquire a traffic generator; the throughput criterion stands as written

The MVP's rate clause is verified rather than restated. The observed-byte
counter supplied half of what was missing; a generator that traverses the tapped
interface at the reference rate supplies the other half.

**Consequence**: acquiring and integrating the generator is a prerequisite of
US1, not a side task, and it becomes a standing acceptance dependency. It also
makes US6 demonstrable — an achieved-mode claim is only interesting next to a
throughput number that a generator produced.

### D-003: Mirrored volume is reported; monetary cost is not

Metered mirroring must be discoverable from the resource, so that a mirror
cannot generate spend invisibly.

**Consequence**: FR-041 stays in scope, expressed as observed mirrored volume.
The platform reports what it can truthfully know. It does not report a currency
figure, because pricing tiers, committed-use discounts and negotiated rates are
not visible to it, and a spend number it cannot stand behind is the same class of
untruthful state this program exists to eliminate.
