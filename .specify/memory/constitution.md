<!--
Sync Impact Report
- Version change: template scaffold -> 1.0.0
- Modified principles:
  - Template principle 1 -> I. Passive and Fail-Open
  - Template principle 2 -> II. Declarative Control and Truthful State
  - Template principle 3 -> III. Evidence Integrity and Least Privilege
  - Template principle 4 -> IV. Observable and Correlatable by Design
  - Template principle 5 -> V. Verification at Every Boundary
- Added principles:
  - VI. Small, Phased, Reversible Delivery
- Added sections:
  - Platform and Security Constraints
  - Development Workflow and Quality Gates
- Removed sections: None
- Follow-up TODOs: None
-->

# Trawl Constitution

## Core Principles

### I. Passive and Fail-Open

Monitoring and capture capabilities MUST NOT modify, block, delay, or redirect observed traffic.
A failed sensor, analyzer, controller, storage service, or policy evaluator MUST fail open with
respect to the monitored network. Passive capture privileges MUST never be reused for traffic
enforcement. Inline prevention requires a separate approved specification, explicit blast-radius
controls, a tested global kill switch, and an amendment or compatibility review against this
principle.

Rationale: visibility must not become an availability risk to the homelab or the workloads being
studied.

### II. Declarative Control and Truthful State

User-managed configuration MUST be expressed as versioned, declarative cluster resources with
validated desired state and observable status. Reconciliation MUST be idempotent, safe to retry,
and converge after restarts or dependency recovery. Status MUST describe observed reality rather
than echo desired configuration; a resource MUST NOT report `Active` or `Completed` until the
corresponding capability or artifact is verifiably available. Controllers MUST modify only objects
they own and MUST make ownership and cleanup behavior explicit.

Rationale: declarative operation is the product's primary interface and is essential on an
immutable operating system where imperative host repair is unavailable.

### III. Evidence Integrity and Least Privilege

Packet captures, extracted metadata, credentials, private keys, and investigation context MUST be
treated according to their sensitivity. Access to configuration, privileged capture, secrets,
artifact enumeration, artifact download, and retention changes MUST be explicitly authorized and
limited to the narrowest practical scope. Capture records MUST preserve immutable trigger context,
timestamps, bounds, origin, integrity metadata, and a truthful lifecycle. Security-sensitive
actions MUST be auditable. Secrets and packet payloads MUST NOT appear in logs, status fields,
metrics, or error messages. Retention MUST be bounded and enforced.

Rationale: network evidence can contain credentials and personal or application data; convenient
collection cannot take precedence over confidentiality, provenance, or accountable handling.

### IV. Observable and Correlatable by Design

Every long-running component and reconciliation path MUST expose health, actionable conditions,
structured logs, and relevant metrics. Data loss, packet loss when measurable, malformed records,
trigger suppression, rate limiting, and storage or retention failures MUST be visible. Related
observations from different analysis sources MUST use a common standardized flow-correlation value
when one can be derived, while retaining original timestamps and traffic attributes for fallback
correlation. High-cardinality values such as addresses, ports, unique flow identifiers, and packet
references MUST remain structured fields rather than unbounded index labels.

Rationale: the platform exists to support investigations; silent gaps and uncorrelatable evidence
directly defeat that purpose.

### V. Verification at Every Boundary

Every behavior change MUST include automated verification proportional to its risk. Pure logic and
policy matching require deterministic unit tests. Resource schemas and reconciliation require
contract or control-plane integration tests. Analyzer ingestion, flow-event handling, capture,
artifact storage, authorization, restart recovery, and retention require tests across their actual
process or service boundaries. Every bug fix MUST add a regression test that fails without the fix.
Release candidates MUST pass an end-to-end exercise on a representative cluster and MUST verify
the measurable outcomes in the active feature specification. Failing or skipped required checks
block release.

Rationale: correctness depends on kernel networking, cluster reconciliation, external telemetry,
and storage boundaries that cannot be established by isolated mocks alone.

### VI. Small, Phased, Reversible Delivery

Work MUST be delivered as the smallest independently testable vertical slice that provides user
value. Features explicitly deferred by an active specification MUST NOT enter implementation
through incidental scaffolding or speculative abstractions. New components, stores, controllers,
and privilege grants require a demonstrated current need. Changes to resource contracts, stored
evidence, or deployment behavior MUST define upgrade, rollback, and cleanup behavior before
implementation. Existing platform capabilities MUST be reused when they meet the requirement.

Rationale: phased delivery limits operational risk and keeps a homelab-scale learning platform
understandable, maintainable, and recoverable.

## Platform and Security Constraints

- The deployment target is Talos Linux on Kubernetes. Application behavior MUST run in managed
  workloads; designs MUST NOT depend on SSH, interactive host shells, host package installation,
  or mutable host configuration.
- The approved baseline uses Cilium and Hubble for cluster networking and flow context, Suricata
  for signature detection, Zeek for protocol metadata, Grafana Alloy and Loki for log transport
  and storage, Grafana for investigation views, and MinIO-compatible object storage for packet
  artifacts. Replacing or duplicating a baseline capability requires an architecture decision
  record that documents the gap, migration, and operational cost.
- Operator and controller code MUST use Go and established Kubernetes controller patterns.
  User-facing APIs MUST remain versioned, schema-validated, and backward compatible within an API
  version. Breaking changes require a new API version and a documented migration path.
- Privileged workloads MUST be isolated to a dedicated namespace and eligible targets. They MUST
  request only the host access and Linux capabilities needed for the declared capture mode, apply
  resource limits, and expose why each privilege is required.
- Deployable images MUST use reviewed, immutable versions or digests. Floating tags such as
  `latest` MUST NOT appear in release manifests.
- Packet captures MUST always have duration and size bounds. Automatic capture MUST also have
  cooldown, deduplication, rate-limit, and retention bounds.
- Credentials and private keys MUST come from the cluster's secret-management boundary, MUST NOT
  be embedded in images or configuration examples, and MUST be readable only by the workload and
  namespace that require them.
- Telemetry labels MUST remain low-cardinality. Addresses, ports, rule identifiers, unique flow
  values, and other unbounded attributes MUST be stored as structured metadata or record fields.
- Homelab scale does not waive correctness. Resource exhaustion, full storage, unavailable
  dependencies, malformed events, and component restarts MUST produce bounded behavior and
  truthful status.

## Development Workflow and Quality Gates

1. Every feature MUST begin with a Spec Kit specification containing prioritized, independently
   testable user scenarios, explicit scope, testable requirements, edge cases, and measurable
   outcomes. Unresolved material ambiguity MUST be clarified before planning.
2. Every technical plan MUST include a Constitution Check that maps the design to each applicable
   principle and constraint. A proposed exception MUST be documented before tasks are generated.
3. Tasks MUST trace to a requirement or enabling quality gate and MUST preserve a usable vertical
   slice at each milestone. Architecture-only scaffolding without a near-term consumer is not an
   acceptable milestone.
4. Changes to resource schemas, permissions, privileged workloads, capture filters, artifact
   access, or retention MUST receive an explicit security review. Changes affecting packet paths
   MUST demonstrate passive, fail-open behavior.
5. Required verification MUST include formatting and static checks, unit tests, schema and
   reconciliation tests, relevant service-boundary integration tests, and end-to-end tests for the
   affected user scenario. Performance-sensitive changes MUST be measured at the reference load.
6. Generated manifests, checked-in schemas, examples, dashboards, and user documentation MUST
   agree with the implemented contract. Generation or validation drift blocks merge.
7. Significant or difficult-to-reverse technical choices MUST be recorded in an architecture
   decision record with context, decision, alternatives, consequences, and rollback implications.
8. A release is eligible only when all mandatory checks pass, no unresolved critical security
   finding remains, operational failure modes are documented, and the active specification's
   acceptance scenarios have evidence of completion.

## Governance

This constitution is the highest project-level engineering authority. Feature specifications,
plans, tasks, architecture decisions, and reviews MAY impose stricter rules but MUST NOT weaken or
bypass it.

Amendments require a documented proposal containing the rationale, affected principles and
artifacts, compatibility impact, and any migration or rollback plan. The project maintainer MUST
approve an amendment before dependent implementation is merged. Amendments take effect when this
document's version and amendment date are updated.

Constitution versions follow semantic versioning:

- **MAJOR**: removes a principle, weakens or incompatibly redefines governance, or permits behavior
  previously prohibited.
- **MINOR**: adds a principle or materially expands mandatory governance or quality gates.
- **PATCH**: clarifies wording without changing required behavior.

Every specification and plan review MUST verify constitutional compliance. Every implementation
review MUST cite evidence for applicable quality gates. A temporary exception requires written
scope, rationale, compensating controls, owner, and expiry date; expired exceptions block further
release until removed or ratified as an amendment. Compliance is re-evaluated whenever scope,
privileges, resource contracts, or data handling changes.

**Version**: 1.0.0 | **Ratified**: 2026-08-29 | **Last Amended**: 2026-08-29
