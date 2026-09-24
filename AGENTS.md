# Trawl — guide for AI agents

Trawl is a Kubernetes operator for passive network security monitoring. You
declare where to watch with a custom resource; it renders Suricata and Zeek
sensors onto the nodes, normalizes what they see into one record shape, and can
capture the packets around a detection and hand them to an authorized analyst
later. It targets Talos, where there is no SSH and no package manager, so every
tool runs in a pod and every change is a resource.

Module `trawl.cloud/trawl`, Go 1.26.7, API group `trawl.cloud/v1alpha1`,
kubebuilder layout, **not** multigroup.

This file is about working in this repository. The rationale for the design is
in the ADRs under `docs/src/content/docs/adr/`, and the interfaces other things
depend on are in `specs/001-cloud-native-nsm/contracts/`. Both are cited by
identifier throughout the code, and those citations are accurate; follow them.

## The one thing to understand first

**The project's subject is truthful status, and its tests are held to the same
standard as its code.** A `NetworkTap` reporting `Active` is a claim that
traffic is being analyzed. A `CapturePolicy` reporting `Armed` is a claim that
detection coverage exists. Someone reads those months later during an incident
and believes them.

Two consequences shape almost every decision here:

- **A skip is worse than a failure, because it looks like coverage.** The
  sentence is in the Makefile, above the line that makes `make test` depend on
  `kustomize`; the same argument is made in different words in
  `test/contract/generated_artifacts_test.go`, where a missing binary once
  turned six rendered-manifest checks into a no-op behind a green job. If you
  are about to write `t.Skip`, be certain you are saying *not applicable* and
  not *could not check*.
- **Absence of evidence is not evidence of health.** Missing conditions count as
  stale, nil counters mean unmeasured rather than zero, and a lookup failure
  maps to "I could not look" rather than "there is nothing there". Several
  fields are pointers purely to preserve that distinction.

The governing document is `.specify/memory/constitution.md`, six principles.
The Makefile, the workflows and the commit log appeal to it by name, and Go
sources and `.golangci.yml` cite individual principles by number. The first is
the other load-bearing one: **passive and fail-open for traffic, fail-closed for
privileged operations.** Trawl must never affect the traffic it watches, but a
capture whose authorization could not be written to the ledger does not happen.

## Layout

```
api/v1alpha1/*_types.go       four CRDs; kubebuilder + CEL markers
cmd/<binary>/main.go          eight binaries; there is no cmd/main.go
internal/                     all logic; see the table below
config/                       kustomize; sixteen directories, not the scaffold's five
images/<name>/Containerfile   analyzer and helper images, most with a SOURCES.lock
hack/                         verification scripts and tools.mk (tool pins)
security/                     gitleaks.toml, suppressions.yaml
specs/                        Spec Kit features; contracts/ lives under 001
docs/                         Astro + Starlight site, published at trawl.cloud
test/                         contract, integration, e2e
```

`internal/webhook/` does not exist. Admission lives in **`internal/admission/`**.

`config/` holds sixteen kustomize directories, not the five a kubebuilder
project starts with: alloy, audit, certmanager, crd, default, dev, gateway,
grafana, hubble, manager, namespace, networkpolicy, prometheus, rbac, samples,
webhook. The ones carrying real decisions are `networkpolicy/` (default-deny,
plus a policy per component), `audit/`, `gateway/`, `alloy/` and `grafana/`.

| package | what it holds |
|---|---|
| `admission` | a webhook per kind, and the shared namespace and audit gate |
| `controller` | five controllers, plus the policy engine and status tracker that run **elsewhere** |
| `capture` | the CaptureJob lifecycle as a pure function, bounds, filters, the runner |
| `policy` | trigger matching, dedup keys, rate limits, BPF templating — all pure |
| `observation` | the normalized envelope, its JSON Schema, correlation, parsers |
| `audit` | the write-once ledger: sink, mTLS client and server, replayer, cursor |
| `storage` | the `Store` interface over one bucket, presigning, conformance suite |
| `authz` | TokenReview and SubjectAccessReview; holds no policy of its own |
| `gateway` | the artifact download handler, rate limiters, the `trawlctl` transport |
| `sensor` | log tailing, the packet meter, duplicate marking, status reporting |
| `content` | analyzer rule layers: upstream fetch, custom overlay, merge |
| `fabric` | PortMirror drivers: RouterOS REST in `fabric/mikrotik`, reviewed RouterOS SSH profile in `fabric/mikrotikssh`, shared pinned-key transport in `fabric/sshtransport` |
| `events` | Hubble flow streaming and Loki alert polling |
| `witness` | the lease that lets the manager speak for a dead event worker |
| `status` | condition types and the closed reason enum |
| `telemetry`, `sanitize`, `tlsutil`, `config` | metrics contract, redaction, cert reload, install config |

## The four resources

**NetworkTap** is one observation point: an interface to watch and which
analyzers to run on it. A mirror source renders a single-replica Deployment with
the `Recreate` strategy, because two pods cannot hold one mirror interface in
promiscuous mode without duplicating every observation. A node source renders a
DaemonSet with `maxUnavailable: 1`, because a rollout must not blind the whole
cluster at once.

**CapturePolicy** arms one trigger against one tap, with bounded capture
behavior. `spec.armed` defaults to **false**: creating a policy is not the same
act as switching it on, and the two are audited separately.

**CaptureJob** is one bounded capture and its verified artifact. Policy-created
jobs carry an immutable snapshot of the trigger that caused them.

**PortMirror** is the only resource that writes to hardware outside the cluster.
Its status reports what the device says, never what was asked for.

Three relationships are deliberate and easy to get wrong:

- A CapturePolicy has **no ownerReference** over the CaptureJobs it creates.
  Deleting a policy must never garbage-collect the packets it collected.
- PortMirror has **no API reference** to NetworkTap. The coupling is physical.
  Keeping them separate keeps mirroring separately authorizable and puts the
  device's failures outside the tap's.
- CaptureJob and CapturePolicy each pin the **UID** of the tap they resolved by
  name, in `status.resolvedTapUID`, and every generated resource name derives
  from the owner's UID rather than its name. A tap deleted and recreated under
  the same name is a different tap and must not inherit the old one's workload,
  observations or status history. PortMirror's `deviceRef` is an ordinary
  by-name Secret reference and pins nothing.

## Which process runs what

This trips people up, so check before assuming.

`PolicyEngine` and `PolicyStatusTracker` live in `internal/controller/` but do
**not** run in the controller manager. They run in the event worker. Only these
run in the manager: the NetworkTap, CaptureJob, CapturePolicy, PortMirror and
retention controllers, the webhooks, the audit sink server and the audit
replayer.

The manager's CapturePolicy reconciler is **the witness**, registered as
`capturepolicy-witness`. It does not reconcile policies in the ordinary sense
and writes nothing at all while the event worker is alive. It reads the worker's
lease, and when that goes stale it speaks for every armed policy the dead worker
owned. Ordinary policy evaluation is in `capturepolicy_engine.go`, running in
the other process.

The split is not cosmetic. The manager is the **only** process holding audit
ledger credentials, so everything else commits through an mTLS sink. The event
worker is leader-elected because two workers would create two captures for one
event. The gateway is deliberately **not** leader-elected, because every request
is decided from live state and nothing about it is a singleton.

Retention is a second controller over CaptureJob, named separately because
controller-runtime refuses duplicate names. It exists apart from the main one
because it answers a different question on a different clock, and a bucket that
will not accept a delete must not block a capture in progress.

## Privilege

Exactly two things hold capabilities, and in both cases the split is the same:
**the container with privilege holds no API token, and the container with the
token holds no privilege.**

Analyzer containers get `NET_RAW` and `NET_ADMIN`, everything else dropped, and
`privileged: false` is set explicitly on every container — it would grant every
capability and the ability to load kernel modules in order to obtain two. Beside them the sensor sidecar runs
fully restricted and holds the pod's only token, projected into that container
alone. The capture runner holds the capture capabilities and receives its whole
job as flags so it cannot be pointed at a different object; its bucket
credential is a file mount, never an environment variable, so it cannot be read
out of the pod spec. Beside it the reporter is a native sidecar whose token is
scoped by `resourceNames` to one CaptureJob's status subresource.

RBAC for generated workloads is scoped by `resourceNames` to the single object
concerned. A sensor sits next to a container with `NET_RAW` on the host network;
an unscoped grant would let a compromised pod report healthy monitoring for the
whole cluster.

Pods use `hostNetwork` because the interface belongs to the host. Nothing else
is shared: no host PID, IPC or filesystem. The system namespace is the only one
labelled for privileged pod security, which is why Trawl reconciles its
resources in exactly one namespace and why the webhooks enforce that.

## Admission, and what cannot live there

All four kinds have a validating webhook; three of them also have a mutating
one. PortMirror deliberately has no mutating webhook, because its only default
is structural and the API server applies it while decoding, so one would have
nothing to do and would add a second `failurePolicy: Fail` call to every write.
The mutating path is easy to forget and is where the authenticated requester is
stamped onto the object.

The webhooks own three things that are security boundaries rather than
conveniences: namespace confinement, the durable-audit gate that commits a
record *before* a mutation is admitted and rejects when the ledger is
unavailable, and identity taken from the API server's user info rather than from
the object. All three use `failurePolicy: fail`, because an `Ignore` policy
would make causing an outage a way around the gates.

Admission is **not trusted as the only enforcement**. CEL runs on write, so an
object restored straight into etcd or written before a rule existed arrives
unchecked. That is why all four `Validate<Kind>Spec` functions are exported and
re-run inside their reconcilers, and why the reconcilers re-check the namespace
themselves.

Some questions cannot be asked at admission at all. Whether two resources
contend depends on what else is stored at the moment they are compared, and a
webhook sees one object; a pair created concurrently would both pass and both be
wrong. Contention is therefore settled at reconcile time, by one rule shared
between the probe-port and device checks: **the younger claim yields.** The
incumbent keeps the port or the device and keeps observing, so contention can
never take down something already running, and ties break on UID so both sides
reach the same answer independently.

PortMirror's webhook is the newest and carries two rules the others do not.
`spec.deviceRef` and `spec.provider` are immutable, because the revert finalizer
resolves `deviceRef` at deletion time: repointing a live mirror at another device
configures the new one and abandons the old one still mirroring, on hardware no
`kubectl get` will ever show. Its API mutations also get their own audit actions,
separate from the device ones, so that somebody asking for a mirror and the
switch actually being reconfigured stay distinguishable in the ledger.

## Adding or changing a reason

Condition reasons are a closed enum in `internal/status/conditions.go`,
PascalCase, no separators, 64 bytes or fewer. They are consumed as
low-cardinality metric and dashboard dimensions, so a free-form reason is a
cardinality bug and a broken alert at once.

`AllReasons()` is a hand-maintained list of every reason value. **A new constant
must be added there too.** Both tests that enforce this are in
`internal/status/conditions_test.go`, not in `test/contract/`: one walks the list
checking the shape rules, and the other parses `conditions.go` with `go/ast` and
fails when a declared constant is missing from the list. That test exists because every PortMirror reason was
absent from it from the day the fabric work landed, so six reasons went
unverified while the shape test passed.

## Build, test, lint

```
make build          # bin/manager from ./cmd/controller-manager
make manifests      # CRDs, RBAC, webhook manifests from markers
make generate       # DeepCopy methods
make test           # unit + contract + envtest, excludes e2e
make test-race      # internal/, api/, cmd/ only — not test/
make test-integration
make lint           # three passes; see below
make lint-config    # validate .golangci.yml itself
make verify         # tool pins, fmt, vet, generated-artifact drift
make security       # manifest privilege, suppressions, govulncheck — also
                    # installs pinned tools as a side effect
make help           # every target, with the reasoning attached
```

Run `make manifests generate` after touching `*_types.go` or any marker, and
`make lint-fix && make test` after touching Go. `make verify` is what catches
generated output that no longer matches its source; CI runs it as a job called
**Generated-artifact drift**.

`make lint` runs golangci-lint **three times** — untagged, then with
`investigation`, then with `acceptance`. golangci-lint builds one configuration
at a time, so each build tag needs its own pass or the tagged suites rot
unlinted. The binary is custom-built from `.custom-gcl.yml` with the logcheck
plugin, so use `make lint` rather than a system golangci-lint.

Tests are **plain `go test`**. There is no Ginkgo or Gomega anywhere, despite
`ginkgolinter` being enabled. Test names are full sentences:
`TestAShortenedRetentionIsEnforcedAndNotMerelyRecorded`. Follow that.

`test/contract` asserts generated artifacts, rendered manifests, the telemetry
contract and the observation schema. `test/integration` uses envtest and real
containers. `test/e2e` is build-tagged `acceptance` or `investigation`, excluded
from `make test`, and needs a real cluster with Trawl deployed. The targets are
`make test-acceptance` and `make test-investigation`; several specs are further
gated behind `TRAWL_E2E_*` environment variables that opt into destructive or
slow scenarios. These are run by a person who typed the target, and
`test/e2e/results/` holds the written-up evidence from those runs.

`.golangci.yml` encodes four **import boundaries** with depguard, and you will
meet them:

- `internal/policy/**`, `internal/observation/**`, and exactly `bounds.go`,
  `filter.go`, `manifest.go` and `state.go` in `internal/capture` may not import
  controller-runtime or client-go. They decide things as pure functions of their
  inputs, so a decision can be reproduced from the record that produced it. Do
  not reach for a client to make one of them easier to write.
- `cmd/capture-runner/**` may not import either. That one is a privilege
  control, not a design preference: the runner holds capture capabilities and
  must not also be able to talk to the API server.
- Nothing under `internal/` or `cmd/` may use the standard library `log` or
  logrus. Logging is structured, everywhere.
- `sort` is banned in favour of `slices`.

## Never edit by hand

`config/crd/bases/*.yaml`, `config/rbac/role.yaml`, `config/webhook/manifests.yaml`,
`**/zz_generated.*.go`, `PROJECT`. Regenerate them. Do not delete
`// +kubebuilder:scaffold:*` markers. Tool versions are pinned in
`hack/tools.mk` and verified by a CI job; change them there, not ad hoc.

The docs site has one generated page: `docs/src/content/docs/quickstart.md` is
rendered from `specs/001-cloud-native-nsm/quickstart.md` by
`docs/scripts/sync-content.mjs` at build time, and is gitignored. Edit the spec.

## Workflow and conventions

The documented process is **Spec Kit**: `/speckit.specify`, `.plan`, `.tasks`,
`.implement`. The command definitions are in `.speckit/commands/`; the
templates, the constitution and the workflow registry are in `.specify/`; the
features themselves are under `specs/`. Task identifiers like `T125` come from
`specs/001-cloud-native-nsm/tasks.md` and appear as commit prefixes when a
commit implements one.

`docs/` has its own `AGENTS.md` and `CLAUDE.md` covering the Astro site. Read
them before working in there.

Commit subjects are full sentences that name the **reason**, not the change, and
there is no Conventional Commits prefix:

```
A device has one mirror target, so only one PortMirror may hold it
An external witness, so a dead worker cannot leave a policy Armed
Six contract tests had never run in CI
```

Bodies are multi-paragraph prose: what was wrong, why it mattered, what was
considered and rejected, what the change turned up on the way, and — when the
commit fixes a bug — an explicit statement that the test was run against the
unfixed code first. Comments in the source follow the same standard. This
codebase explains *why* in prose above the code, at length, and records the
incident that motivated a defensive choice. Match it. A comment here is expected
to survive being read by someone who was not there.

Do not write a comment describing a control that does not exist. One claiming
PortMirror had an admission webhook survived until someone checked.

## Traps

- `internal/webhook/` and `cmd/main.go` do not exist. Both appear in kubebuilder
  documentation and in this file's previous version.
- Reaching for a Kubernetes client inside `internal/policy` or
  `internal/observation` will fail lint, by design.
- Adding a condition reason without adding it to `AllReasons()` will fail a test
  that parses the source.
- `List` in the storage interface is inclusive of `startAt`, unlike S3's own
  `start-after`. That divergence went unnoticed for the life of the project
  because nothing asked both implementations the same question, which is what
  `storage/storagetest` now does.
- Rate limits compare with `>=`: once the maximum exists, the next request is
  the one over the line.
- A presigned URL is a bearer credential that cannot be revoked. The TTL clamps
  down, never up.
- Two counters from different points in Suricata's pipeline are not comparable,
  and bytes come only from the decoder. Read byte counts against kernel drops,
  never alone.
