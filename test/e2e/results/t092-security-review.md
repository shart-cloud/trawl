# T092 review: CRD, namespace webhook, capture roles, samples and digest patch

Reviewed 2026-09-08 against the deployed cluster `admin@talos-cluster` (single
node `talos-node`, Kubernetes v1.35.5), running the build of `8814f68` —
controller-manager `sha256:e43e4cec…`, artifact-gateway `sha256:22267684…`,
event-worker `sha256:15af20a9…`.

**Unlike the other documents in this directory, every probe below was run by
hand.** No spec produced these figures. That is a deliberate limit and not a
convention this file is trying to change: T092 asks for a *review*, and T121
(`test/contract/security_manifests_test.go`) is the task that turns the static
half of it into assertions that re-run. What is recorded here is what a reader
would otherwise have to take on trust, plus the one trap that would have made
T121 pass while proving nothing — see "A probe that lies", below.

The generated half of T092 needs no argument: `make verify` reports
`verify-drift: no drift`, so the checked-in CRD, RBAC and webhook manifests are
what the generators produce from the current source.

## 1. The webhook rejects off-namespace CaptureJobs

The manual sample, rewritten only in its `metadata.namespace`, submitted twice
as a server-side dry run so admission really runs:

| namespace | result |
|---|---|
| `default` | `Error from server (Forbidden): admission webhook "vcapturejob.trawl.cloud" denied the request: trawl resources are accepted only in the "trawl-system" namespace; this resource targets "default"` |
| `trawl-system` | `capturejob.trawl.cloud/offns-probe created (server dry run)` |

The second row is the point of the test. A rejection on its own does not say
*why* something was rejected — the identical object differing in one field is
what makes the namespace the cause rather than a coincidence.

The gate is `Gate.CheckNamespace` (`internal/admission/server.go:75`), reached
from `ValidateCreate`, `ValidateUpdate` and `ValidateDelete`
(`internal/admission/capturejob_webhook.go:118,151,201`).

For that gate to mean anything the webhook has to see resources it intends to
refuse, so its own scope must not be narrowed to the namespace it enforces. The
live configuration confirms it is not:

| webhook | failurePolicy | namespaceSelector | objectSelector | rule scope |
|---|---|---|---|---|
| `vcapturejob.trawl.cloud` | `Fail` | `{}` | `{}` | `*` |
| `vnetworktap.trawl.cloud` | `Fail` | `{}` | `{}` | `*` |

Empty selectors and `Fail` together are what make this enforcement rather than
advice: a CaptureJob in any namespace is intercepted, and an unreachable webhook
refuses the write instead of waving it through.

## 2. The roles carry exactly the verbs their names promise

As the API server holds them:

| ClusterRole | resource | verbs |
|---|---|---|
| `trawl-capture-analyst` | `capturejobs` | create, get, list, watch |
| | `capturejobs/download` | get |
| | `networktaps` | get, list, watch |
| `trawl-capture-viewer` | `capturejobs`, `networktaps` | get, list, watch |
| `trawl-retention-admin` | `capturejobs` | get, list, watch, patch, update |

No wildcard appears in any verb, resource or apiGroup.

Effect, measured as `SubjectAccessReview` — the same question the gateway asks
before it serves bytes. Analyst and viewer went through their standing
acceptance bindings; retention-admin has no standing binding, so one was created
for the measurement and deleted immediately after (no `t092-retadmin` objects
remain).

| verb / resource | analyst | viewer | retention-admin |
|---|---|---|---|
| get `capturejobs` | ✅ | ✅ | ✅ |
| create `capturejobs` | ✅ | ❌ | ❌ |
| patch `capturejobs` | ❌ | ❌ | ✅ |
| update `capturejobs` | ❌ | ❌ | ✅ |
| delete `capturejobs` | ❌ | ❌ | ❌ |
| **get `capturejobs/download`** | **✅** | **❌** | ❌ |
| create `capturejobs/download` | ❌ | ❌ | ❌ |
| get `networktaps` | ✅ | ✅ | ❌ |

The bolded row is the whole reason the virtual subresource exists: the viewer
can see that a capture happened and cannot read the traffic it collected. Every
allowed cell was attributed by the API server to the expected binding and
ClusterRole by name.

`retention-admin` is deliberately necessary-but-not-sufficient. RBAC cannot say
"only `spec.retention`", so the role grants `patch`/`update` broadly and the
webhook narrows it — rejecting updates that touch other fields, updates after
the retention deadline, and subjects outside `capture.retentionAdminGroups`.
The table above is therefore the *upper* bound on what a retention admin can do,
not the effective one; the acceptance suite's `patchRetentionAsAdmin` exercises
the narrowing.

## 3. The invalid sample is rejected for the reason it claims

`config/samples/invalid/…_bad_filter.yaml` claims it is admitted, then fails
with `InvalidFilter` and `FilterValid=False`, producing no artifact and nothing
downloadable. The live `bad-filter` CaptureJob, from that sample:

```
spec.filter               host 10.0.0.50 and tcp prot 443
status.phase              Failed
status.failure.reason     InvalidFilter
status.failure.failedPhase Pending
status.artifact           (empty)
Accepted=True             reason=Accepted
FilterValid=False         reason=FilterInvalid
CaptureStarted=False      reason=CaptureFailed
ArtifactVerified=False    reason=ArtifactMissing
Downloadable=False        reason=NotDownloadable
```

Every clause of the claim holds, including the one the comment makes about
ordering: `failedPhase=Pending` with `CaptureStarted=False` is the observable
form of "the runner compiles the filter before any packet socket is opened".

Note the two similarly-named fields, which are both correct and easy to confuse:
`status.failure.reason` is the `FailureReason` enum value `InvalidFilter`, while
the `FilterValid` *condition* carries reason `FilterInvalid`
(`internal/status/conditions.go:105`). A review that reads conditions and
expects the enum spelling will conclude the sample is wrong when it is not.

## A probe that lies

`kubectl auth can-i <verb> capturejobs.trawl.cloud/download` **does not measure
the subresource**. It returns the answer for `capturejobs`, so it reports the
analyst as able to `create` the download subresource — which no role grants —
and reports the viewer as able to `get` it, which is the exact permission the
design exists to withhold.

This matters beyond this review. The download split is the security boundary
T121 is meant to defend, and `can-i` is the obvious way to assert it. Written
that way, T121 would pass against RBAC that had been flattened to let any viewer
download every capture. `SubjectAccessReview` with an explicit `subresource`
field, as used above, is the form that actually asks the question — and it is
also the form the gateway itself submits, so the test would then be checking the
real code path rather than a lookalike.
