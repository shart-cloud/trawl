# Trawl CRD Contract (`trawl.cloud/v1alpha1`)

This contract is normative for the first served/stored API. Generated CRD YAML must
express every schema-representable rule below; admission webhooks enforce caller
identity, immutable fields, BPF validation staging, live references, and rules that
cannot be expressed structurally.

All resources are namespace-scoped and are accepted only in the installation-
configured system namespace (`trawl-system` by default). The validating webhook
rejects off-namespace resources; the manager cache and generated Roles watch only
that namespace.

## Shared conventions

- Durations use Go/Kubernetes duration strings such as `30s`, `5m`, or `30d`.
  The API parser explicitly supports `d` for whole days in retention values.
- Byte sizes use Kubernetes quantities such as `50Mi` or `1Gi`.
- References are same-namespace unless explicitly stated otherwise.
- Every status includes `observedGeneration` and `conditions` using Kubernetes
  `metav1.Condition` fields.
- Spec fields marked immutable reject update rather than silently restarting work.
- Unknown fields are pruned/rejected by the structural schema; public unions are
  closed.
- API enum wire values use PascalCase exactly as written below.

## NetworkTap

### Example

```yaml
apiVersion: trawl.cloud/v1alpha1
kind: NetworkTap
metadata:
  name: north-south-mirror
  namespace: trawl-system
spec:
  mode: Passive
  type: MirrorInterface
  mirrorInterface:
    interface: enp5s0
    promiscuous: true
    nodeSelector:
      matchLabels:
        kubernetes.io/hostname: talos-sensor-01
  analyzers:
    suricata:
      enabled: true
      resources:
        requests: {cpu: 500m, memory: 512Mi}
        limits: {cpu: "1", memory: 1Gi}
    zeek:
      enabled: true
      resources:
        requests: {cpu: 500m, memory: 512Mi}
        limits: {cpu: "1", memory: 1Gi}
```

### Spec

```text
NetworkTapSpec
├── mode: Passive                                      required, default Passive
├── type: MirrorInterface | NodeInterface              required
├── mirrorInterface?: InterfaceSource                  exactly one source branch
├── nodeInterface?: InterfaceSource                    exactly one source branch
└── analyzers: AnalyzerSelection                       required

InterfaceSource
├── interface: string                                  1..15 bytes, Linux name pattern
├── promiscuous: boolean                               default false
└── nodeSelector: metav1.LabelSelector                 required, non-empty

AnalyzerSelection
├── suricata: AnalyzerConfig
└── zeek: AnalyzerConfig

AnalyzerConfig
├── enabled: boolean                                   default false
├── resources?: corev1.ResourceRequirements            required when enabled
└── customContent?: CustomContentRef                   optional site-specific overlay

CustomContentRef
└── reference: string                                  OCI repository@sha256:<64 hex>
```

Cross-field rules:

1. `type=MirrorInterface` requires `mirrorInterface` and forbids `nodeInterface`.
2. `type=NodeInterface` requires `nodeInterface` and forbids `mirrorInterface`.
3. At least one analyzer is enabled.
4. Enabled analyzers have CPU/memory request and limit, with request <= limit.
5. A mirror selector resolves to exactly one eligible node before activation.
6. `mode`, source type, and interface are accepted only for passive observation;
   the generated workload cannot specify packet-path mutation.
7. `customContent.reference` must be digest-pinned; a tag is rejected (FR-042).

### Status

```text
NetworkTapStatus
├── observedGeneration: int64
├── phase: Pending | Active | Degraded | Error
├── matchedTargets: int32
├── readyTargets: int32
├── lastPacketTime?: metav1.Time
├── targets[]: TargetStatus                            map key: nodeName
└── conditions[]: metav1.Condition                    map key: type

TargetStatus
├── nodeName: string
├── interface: string
├── podRef?: LocalObjectReference
├── reporterInstance: string
├── heartbeatTime: metav1.Time
├── lastPacketTime?: metav1.Time
├── packetsObserved: int64
├── kernelDrops?: int64
├── duplication: Unknown | NotDetected | Suspected
├── rejectedRecords: int64
└── analyzers[]: AnalyzerStatus                        map key: name

AnalyzerStatus
├── name: Suricata | Zeek
├── healthy: boolean
├── version?: string
├── lastRecordTime?: metav1.Time
├── upstreamFetchedAt?: metav1.Time                    upstream content currency
├── customContentDigest?: string                       applied overlay digest
└── reason?: string                                    sanitized, <=256 bytes
```

Required condition types: `Accepted`, `TargetsResolved`, `WorkloadReady`,
`AnalyzersHealthy`, `PacketsObserved`.

## CapturePolicy

### Suricata example

```yaml
apiVersion: trawl.cloud/v1alpha1
kind: CapturePolicy
metadata:
  name: on-high-severity-alert
  namespace: trawl-system
spec:
  tapRef:
    name: north-south-mirror
  armed: true
  trigger:
    type: SuricataAlert
    suricataAlert:
      severities: [1, 2]
      categories: [trojan-activity, attempted-admin]
  capture:
    duration: 5m
    filterTemplate: "host {{source.ip}} and host {{destination.ip}}"
    snaplen: 0
    maxSize: 100Mi
  retention: 30d
  rateLimit:
    maxCapturesPerHour: 10
    cooldown: 1m
```

### Denied-flow example

```yaml
apiVersion: trawl.cloud/v1alpha1
kind: CapturePolicy
metadata:
  name: repeated-policy-denial
  namespace: trawl-system
spec:
  tapRef:
    name: cluster-nodes
  armed: true
  trigger:
    type: HubbleDrop
    hubbleDrop:
      reasons: [POLICY_DENIED]
      sourceNamespaces: [default, production]
      threshold:
        count: 5
        window: 1m
  capture:
    duration: 2m
    filterTemplate: "host {{source.ip}} and host {{destination.ip}}"
    snaplen: 0
    maxSize: 50Mi
  retention: 14d
  rateLimit:
    maxCapturesPerHour: 20
    cooldown: 30s
```

### Spec

```text
CapturePolicySpec
├── tapRef: LocalObjectReference                       required
├── armed: boolean                                     default false
├── trigger: Trigger                                   required, closed union
├── capture: CaptureBounds                             required
├── retention: duration                                1h..30d, default 30d
└── rateLimit: RateLimit                               required

Trigger
├── type: SuricataAlert | HubbleDrop
├── suricataAlert?: SuricataAlertTrigger               exactly one branch
└── hubbleDrop?: HubbleDropTrigger                     exactly one branch

SuricataAlertTrigger
├── severities[]: int32                                unique, 1..4, at least 1
├── ruleIDs[]?: uint32                                 unique, max 256
└── categories[]?: string                              unique, max 64 items/128 bytes each

HubbleDropTrigger
├── reasons[]: string                                  unique, 1..64 items
├── sourceNamespaces[]?: string                        unique, max 64
└── threshold?: Threshold

Threshold
├── count: int32                                       1..10000
└── window: duration                                   1s..15m

CaptureBounds
├── duration: duration                                 1s..1h
├── filterTemplate?: string                            max 1024 bytes
├── snaplen: int32                                     0 or 64..262144, default 0
└── maxSize: resource.Quantity                         1Mi..1Gi

RateLimit
├── maxCapturesPerHour: int32                          1..100
└── cooldown: duration                                 1s..1h
```

Allowed template placeholders are exactly:

- `{{source.ip}}`, `{{source.port}}`, `{{destination.ip}}`,
  `{{destination.port}}`, and `{{protocol}}` for both trigger types.
- `{{suricata.ruleID}}`, `{{suricata.severity}}`, and
  `{{suricata.category}}` for Suricata alerts.
- `{{hubble.dropReason}}`, `{{hubble.sourceNamespace}}`, and
  `{{hubble.destinationNamespace}}` for Hubble drops.

No functions, loops, conditions, nested templates, environment expansion, or raw
Go template expressions are accepted. Rendered output is parsed as BPF before a
capture socket opens.

### Status

```text
CapturePolicyStatus
├── observedGeneration: int64
├── phase: Disarmed | Armed | Degraded | RateLimited
├── resolvedTapUID?: types.UID
├── totalCaptures: int64
├── activeCaptures: int32
├── lastTriggerTime?: metav1.Time
├── lastCaptureRef?: LocalObjectReference
├── decisions:
│   ├── matched: int64
│   ├── notMatched: int64
│   ├── duplicate: int64
│   ├── rateLimited: int64
│   └── failed: int64
└── conditions[]: metav1.Condition
```

Required condition types: `Accepted`, `TapResolved`, `SourceConnected`,
`WithinRateLimit`, `Ready`.

## CaptureJob

### Manual example

```yaml
apiVersion: trawl.cloud/v1alpha1
kind: CaptureJob
metadata:
  generateName: manual-
  namespace: trawl-system
spec:
  requestType: Manual
  tapRef:
    name: north-south-mirror
  targetNode: talos-sensor-01
  filter: "host 10.0.0.50 and tcp port 443"
  duration: 2m
  snaplen: 0
  maxSize: 50Mi
  retention: 7d
```

### Operator-created shape

```yaml
apiVersion: trawl.cloud/v1alpha1
kind: CaptureJob
metadata:
  name: auto-7f9d2e8b5c-1724941800
  namespace: trawl-system
spec:
  requestType: Policy
  tapRef:
    name: north-south-mirror
  targetNode: talos-sensor-01
  filter: "host 10.0.0.50 and host 192.168.1.100"
  duration: 5m
  snaplen: 0
  maxSize: 100Mi
  retention: 30d
  policyRef:
    name: on-high-severity-alert
    uid: 6e4f5c85-4a55-4f10-9ccd-6bb937a5f855
    generation: 3
  trigger:
    source: SuricataAlert
    fingerprint: "sha256:8807e..."
    eventTime: "2026-08-29T19:30:20Z"
    observedAt: "2026-08-29T19:30:21Z"
    flow:
      sourceIP: 10.0.0.50
      sourcePort: 49832
      destinationIP: 192.168.1.100
      destinationPort: 443
      protocol: TCP
      communityID: "1:abc123"
    suricata:
      ruleID: 2024897
      revision: 4
      severity: 1
      category: trojan-activity
      message: "ET MALWARE family activity"
  deduplicationKey: "sha256:0b8f2..."
```

### Spec

```text
CaptureJobSpec                                      execution fields immutable after create
├── requestType: Manual | Policy                      default Manual
├── tapRef: LocalObjectReference                      required
├── targetNode?: string                               required for Manual
├── filter?: string                                   max 1024 bytes
├── duration: duration                                1s..1h
├── snaplen: int32                                    0 or 64..262144
├── maxSize: resource.Quantity                        1Mi..1Gi
├── retention: duration                               1h..30d, default 30d
├── policyRef?: ImmutablePolicyReference              Policy caller only
├── trigger?: TriggerSnapshot                         Policy caller only
└── deduplicationKey?: string                         Policy caller only, sha256 form
```

`Manual` forbids `policyRef`, `trigger`, and `deduplicationKey`. `Policy` requires
all three and is accepted only from the configured event-worker ServiceAccount.
An operator-created failed attempt may omit `targetNode` only when target
resolution itself failed. Users cannot set owner references to make evidence
garbage-collected with a policy.

Every field except `retention` rejects update. A retention update is accepted only
from the configured retention-administrator group, before the current deadline,
within 1h–30d, and only while phase is not `Expired`. It recomputes the deadline as
`completedAt + retention`, emits an audit record, and cannot change capture bytes,
artifact identity, bounds, policy, or trigger context.

### Status

```text
CaptureJobStatus
├── observedGeneration: int64
├── phase: Pending | Capturing | Storing | Completed | Failed | Expired
├── resolvedTapUID?: types.UID
├── resolvedInterface?: string
├── runnerJobRef?: LocalObjectReference
├── requestedAt: metav1.Time
├── startedAt?: metav1.Time
├── captureEndedAt?: metav1.Time
├── completedAt?: metav1.Time
├── packetCount?: int64
├── sizeBytes?: int64
├── sha256?: string
├── artifact?: ArtifactReference
├── retentionDeadline?: metav1.Time
├── failure?: CaptureFailure
├── runnerResult?: RunnerResult                        reporter-owned
└── conditions[]: metav1.Condition

ArtifactReference
├── profile: string                                    installation-controlled
├── key: string                                        opaque, controller-derived
├── etag?: string
├── versionID?: string
└── verifiedAt: metav1.Time

CaptureFailure
├── reason: FailureReason
├── message: string                                    sanitized, max 512 bytes
├── failedPhase: Pending | Capturing | Storing
└── attempts: int32

RunnerResult
├── outcome: Succeeded | Failed
├── reason?: FailureReason
├── stopReason?: Duration | Size | Cancelled | Error
├── packetCount?: int64
├── sizeBytes?: int64
├── sha256?: string
├── exitCode: int32
└── message?: string                                   sanitized, max 512 bytes
```

`runnerResult`, `resolvedInterface`, `startedAt`, `captureEndedAt` and the
`FilterValid` / `CaptureStarted` conditions are written by the reporter sidecar
through server-side apply as field owner `trawl-capture-reporter`. The controller
owns every other status field and derives the terminal phase from `runnerResult`
together with what it can verify in object storage; it never trusts the runner's
claim of success without the artifact.

The requester's authenticated username is stamped by the mutating webhook in the
`trawl.cloud/requester` annotation and cannot be changed afterwards.

Required condition types: `Accepted`, `TargetReady`, `FilterValid`,
`CaptureStarted`, `ArtifactVerified`, `Downloadable`, `RetentionEnforced`.

The capture reporter owns `startedAt`, `captureEndedAt`, `resolvedInterface`, and the
live capture conditions through server-side apply after validating atomic runner
progress records. The controller owns aggregate conditions, failure, artifact facts,
and terminal phase. The reporter Role permits patching only its owning CaptureJob
`/status` by `resourceNames`; the capture runner has no Kubernetes token.

## Authorization contract

Recommended aggregated roles use explicit resources and verbs, never wildcards:

| Role | NetworkTap | CapturePolicy | CaptureJob | `capturejobs/download` |
|---|---|---|---|---|
| Trawl viewer | get/list/watch | get/list/watch | none | none |
| Trawl analyst | get/list/watch | get/list/watch | create/get/list/watch | get |
| Trawl operator | all normal spec verbs | all normal spec verbs | create/get/list/watch | get |
| Trawl admin | above plus controlled delete/retention administration | above | update retention and delete under documented override | get |

Status subresource writes belong only to Trawl service accounts. Users never write
status. The artifact gateway checks `get` on the synthetic RBAC subresource
`capturejobs/download` with the requested namespace and resource name.

Grafana does not invoke the gateway directly in the MVP. It displays a non-secret
copyable `trawlctl capture download` command template; the CLI obtains a Kubernetes
bearer credential from a kubeconfig exec plugin or stdin and never places it in the
process arguments.

## Compatibility contract

- Generated CRDs set `served: true`, `storage: true` for `v1alpha1` and enable the
  status subresource.
- Additive optional fields require defaulting and round-trip tests against old
  stored fixtures.
- Existing enum wire values are never repurposed.
- A breaking field or lifecycle change introduces a new API version and conversion
  strategy before changing the storage version.
- Trawl releases declare the Kubernetes and Cilium/Hubble version matrix they were
  tested against.
