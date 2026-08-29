# Trawl — Architecture Design

## Cloud-Native Network Security Monitoring for Kubernetes

> **trawl.cloud** — A Kubernetes-native network security monitoring operator
> built for Talos Linux, designed to bring Zeek, Suricata, and event-driven
> packet capture into the cloud-native ecosystem with CRD-based orchestration.

---

## Problem Statement

SEC503 teaches network monitoring and threat detection using Zeek and Suricata
against full packet captures. No existing platform brings these tools into
Kubernetes as first-class citizens with declarative, event-driven orchestration.
Security Onion doesn't run on K8s. EDCOP was a prototype that never matured.
Corelight's approach requires their commercial sensors. We need to build the
missing piece — a CRD-driven operator for Kubernetes.

## Constraints

| Constraint | Implication |
|---|---|
| **Talos Linux** | Immutable OS. No SSH, no shell, no package manager. Every tool must run in a pod. |
| **Cilium CNI + Hubble** | Already deployed. Provides eBPF flow visibility, policy enforcement, DNS/HTTP observability. |
| **Loki + Grafana** | Log storage and visualization. Not Elasticsearch — all pipelines target Loki via Alloy. |
| **MikroTik CRS switch** | Can mirror physical switch ports for north-south and inter-VLAN visibility. |
| **UniFi router** | Edge routing. Limited mirror capabilities but provides flow data. |
| **Homelab scale** | Not a 10Gbps production firehose. Capture everything, store selectively. |

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        PHYSICAL NETWORK                             │
│                                                                     │
│  UniFi Router ──── MikroTik CRS ──── Talos Nodes                   │
│                         │                                           │
│                    Port Mirror                                      │
│                    (SPAN to dedicated NIC                            │
│                     on sensor node)                                  │
└─────────────────────┬───────────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────────────┐
│                     CAPTURE PLANE                                   │
│                                                                     │
│  ┌──────────────────────┐   ┌──────────────────────────────┐        │
│  │  Mirror Receiver Pod │   │  Sensor DaemonSet            │        │
│  │  (dedicated node,    │   │  (every node, hostNetwork,   │        │
│  │   promisc on mirror  │   │   AF_PACKET on veth/overlay) │        │
│  │   NIC)               │   │                              │        │
│  └──────────┬───────────┘   └──────────────┬───────────────┘        │
│             │                              │                        │
│             └──────────┬───────────────────┘                        │
│                        │  raw packets                               │
│                        ▼                                            │
│  ┌─────────────────────────────────────────────────────────┐        │
│  │              ANALYSIS PLANE                             │        │
│  │                                                         │        │
│  │  ┌─────────────┐    ┌──────────────┐                    │        │
│  │  │  Suricata    │    │  Zeek        │                    │        │
│  │  │  DaemonSet   │    │  DaemonSet   │                    │        │
│  │  │              │    │              │                    │        │
│  │  │  • IDS rules │    │  • conn.log  │                    │        │
│  │  │  • EVE JSON  │    │  • dns.log   │                    │        │
│  │  │  • pcap-log  │    │  • http.log  │                    │        │
│  │  │    (cond.)   │    │  • ssl.log   │                    │        │
│  │  │              │    │  • files.log │                    │        │
│  │  └──────┬───────┘    └──────┬───────┘                    │        │
│  │         │                   │                            │        │
│  └─────────┼───────────────────┼────────────────────────────┘        │
│            │                   │                                     │
└────────────┼───────────────────┼─────────────────────────────────────┘
             │                   │
┌────────────▼───────────────────▼─────────────────────────────────────┐
│                     OBSERVABILITY PLANE                               │
│                                                                       │
│  ┌───────────────┐                                                    │
│  │ Grafana Alloy │ ◄── scrapes Suricata EVE JSON                      │
│  │ (DaemonSet)   │ ◄── scrapes Zeek JSON logs                         │
│  │               │ ◄── receives Hubble flow exports                    │
│  └───────┬───────┘                                                    │
│          │                                                            │
│          ▼                                                            │
│  ┌───────────────┐    ┌───────────────┐    ┌───────────────┐          │
│  │     Loki      │    │    MinIO       │    │   Grafana     │          │
│  │               │    │               │    │               │          │
│  │  • alert logs │    │  • pcap files │    │  • dashboards │          │
│  │  • conn logs  │    │  • forensic   │    │  • alerting   │          │
│  │  • dns logs   │    │    captures   │    │  • explore    │          │
│  │  • flow data  │    │               │    │               │          │
│  └───────────────┘    └───────────────┘    └───────────────┘          │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────────────────┐
│                     CONTROL PLANE (THE OPERATOR)                      │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────┐     │
│  │                    Trawl Operator                             │     │
│  │                                                               │     │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │     │
│  │  │ Tap          │  │ Capture      │  │ Hubble       │        │     │
│  │  │ Controller   │  │ Controller   │  │ Watcher      │        │     │
│  │  │              │  │              │  │              │        │     │
│  │  │ Reconciles   │  │ Watches for  │  │ gRPC client  │        │     │
│  │  │ NetworkTap   │  │ triggers,    │  │ to Hubble    │        │     │
│  │  │ CRs, manages │  │ creates      │  │ Relay,       │        │     │
│  │  │ DaemonSets   │  │ capture      │  │ emits events │        │     │
│  │  │ and sensor   │  │ jobs         │  │ on policy    │        │     │
│  │  │ pods         │  │              │  │ drops, etc.  │        │     │
│  │  └──────────────┘  └──────────────┘  └──────────────┘        │     │
│  │                                                               │     │
│  │  ┌──────────────┐  ┌──────────────┐                           │     │
│  │  │ Alert        │  │ PCAP         │                           │     │
│  │  │ Watcher      │  │ Manager      │                           │     │
│  │  │              │  │              │                           │     │
│  │  │ Watches EVE  │  │ Manages pcap │                           │     │
│  │  │ JSON for     │  │ lifecycle:   │                           │     │
│  │  │ Suricata     │  │ create,      │                           │     │
│  │  │ alerts,      │  │ upload to    │                           │     │
│  │  │ triggers     │  │ MinIO, TTL,  │                           │     │
│  │  │ captures     │  │ cleanup      │                           │     │
│  │  └──────────────┘  └──────────────┘                           │     │
│  │                                                               │     │
│  └──────────────────────────────────────────────────────────────┘     │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

---

## Custom Resource Definitions

The MVP serves namespaced CRDs cluster-wide for normal Kubernetes discovery but
accepts and reconciles them only in the configured system namespace
(`trawl-system` by default). Admission rejects off-namespace resources so privileged
sensor or capture workloads cannot escape that boundary.

### 1. NetworkTap

Defines a traffic source — where to capture from.

```yaml
apiVersion: trawl.cloud/v1alpha1
kind: NetworkTap
metadata:
  name: north-south-mirror
  namespace: trawl-system
spec:
  # Type of tap source
  type: mirror-interface   # mirror-interface | node-interface | pod-selector

  # Passive (IDS) or inline (IPS). IPS requires Phase 5.
  mode: passive            # passive | inline

  # --- mirror-interface: physical port mirror from MikroTik ---
  mirrorInterface:
    interface: enp5s0        # NIC receiving mirrored traffic
    promiscuous: true
    nodeSelector:
      kubernetes.io/hostname: talos-sensor-01

  # --- node-interface: capture on every node's primary NIC ---
  # nodeInterface:
  #   interface: eth0
  #   promiscuous: false     # listen on existing traffic only

  # --- pod-selector: sidecar injection for targeted pod capture ---
  # podSelector:
  #   namespaceSelector:
  #     matchLabels:
  #       trawl.cloud/monitor: "true"
  #   podSelector:
  #     matchLabels:
  #       app: target-workload

  # TLS decryption via K8s Secrets (Phase 4)
  # tlsDecryption:
  #   enabled: true
  #   secrets:
  #     - namespace: ingress
  #       name: wildcard-tls
  #     - namespace: default
  #       name: app-tls

  # Which analyzers process this tap's traffic
  analyzers:
    - name: suricata
      enabled: true
      rulesets:
        - et-open
        - custom-k8s
    - name: zeek
      enabled: true
      scripts:
        - base
        - policy/protocols/ssl/validate-certs
        - policy/frameworks/notice/community-id

  # Resource limits for analyzer containers on this tap
  resources:
    suricata:
      cpu: "500m"
      memory: "512Mi"
    zeek:
      cpu: "500m"
      memory: "512Mi"

status:
  state: Active           # Active | Degraded | Error
  nodesMatched: 1
  packetsProcessed: 0
  lastPacketSeen: null
```

### 2. CapturePolicy

Defines when and how to trigger forensic packet captures.

```yaml
apiVersion: trawl.cloud/v1alpha1
kind: CapturePolicy
metadata:
  name: on-suricata-high-severity
  namespace: trawl-system
spec:
  # What triggers the capture
  trigger:
    type: suricata-alert     # suricata-alert | hubble-drop | hubble-flow | schedule | manual
    suricataAlert:
      severity: [1, 2]       # Suricata severity levels (1 = highest)
      # Optional: limit to specific SIDs or classtype
      # sids: [2024897, 2024898]
      # classtypes: ["trojan-activity", "attempted-admin"]

  # What to capture when triggered
  capture:
    duration: 300s            # how long to capture after trigger
    filter: "host {{.Alert.SrcIP}} and host {{.Alert.DstIP}}"
    snaplen: 0                # 0 = full packet
    maxSize: 100Mi            # stop capture if file exceeds this

  # Where to store captures
  storage:
    type: minio               # minio | pvc | hostpath
    minio:
      endpoint: minio.storage.svc:9000
      bucket: forensic-captures
      prefix: "suricata/{{.Year}}/{{.Month}}/"
    retention: 30d

  # Rate limiting — don't go crazy on a noisy rule
  rateLimit:
    maxCapturesPerHour: 10
    cooldownAfterCapture: 60s

status:
  state: Armed
  totalCaptures: 0
  lastTriggered: null
  activeCaptures: 0
---
apiVersion: trawl.cloud/v1alpha1
kind: CapturePolicy
metadata:
  name: on-hubble-policy-drop
  namespace: trawl-system
spec:
  trigger:
    type: hubble-drop
    hubbleDrop:
      reasons:
        - POLICY_DENIED
        - UNSUPPORTED_L3_PROTOCOL
      # Only trigger on drops from specific namespaces
      sourceNamespaces: ["default", "production"]
      # Minimum drops in window before triggering
      threshold:
        count: 5
        window: 60s

  capture:
    duration: 120s
    filter: "host {{.Flow.SrcIP}} and host {{.Flow.DstIP}}"
    snaplen: 0
    maxSize: 50Mi

  storage:
    type: minio
    minio:
      endpoint: minio.storage.svc:9000
      bucket: forensic-captures
      prefix: "hubble-drops/{{.Year}}/{{.Month}}/"
    retention: 14d

  rateLimit:
    maxCapturesPerHour: 20
    cooldownAfterCapture: 30s
---
apiVersion: trawl.cloud/v1alpha1
kind: CapturePolicy
metadata:
  name: scheduled-baseline
  namespace: trawl-system
spec:
  trigger:
    type: schedule
    schedule:
      cron: "0 */6 * * *"    # every 6 hours

  capture:
    duration: 300s             # 5-minute sample
    filter: ""                 # no filter — full baseline
    snaplen: 128               # headers only for baseline
    maxSize: 200Mi

  storage:
    type: minio
    minio:
      endpoint: minio.storage.svc:9000
      bucket: baseline-captures
      prefix: "baseline/{{.Year}}/{{.Month}}/"
    retention: 7d
```

### 3. CaptureJob (operator-reconciled; created manually or by policy)

Created by the operator when a CapturePolicy fires. Represents a single
capture execution. Users can also create these manually for ad-hoc captures.

```yaml
apiVersion: trawl.cloud/v1alpha1
kind: CaptureJob
metadata:
  name: capture-2026-08-29-143022-suri-2024897
  namespace: trawl-system
  ownerReferences:
    - apiVersion: trawl.cloud/v1alpha1
      kind: CapturePolicy
      name: on-suricata-high-severity
spec:
  tapRef: north-south-mirror
  node: talos-sensor-01
  filter: "host 10.0.0.50 and host 192.168.1.100"
  duration: 300s
  snaplen: 0
  maxSize: 100Mi
  storage:
    type: minio
    bucket: forensic-captures
    key: "suricata/2026/08/capture-2026-08-29-143022-suri-2024897.pcap"

  # Context from the triggering event
  context:
    source: suricata-alert
    alert:
      sid: 2024897
      msg: "ET MALWARE Win32/Emotet CnC Activity"
      severity: 1
      srcIP: 10.0.0.50
      dstIP: 192.168.1.100
      srcPort: 49832
      dstPort: 443

status:
  state: Completed        # Pending | Capturing | Uploading | Completed | Failed
  startedAt: "2026-08-29T14:30:22Z"
  completedAt: "2026-08-29T14:35:22Z"
  pcapSize: "42Mi"
  packetCount: 284710
  storageKey: "suricata/2026/08/capture-2026-08-29-143022-suri-2024897.pcap"
```

---

## Component Design

### Sensor DaemonSet (Suricata + Zeek)

Runs on every node (or nodes matching a NetworkTap's nodeSelector).
Both analyzers share the same network namespace via a pod with two
containers.

**Talos-specific requirements:**
- Namespace labeled `pod-security.kubernetes.io/enforce=privileged`, with admission
  rejecting Trawl resources outside that configured namespace
- `hostNetwork: true` only for analyzer/capture workloads
- Drop all capabilities, then add only `NET_ADMIN` and `NET_RAW`; add `SYS_NICE`
  only after measured need and security review
- `allowPrivilegeEscalation: false`, `RuntimeDefault` seccomp, and no blanket
  `securityContext.privileged: true` in the MVP
- Shared emptyDir volume for pcap handoff between containers

**Suricata container:**
- Image: reviewed Trawl build of Suricata 8.0.6, pinned by digest
- AF_PACKET mode for high-performance capture
- EVE JSON output to stdout (picked up by Alloy) AND to shared volume
- No analyzer-managed pcap logging; bounded CaptureJobs own forensic packet files
- suricata-update CronJob for daily rule updates
- Custom rules for K8s-specific threats (cryptomining, C2, DNS tunneling)

**Zeek container:**
- Image: official `zeek/zeek` or custom build
- JSON log output (`@load policy/tuning/json-logs`)
- Community ID enabled (correlates with Suricata alerts)
- Key log types: conn, dns, http, ssl, x509, files, notice, weird
- Logs to stdout for Alloy collection

### Mirror Receiver Pod

For the MikroTik port mirror. Deployed as a single-replica Deployment
with a nodeSelector pinning it to the node with the mirror NIC.

- `hostNetwork: true`, promiscuous mode on the mirror interface
- Runs a lightweight packet broker (could be a simple bridge or
  a custom Go binary) that makes mirrored traffic available to
  the Suricata/Zeek pods on that node
- Alternative: if Suricata/Zeek DaemonSet is on the same node,
  they can directly listen on the mirror interface

### Hubble Watcher

A Deployment (single replica) that connects to Hubble Relay's gRPC API
and watches for events that should trigger captures.

```
Hubble Relay (gRPC :4245)
        │
        ▼
┌─────────────────────────┐
│    Hubble Watcher        │
│                          │
│  • Subscribes to flows   │
│    via GetFlows() stream  │
│  • Filters for:          │
│    - verdict=DROPPED     │
│    - verdict=ERROR       │
│    - specific L7 events  │
│  • Evaluates against     │
│    CapturePolicy CRs     │
│  • Creates CaptureJob    │
│    CRs when policies     │
│    match                 │
└─────────────────────────┘
```

Key Hubble gRPC observations to act on:
- `DROPPED` verdicts (policy denied)
- DNS responses with known-bad domains
- Flows to/from external IPs not in allowlist
- Unusual protocol usage between pods
- Volume anomalies (sudden traffic spikes between services)

### Alert Watcher

Watches Suricata EVE JSON logs (via Loki queries or direct file tailing
on the shared volume) for alerts that match CapturePolicy triggers.

- Could query Loki via LogQL: `{job="suricata"} | json | event_type="alert" | severity <= 2`
- Or tail the EVE JSON file directly from the shared volume
- Evaluates alerts against CapturePolicy CRs
- Creates CaptureJob CRs when policies match
- Deduplicates to respect rate limits

### PCAP Manager

Handles the lifecycle of capture files:
- Watches CaptureJob CRs
- Spawns ephemeral capture pods (privileged, with tcpdump/dumpcap)
- Uses an unprivileged reporter sidecar with resource-name-scoped `/status` access
  to publish actual capture start/end progress; the capture container has no
  Kubernetes token
- Uploads completed pcaps to MinIO
- Updates CaptureJob status
- Enforces retention policies (deletes expired objects from MinIO)
- Provides an authenticated API and CLI path for pcap downloads; Grafana displays a
  non-secret copyable command rather than embedding a bearer token or presigned URL
- Commits security-sensitive actions to an immutable MinIO-backed audit ledger
  before reporting success and forwards the ledger to Loki for search

---

## Log Pipeline

### Grafana Alloy Configuration (DaemonSet)

Alloy runs on every node and scrapes logs from Suricata and Zeek
containers, adding Kubernetes metadata as labels.

```
Suricata EVE JSON ──→ Alloy ──→ Loki
  Labels: job=suricata, node=X, event_type={alert,dns,flow,http,...}
  Structured metadata: src_ip, dst_ip, severity, sid, signature

Zeek JSON logs ──→ Alloy ──→ Loki
  Labels: job=zeek, node=X, log_type={conn,dns,http,ssl,files,...}
  Structured metadata: uid, community_id, orig_h, resp_h

Hubble flows ──→ Alloy (or direct Hubble metrics export) ──→ Loki
  Labels: job=hubble, source_namespace, dest_namespace, verdict
```

**Key design choice:** Use Loki's structured metadata feature (not labels)
for high-cardinality fields like IP addresses, ports, and UIDs. Labels
stay low-cardinality: job, node, event_type/log_type, namespace.

### Correlation via Community ID

Both Suricata and Zeek support Community ID, a standardized flow hash.
This means a Suricata alert and the corresponding Zeek conn.log entry
share the same community_id value, enabling cross-tool correlation
in Grafana.

```
LogQL example — find the Zeek conn.log for a Suricata alert:

  {job="zeek", log_type="conn"} | json | community_id="1:abc123..."
```

---

## Grafana Dashboards

### 1. Trawl Overview
- Suricata alert rate (by severity, by classtype)
- Zeek connection volume (by protocol, by service)
- Hubble flow verdicts (allowed vs dropped)
- Active NetworkTaps and their health
- Active/recent CaptureJobs

### 2. Alert Investigation
- Suricata alert detail panel
- Cross-reference to Zeek logs via Community ID
- CaptureJob reference and copyable authenticated CLI/API download command
- Hubble flow context for the same src/dst pair
- Timeline view of all events for a given IP

### 3. Protocol Analysis (SEC503 focus)
- DNS query volume and response codes (Zeek dns.log)
- HTTP request methods, user agents, status codes (Zeek http.log)
- TLS versions, cipher suites, JA3 hashes (Zeek ssl.log)
- Certificate details and validation status (Zeek x509.log)
- Connection duration distributions (Zeek conn.log)
- Unusual file transfers (Zeek files.log)

### 4. Capture Management
- CapturePolicy status (armed, triggered counts, rate limit status)
- CaptureJob history (timeline, sizes, trigger sources)
- MinIO storage usage and retention status
- Copyable authenticated CLI/API download commands (browser SSO is post-MVP)

---

## Physical Network Integration

### MikroTik CRS Port Mirror Setup

The MikroTik CRS switch mirrors traffic from selected ports to a
dedicated port connected to a NIC on the Talos sensor node.

```
MikroTik CRS Config (RouterOS):

  /interface ethernet switch
  set switch1 mirror-source=ether1,ether2 mirror-target=ether8

  # ether1,ether2 = uplink ports carrying inter-VLAN traffic
  # ether8         = connected to sensor node's secondary NIC (enp5s0)
```

This gives visibility into:
- Traffic between VLANs (IoT, servers, management, etc.)
- North-south traffic hitting the router
- Any east-west traffic that traverses the switch fabric

The sensor node's secondary NIC runs in promiscuous mode, and the
Suricata/Zeek DaemonSet on that node listens on it via the
`north-south-mirror` NetworkTap.

### What the MikroTik mirror DOESN'T see:
- Pod-to-pod traffic on the same node (stays on veth bridge)
- Pod-to-pod traffic on different nodes via Cilium overlay (VXLAN/Geneve)
- Traffic that never leaves the K8s cluster

That's why we also need the node-interface NetworkTap — Suricata/Zeek
with hostNetwork can see overlay-decapsulated traffic on each node.

---

## Implementation Phases

### Phase 1: Foundation
- [ ] Create `trawl-system` namespace with privileged PSA label
- [ ] Deploy Suricata DaemonSet with AF_PACKET + EVE JSON to stdout
- [ ] Deploy Zeek DaemonSet with JSON logging to stdout
- [ ] Configure Alloy to scrape both and ship to Loki
- [ ] Build initial Grafana dashboards (alerts, connections, DNS)
- [ ] Set up separate private MinIO buckets for pcap storage and the immutable audit
      ledger; enable backend-enforced versioning/write-once retention on the ledger
- [ ] Configure MikroTik port mirror + sensor node NIC

### Phase 2: CRDs + Operator (MVP)
- [ ] Define and register CRD schemas (NetworkTap, CapturePolicy, CaptureJob)
- [ ] Build operator scaffolding (kubebuilder or operator-sdk, Go)
- [ ] Implement Tap Controller (reconcile NetworkTap → manage DaemonSets)
- [ ] Implement manual CaptureJob creation → pcap capture → MinIO upload
- [ ] Wire up authenticated gateway/CLI downloads and safe Grafana command hints
- [ ] Add an immutable MinIO-backed audit ledger with Loki forwarding

### Phase 3: Event-Driven Capture + Sidecar Injection
- [ ] Implement Alert Watcher (Suricata EVE → CapturePolicy evaluation)
- [ ] Implement Hubble Watcher (gRPC → CapturePolicy evaluation)
- [ ] Implement rate limiting and deduplication
- [ ] Add capture context (triggering alert/flow details) to CaptureJob
- [ ] Build Capture Management dashboard in Grafana
- [ ] Build MutatingWebhookConfiguration for sidecar injection
- [ ] Implement pod-selector NetworkTap type (inject capture sidecar
      into pods matching selector, shares network namespace, captures
      on eth0, forwards via VXLAN or shared emptyDir to analysis plane)
- [ ] Sidecar auto-cleanup when NetworkTap is deleted

### Phase 4: TLS Decryption + Advanced Features
- [ ] TLS decryption via K8s Secrets (mount TLS private keys from
      cert-manager / ingress Secrets into Suricata and Zeek pods)
- [ ] Add `tlsDecryption` field to NetworkTap spec
- [ ] Operator RBAC: read Secrets in monitored namespaces only
- [ ] Suricata rule management via CRD (RuleSet CR)
- [ ] Zeek script management via ConfigMap/CRD
- [ ] Community ID correlation dashboards
- [ ] Scheduled baseline captures
- [ ] Anomaly detection triggers (traffic volume deviation)
- [ ] Integration with Falco for runtime events → capture triggers
- [ ] PCAP replay capability for SEC503 exercises

### Phase 5: IPS Mode
- [ ] Suricata inline mode via Cilium TrafficControl or NFQUEUE
- [ ] NetworkTap `mode: inline` field (vs default `mode: passive`)
- [ ] CRD-driven rule promotion (IDS alert → IPS block rule)
- [ ] Kill-switch mechanism (disable IPS globally via single CR update)
- [ ] Canary deployment pattern for new blocking rules

---

## Technology Choices

| Component | Choice | Rationale |
|---|---|---|
| **Operator framework** | kubebuilder (Go) | Native K8s controller patterns, strong CRD support |
| **Suricata image** | Trawl-reviewed Suricata 8.0.6 build, digest-pinned | Reproducible analyzer and rule supply chain |
| **Zeek image** | Trawl-reviewed Zeek 8.0.10 LTS build, digest-pinned | Reproducible scripts and Community ID behavior |
| **Log collector** | Grafana Alloy | Replaces deprecated Promtail, native Loki integration |
| **Log storage** | Loki | Already in stack, cost-effective, LogQL is powerful |
| **PCAP storage** | MinIO | S3-compatible, self-hosted, works with presigned URLs |
| **Visualization** | Grafana | Already in stack, rich dashboard ecosystem |
| **Hubble integration** | gRPC client (Go) | Direct Hubble Relay API, low-latency event stream |
| **Rule updates** | suricata-update CronJob | Standard Suricata tooling, ET Open ruleset |
| **Packet capture tool** | dumpcap (in capture pods) | Lighter than tcpdump, writes pcap-ng directly |

---

## Design Decisions (Resolved)

1. **Both DaemonSet AND sidecar injection for east-west visibility.**
   DaemonSet with hostNetwork provides broad node-level capture of
   decapsulated overlay traffic — this is the baseline and ships in
   Phase 1. Sidecar injection via mutating admission webhook adds
   per-pod attribution for targeted workloads — this ships in Phase 3.
   The `NetworkTap` CRD already supports both via the `type` field
   (`node-interface` for DaemonSet, `pod-selector` for sidecar). The
   sidecar approach requires a MutatingWebhookConfiguration that
   injects a capture container into pods matching the NetworkTap's
   `podSelector`. The sidecar shares the pod's network namespace and
   captures on `eth0`, forwarding to the analysis plane via VXLAN or
   a shared emptyDir volume.

2. **TLS decryption is post-MVP, using K8s Secrets for private keys.**
   Both Suricata and Zeek support TLS decryption when provided with
   the server's private key. In Kubernetes, TLS certs are already
   stored as Secrets (for ingress controllers, cert-manager certs,
   service mesh mTLS). The operator can mount relevant Secrets into
   the Suricata/Zeek pods for decryption. This is a clean, K8s-native
   approach — no key files on disk, secrets rotation handled by
   cert-manager, and the operator only needs RBAC to read Secrets
   in monitored namespaces.

   Implementation sketch:
   ```yaml
   # Addition to NetworkTap spec (Phase 4)
   tlsDecryption:
     enabled: true
     secrets:
       - namespace: ingress
         name: wildcard-tls
       - namespace: default
         name: app-tls
     # Suricata: maps to eve.tls.key config
     # Zeek: maps to SSL::keys_for_decryption
   ```

   **What this won't cover:** Cilium WireGuard node-to-node encryption
   (that's below the application layer and would require Cilium
   cooperation to decrypt). Also won't cover ephemeral session keys
   from perfect forward secrecy without SSLKEYLOGFILE integration,
   which is a separate post-MVP effort if needed.

3. **IDS first, IPS as a later phase.**
   Start with Suricata in IDS mode (passive, AF_PACKET). All the
   SEC503 learning value comes from detection and analysis, not
   inline blocking. IPS mode on Talos would require integration
   with Cilium's TrafficControl or NFQUEUE, adding significant
   complexity and blast radius. IPS becomes a Phase 4+ goal once
   the detection pipeline is battle-tested and we trust the ruleset
   tuning enough to let it drop traffic.

4. **Go for the operator, kubebuilder scaffold.**
   Go gives us client-go, controller-runtime, kubebuilder scaffolding,
   and the entire K8s ecosystem. The Hubble gRPC client libraries are
   also Go-native (cilium/hubble). kubebuilder generates the CRD
   schemas, RBAC, and controller boilerplate. The operator binary
   ships as a single container image.
