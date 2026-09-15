# Trawl

Kubernetes-native network security monitoring. Declare where to watch; Trawl
runs Suricata and Zeek there, normalizes what they see into one searchable
record shape, captures the packets around a detection, and hands those packets
to an authorized analyst later.

Documentation: **[trawl.cloud](https://trawl.cloud)**

## Why

Network security monitoring has good tools and no cloud-native home. Security
Onion does not run on Kubernetes, EDCOP never matured, and Corelight's approach
means their sensors. The techniques taught against full packet captures do not
have an operator that treats Zeek and Suricata as first-class workloads.

Trawl was built for Talos Linux, where the constraint is sharpest: the host is
immutable, there is no SSH and no package manager, so a sensor cannot be
installed on a node at all. Everything is a pod, and everything that changes is
a resource.

## Status

**Alpha.** The API is `v1alpha1` and will change; promotion to `v1beta1` is a
planned workstream with a conversion strategy, not a version bump. The MVP is
specified, implemented and gated, and the work after it is written down in the
[roadmap](https://trawl.cloud/roadmap/) as nine workstreams with the order they
have to be built in.

It runs in a homelab against real traffic. It has not been run at production
scale, and the throughput criterion is honest about lacking a traffic generator
to prove itself against.

## How it works

Four resources, in the order you would meet them:

| resource | what it declares |
|---|---|
| **NetworkTap** | an interface to watch and which analyzers to run on it |
| **CapturePolicy** | a trigger armed against a tap, with bounded capture behavior |
| **CaptureJob** | one bounded packet capture and its verified artifact |
| **PortMirror** | a mirror session on a switch, so a tap has something to observe |

A tap renders analyzer pods onto the nodes that match it, each with an
unprivileged sidecar that normalizes Suricata and Zeek output into a single
versioned observation envelope and writes it to stdout, where Alloy collects it
into Loki. Cilium's Hubble is a third source, and the only one that can say a
flow was *denied*.

An armed policy watches those observations. When one matches, a capture job runs
`dumpcap` on the node where the traffic was seen, bounded by duration, size and
snaplen, and uploads a verified pcapng. Retrieving it goes through a gateway
that checks the caller with a TokenReview and a SubjectAccessReview, writes the
grant to a write-once ledger, and only then answers with a short-lived
presigned URL.

Three properties are worth stating because they drove most of the design:

- **Passive, and fail-open for traffic.** Trawl must never affect the packets it
  watches. No component has a transmit path, and every failure mode is chosen so
  that monitoring degrades rather than the network.
- **Fail-closed for privileged operations.** A capture whose authorization could
  not be durably committed does not happen, and a download the ledger did not
  hear about is not served.
- **Status is a claim, not an echo.** A tap reporting `Active` means traffic is
  being analyzed right now. A policy reporting `Armed` means coverage exists. An
  external witness watches the event worker so that a dead worker cannot leave
  every policy claiming coverage it is not providing.

The reasoning behind each major decision is recorded as an
[ADR](https://trawl.cloud/adr/0001-normalized-observation-envelope/).

## Requirements

- Talos Kubernetes 1.35–1.37, with one node labelled as sensor-eligible
- Cilium with Hubble Relay
- Grafana Alloy, Loki with TSDB schema v13 or later, and Grafana
- A MinIO-compatible endpoint, with object lock available for the audit ledger
- For physical mirroring, a dedicated NIC and a MikroTik RouterOS 7 switch

The ledger and the capture artifacts live in **separate buckets with separate
credentials**. Only the controller manager holds the ledger's.

## Install

Each tagged release publishes `install.yaml`, a single bundle with every image
pinned by digest:

```sh
kubectl apply -f https://github.com/shart-cloud/trawl/releases/latest/download/install.yaml
```

No release has been cut yet, so until the first tag, render the bundle from a
checkout with `make build-installer` and apply `dist/install.yaml`.

To run your own images instead:

```sh
make docker-build-all IMAGE_REPO=<registry>/trawl VERSION=<tag>
make install                      # CRDs only
make deploy IMG=<registry>/trawl:<tag>
```

Sample resources are in `config/samples/`. `config/samples/invalid/` holds ones
that are supposed to be rejected, which is the faster way to see what the
admission webhooks enforce.

`make undeploy` removes the controllers and leaves the CRDs, so the records of
where collected evidence is stored survive. `make uninstall` deletes the CRDs
and therefore those records too; it says so in `make help`.

The full acceptance path, from an empty cluster to validating every user story
against real traffic, is the [quickstart](https://trawl.cloud/quickstart/).

## Security posture

Two containers in the system hold Linux capabilities: the analyzers, which get
`NET_RAW` and `NET_ADMIN` and nothing else, and the capture runner. In both
cases the privileged container holds **no Kubernetes credentials**, and the
container beside it that holds the token has **no privilege**. `privileged` is
never set on anything.

Every security-sensitive action is written to a write-once ledger before it is
allowed, and the ledger is a gate rather than a log: when it cannot be reached,
the action is refused. Detection content is pinned by digest, because a tag can
be repointed after the review that approved its contents.

Scanning is release-blocking rather than advisory, and suppressions expire —
an out-of-date suppression breaks the build, so the choice is to fix the finding
or re-review it in writing. The list is currently empty, which is the healthy
state.

See [evidence handling](https://trawl.cloud/security/evidence-handling/).

## Development

`AGENTS.md` is the orientation guide for this repository, written for AI agents
and just as usable by people. It covers the layout, which process runs what, the
conventions, and the traps.

```sh
make test              # unit, contract and envtest
make test-integration  # envtest and containers
make lint              # three passes, one per build tag
make verify            # tool pins, formatting, generated-artifact drift
make security          # manifest privilege, suppressions, govulncheck
make help              # everything else
```

The end-to-end suites are build-tagged and need a real cluster with Trawl
deployed; `make test-acceptance` and `make test-investigation` run them.

Features are specified before they are built, under `specs/`, following Spec
Kit. `.specify/memory/constitution.md` holds the six principles that every plan
is checked against.

## License

Apache License 2.0. See [LICENSE](LICENSE).
