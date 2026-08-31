/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package hubble consumes Cilium Hubble flow events.
//
// Hubble is the third observation source, and a different kind from the other
// two: Suricata and Zeek see packets on a wire, while Hubble sees the cluster's
// own verdict about a connection. That makes it the only source that can say a
// flow was *denied*, which is what FR-029's denied-flow triggers depend on and
// what lets an investigation distinguish "the traffic did not happen" from "the
// traffic was blocked".
package hubble

import (
	"strings"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"

	"trawl.cloud/trawl/internal/observation"
)

// L4 protocol names, lowercased to match what the analyzers emit. A casing
// mismatch here would silently break attribute-based correlation between a
// Hubble flow and the analyzer records describing the same traffic.
const (
	protoTCP    = "tcp"
	protoUDP    = "udp"
	protoICMP   = "icmp"
	protoICMPv6 = "icmpv6"
	protoSCTP   = "sctp"
)

// Verdicts Cilium reports, named exactly as the flow API names them.
//
// The verdict is copied verbatim rather than mapped: these describe what the
// datapath did, and translating one into another would misdescribe it. The
// names come from flowpb.Verdict_name, which is also where the schema's enum
// and TestEveryVerdictCiliumReportsSatisfiesTheSchema derive theirs - so a
// verdict added by a future Cilium fails a test rather than a production query.
const (
	VerdictForwarded  = "FORWARDED"
	VerdictDropped    = "DROPPED"
	VerdictError      = "ERROR"
	VerdictAudit      = "AUDIT"
	VerdictRedirected = "REDIRECTED"
	VerdictTraced     = "TRACED"
	VerdictTranslated = "TRANSLATED"

	// VerdictUnknown is Cilium's zero value. It is spelled VERDICT_UNKNOWN,
	// not UNKNOWN; the schema enumerated the latter, which no flow could ever
	// carry.
	VerdictUnknown = "VERDICT_UNKNOWN"
)

// Normalizer converts Hubble flows into Trawl observations.
type Normalizer struct {
	// Version is the Hubble/Cilium version these flows came from.
	//
	// Required by the envelope: without it a stored record cannot say which
	// implementation produced it, and Hubble's field semantics have changed
	// across Cilium releases. It is read from the server on connect rather than
	// configured, so it describes what actually answered.
	Version string

	// Node identifies the observing node when Hubble does not report one.
	Node string

	// Now supplies the observation timestamp.
	Now func() time.Time
}

// Normalize converts one Hubble flow.
//
// It returns (nil, nil) for flows Trawl does not model, so a caller can count
// them without treating them as errors.
func (n *Normalizer) Normalize(f *flowpb.Flow) (*observation.Observation, error) {
	if f == nil {
		return nil, errNilFlow
	}
	if f.GetTime() == nil {
		// Without an event time a flow cannot be placed in a timeline, which is
		// the only thing it is useful for.
		return nil, errNoTimestamp
	}

	eventTime := f.GetTime().AsTime().UTC()

	obs := &observation.Observation{
		SchemaVersion: observation.SchemaVersion,
		ID:            flowID(f, eventTime),
		EventTime:     eventTime,
		ObservedAt:    n.now(),
		Source: observation.Source{
			Kind:    observation.SourceHubble,
			Version: n.version(),
		},
		Target: observation.Target{
			Node:             nodeName(f, n.Node),
			ObservationPoint: f.GetTraceObservationPoint().String(),
		},
		ObservationType: observation.TypeClusterFlow,
		Flow:            n.flowOf(f),
		Details: observation.Details{
			ClusterFlow: &observation.ClusterFlow{
				Verdict:    f.GetVerdict().String(),
				DropReason: dropReason(f),
				Direction:  f.GetTrafficDirection().String(),
				EventType:  eventTypeOf(f),
				IsReply:    isReply(f),
			},
		},
	}
	return obs, nil
}

// flowOf builds the shared flow envelope.
//
// Hubble supplies workload identity that packet analyzers cannot see — the
// namespace, pod, and workload behind an address. That is carried through
// because it is what turns "10.244.1.7 was denied" into "the payments API was
// denied", and the address alone is meaningless once the pod is rescheduled.
func (n *Normalizer) flowOf(f *flowpb.Flow) *observation.Flow {
	ip := f.GetIP()
	if ip == nil {
		return nil
	}

	out := &observation.Flow{
		Protocol:    protocolOf(f),
		Source:      endpointOf(ip.GetSource(), f.GetSource(), sourcePort(f)),
		Destination: endpointOf(ip.GetDestination(), f.GetDestination(), destinationPort(f)),
	}

	// Hubble does not emit a Community ID, so cluster-flow records correlate to
	// analyzer records by attribute and time rather than exactly. The
	// correlation classifier reports that difference rather than hiding it.
	return out
}

func endpointOf(ip string, ep *flowpb.Endpoint, port *int32) observation.Endpoint {
	out := observation.Endpoint{IP: ip, Port: port}
	if ep == nil {
		return out
	}
	out.Namespace = ep.GetNamespace()
	out.Pod = ep.GetPodName()
	if workloads := ep.GetWorkloads(); len(workloads) > 0 {
		out.Workload = workloads[0].GetName()
	}
	return out
}

func protocolOf(f *flowpb.Flow) string {
	l4 := f.GetL4()
	switch {
	case l4.GetTCP() != nil:
		return protoTCP
	case l4.GetUDP() != nil:
		return protoUDP
	case l4.GetICMPv4() != nil:
		return protoICMP
	case l4.GetICMPv6() != nil:
		return protoICMPv6
	case l4.GetSCTP() != nil:
		return protoSCTP
	default:
		return strings.ToLower(f.GetIP().GetIpVersion().String())
	}
}

func sourcePort(f *flowpb.Flow) *int32 {
	l4 := f.GetL4()
	switch {
	case l4.GetTCP() != nil:
		return portPtr(l4.GetTCP().GetSourcePort())
	case l4.GetUDP() != nil:
		return portPtr(l4.GetUDP().GetSourcePort())
	case l4.GetSCTP() != nil:
		return portPtr(l4.GetSCTP().GetSourcePort())
	default:
		return nil
	}
}

func destinationPort(f *flowpb.Flow) *int32 {
	l4 := f.GetL4()
	switch {
	case l4.GetTCP() != nil:
		return portPtr(l4.GetTCP().GetDestinationPort())
	case l4.GetUDP() != nil:
		return portPtr(l4.GetUDP().GetDestinationPort())
	case l4.GetSCTP() != nil:
		return portPtr(l4.GetSCTP().GetDestinationPort())
	default:
		return nil
	}
}

func portPtr(v uint32) *int32 {
	//nolint:gosec // ports are bounded by uint16
	p := int32(v)
	return &p
}

// dropReason returns why a flow was denied.
//
// It is the field a denied-flow policy matches on (FR-029) and the first thing
// an operator looks at, so the human-readable form is preferred over the
// numeric code.
func dropReason(f *flowpb.Flow) string {
	if f.GetVerdict() != flowpb.Verdict_DROPPED {
		return ""
	}
	if desc := f.GetDropReasonDesc().String(); desc != "" && desc != "DROP_REASON_UNKNOWN" {
		return desc
	}
	return ""
}

func eventTypeOf(f *flowpb.Flow) string {
	if e := f.GetEventType(); e != nil {
		return flowpb.EventType(e.GetType()).String()
	}
	return ""
}

func isReply(f *flowpb.Flow) *bool {
	if r := f.GetIsReply(); r != nil {
		v := r.GetValue()
		return &v
	}
	return nil
}

func nodeName(f *flowpb.Flow, fallback string) string {
	if n := f.GetNodeName(); n != "" {
		return n
	}
	return fallback
}

// version reports the connected Hubble version, or "unknown" when the server
// did not supply one. "unknown" is deliberate: the envelope requires a version,
// and an empty string would fail validation and drop an otherwise usable
// observation over a missing label.
func (n *Normalizer) version() string {
	if n.Version != "" {
		return n.Version
	}
	return "unknown"
}

func (n *Normalizer) now() time.Time {
	if n.Now != nil {
		return n.Now().UTC()
	}
	return time.Now().UTC()
}
