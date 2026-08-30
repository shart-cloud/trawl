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

package hubble

import (
	"testing"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"trawl.cloud/trawl/internal/observation"
)

func fixedNow() time.Time { return time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC) }

func normalizer() *Normalizer {
	return &Normalizer{Version: "1.18.11", Node: "fallback-node", Now: fixedNow}
}

func forwardedFlow() *flowpb.Flow {
	return &flowpb.Flow{
		Time:     timestamppb.New(fixedNow().Add(-30 * time.Second)),
		NodeName: "talos-node",
		Verdict:  flowpb.Verdict_FORWARDED,
		IP: &flowpb.IP{
			Source:      "10.244.1.7",
			Destination: "10.244.2.9",
			IpVersion:   flowpb.IPVersion_IPv4,
		},
		L4: &flowpb.Layer4{
			Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{
				SourcePort:      44321,
				DestinationPort: 8080,
			}},
		},
		Source: &flowpb.Endpoint{
			Namespace: "shop",
			PodName:   "frontend-abc",
			Workloads: []*flowpb.Workload{{Name: "frontend"}},
		},
		Destination: &flowpb.Endpoint{
			Namespace: "shop",
			PodName:   "payments-xyz",
			Workloads: []*flowpb.Workload{{Name: "payments"}},
		},
		TrafficDirection:      flowpb.TrafficDirection_EGRESS,
		TraceObservationPoint: flowpb.TraceObservationPoint_TO_ENDPOINT,
		IsReply:               wrapperspb.Bool(false),
	}
}

func TestNormalizeForwardedFlow(t *testing.T) {
	obs, err := normalizer().Normalize(forwardedFlow())
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	if obs.ObservationType != observation.TypeClusterFlow {
		t.Errorf("observation_type = %q", obs.ObservationType)
	}
	if obs.Source.Kind != observation.SourceHubble {
		t.Errorf("source kind = %q", obs.Source.Kind)
	}
	if obs.Details.ClusterFlow.Verdict != VerdictForwarded {
		t.Errorf("verdict = %q, want %q", obs.Details.ClusterFlow.Verdict, VerdictForwarded)
	}
	if err := observation.Validate(obs); err != nil {
		t.Errorf("normalized flow violates the schema: %v", err)
	}
}

func TestNormalizeCarriesWorkloadIdentity(t *testing.T) {
	// This is what Hubble adds that a packet analyzer cannot see. Without it,
	// "10.244.1.7 was denied" is meaningless once the pod is rescheduled and
	// the address belongs to something else.
	obs, err := normalizer().Normalize(forwardedFlow())
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	src := obs.Flow.Source
	if src.Namespace != "shop" || src.Pod != "frontend-abc" || src.Workload != "frontend" {
		t.Errorf("source identity = %+v", src)
	}
	dst := obs.Flow.Destination
	if dst.Workload != "payments" {
		t.Errorf("destination workload = %q, want payments", dst.Workload)
	}
}

func TestNormalizeDroppedFlowCarriesReason(t *testing.T) {
	// The drop reason is what a denied-flow policy matches on (FR-029) and the
	// first thing an operator looks at.
	f := forwardedFlow()
	f.Verdict = flowpb.Verdict_DROPPED
	f.DropReasonDesc = flowpb.DropReason_POLICY_DENIED

	obs, err := normalizer().Normalize(f)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	cf := obs.Details.ClusterFlow
	if cf.Verdict != VerdictDropped {
		t.Errorf("verdict = %q, want %q", cf.Verdict, VerdictDropped)
	}
	if cf.DropReason == "" {
		t.Error("a dropped flow carries no drop reason")
	}
}

func TestForwardedFlowHasNoDropReason(t *testing.T) {
	// A drop reason on a forwarded flow would be a contradiction an operator
	// could act on wrongly.
	obs, err := normalizer().Normalize(forwardedFlow())
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if got := obs.Details.ClusterFlow.DropReason; got != "" {
		t.Errorf("drop reason = %q on a forwarded flow, want empty", got)
	}
}

func TestNormalizeExtractsPortsPerProtocol(t *testing.T) {
	cases := map[string]struct {
		l4       *flowpb.Layer4
		protocol string
		sport    int32
	}{
		"tcp": {&flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{SourcePort: 1234, DestinationPort: 443}}}, protoTCP, 1234},
		"udp": {&flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{SourcePort: 5353, DestinationPort: 53}}}, protoUDP, 5353},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := forwardedFlow()
			f.L4 = tc.l4

			obs, err := normalizer().Normalize(f)
			if err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			if obs.Flow.Protocol != tc.protocol {
				t.Errorf("protocol = %q, want %q", obs.Flow.Protocol, tc.protocol)
			}
			if obs.Flow.Source.Port == nil || *obs.Flow.Source.Port != tc.sport {
				t.Errorf("source port = %v, want %d", obs.Flow.Source.Port, tc.sport)
			}
		})
	}
}

func TestICMPFlowHasNoPorts(t *testing.T) {
	// Reporting port 0 would be a value an analyst could filter on and be
	// misled by; absent is the truthful answer.
	f := forwardedFlow()
	f.L4 = &flowpb.Layer4{Protocol: &flowpb.Layer4_ICMPv4{ICMPv4: &flowpb.ICMPv4{Type: 8}}}

	obs, err := normalizer().Normalize(f)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if obs.Flow.Protocol != protoICMP {
		t.Errorf("protocol = %q, want icmp", obs.Flow.Protocol)
	}
	if obs.Flow.Source.Port != nil {
		t.Errorf("source port = %v on ICMP, want nil", obs.Flow.Source.Port)
	}
}

func TestNormalizePreservesBothTimestamps(t *testing.T) {
	// Hubble's clock and Trawl's may differ; an analyst needs to see the skew.
	obs, err := normalizer().Normalize(forwardedFlow())
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if !obs.ObservedAt.Equal(fixedNow()) {
		t.Errorf("observed_at = %v", obs.ObservedAt)
	}
	if !obs.EventTime.Before(obs.ObservedAt) {
		t.Errorf("event_time %v is not before observed_at %v", obs.EventTime, obs.ObservedAt)
	}
}

func TestFlowIDIsStableAcrossReplay(t *testing.T) {
	// The worker re-reads around its watermark after a reconnect rather than
	// risk a gap, so the same flow arrives twice and must be recognisable as
	// one record rather than counted twice.
	n := normalizer()

	first, err := n.Normalize(forwardedFlow())
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	second, err := n.Normalize(forwardedFlow())
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if first.ID != second.ID {
		t.Errorf("flow ID is not stable across replay: %q vs %q", first.ID, second.ID)
	}
}

func TestDistinctFlowsGetDistinctIDs(t *testing.T) {
	n := normalizer()

	base, err := n.Normalize(forwardedFlow())
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	other := forwardedFlow()
	other.IP.Destination = "10.244.9.9"
	changed, err := n.Normalize(other)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if base.ID == changed.ID {
		t.Error("different flows produced the same ID")
	}
}

func TestFlowWithoutTimestampIsRejected(t *testing.T) {
	// Without an event time a flow cannot be placed in a timeline, which is the
	// only thing it is useful for.
	f := forwardedFlow()
	f.Time = nil

	if _, err := normalizer().Normalize(f); err == nil {
		t.Fatal("a flow with no timestamp was accepted")
	}
}

func TestNilFlowIsRejected(t *testing.T) {
	if _, err := normalizer().Normalize(nil); err == nil {
		t.Fatal("a nil flow was accepted")
	}
}

func TestVersionFallsBackRatherThanDroppingTheRecord(t *testing.T) {
	// The envelope requires a version. An empty one would fail validation and
	// discard a usable observation over a missing label, so an unknown version
	// is recorded as such.
	n := &Normalizer{Node: "n", Now: fixedNow}

	obs, err := n.Normalize(forwardedFlow())
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if obs.Source.Version == "" {
		t.Error("source version is empty; the record will fail schema validation")
	}
	if err := observation.Validate(obs); err != nil {
		t.Errorf("record with an unknown version failed validation: %v", err)
	}
}

func TestNodeNameFallsBackWhenHubbleOmitsIt(t *testing.T) {
	f := forwardedFlow()
	f.NodeName = ""

	obs, err := normalizer().Normalize(f)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if obs.Target.Node != "fallback-node" {
		t.Errorf("node = %q, want the configured fallback", obs.Target.Node)
	}
}

func TestClusterFlowCorrelatesByAttributeNotExactly(t *testing.T) {
	// Hubble emits no Community ID, so a cluster flow can only match analyzer
	// records approximately. The classifier must say so rather than implying a
	// confirmed pairing.
	obs, err := normalizer().Normalize(forwardedFlow())
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if obs.Flow.CommunityID != "" {
		t.Error("a Hubble flow claimed a Community ID it cannot compute")
	}

	analyzer := &observation.Observation{
		EventTime:       obs.EventTime,
		ObservationType: observation.TypeConnection,
		Flow: &observation.Flow{
			Protocol:    "tcp",
			Source:      observation.Endpoint{IP: "10.244.1.7", Port: obs.Flow.Source.Port},
			Destination: observation.Endpoint{IP: "10.244.2.9", Port: obs.Flow.Destination.Port},
		},
	}

	c := &observation.Correlator{}
	if got := c.Match(obs, analyzer); got != observation.MatchAttributeTime {
		t.Errorf("match = %q, want %q", got, observation.MatchAttributeTime)
	}
}
