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

package policy_test

import (
	"fmt"
	"testing"
	"time"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/observation"
	"trawl.cloud/trawl/internal/policy"
)

// drop builds a denied cluster-flow observation the way the event worker's
// Hubble client emits one.
func drop(mutate ...func(*observation.Observation)) *observation.Observation {
	port := func(v int32) *int32 { return &v }
	obs := &observation.Observation{
		SchemaVersion:   observation.SchemaVersion,
		ID:              "31deea5d1f86a8e8026319623eb2be64",
		EventTime:       time.Date(2026, 9, 9, 14, 0, 0, 0, time.UTC),
		ObservedAt:      time.Date(2026, 9, 9, 14, 0, 0, 0, time.UTC),
		Source:          observation.Source{Kind: observation.SourceHubble, Version: "1.16"},
		Target:          observation.Target{Node: "talos-node"},
		ObservationType: observation.TypeClusterFlow,
		Flow: &observation.Flow{
			Protocol:    "tcp",
			Source:      observation.Endpoint{IP: "10.244.0.11", Port: port(41022), Namespace: "payments", Pod: "api-7d9"},
			Destination: observation.Endpoint{IP: "10.244.0.42", Port: port(5432), Namespace: "data", Pod: "pg-0"},
		},
		Details: observation.Details{ClusterFlow: &observation.ClusterFlow{
			Verdict:    "DROPPED",
			DropReason: "POLICY_DENIED",
			Direction:  "EGRESS",
		}},
	}
	for _, m := range mutate {
		m(obs)
	}
	return obs
}

func TestDropWithAListedReasonMatches(t *testing.T) {
	trigger := trawlv1alpha1.HubbleDropTrigger{Reasons: []string{"POLICY_DENIED"}}

	got := policy.MatchHubbleDrop(trigger, drop())

	if !got.Matched {
		t.Errorf("a POLICY_DENIED drop did not match a trigger listing it: %s", got.Reason)
	}
}

func TestOnlyDeniedVerdictsMatch(t *testing.T) {
	// The trigger selects denied flows. Hubble reports the verdict separately
	// from the reason, and a forwarded flow can carry a reason field left from
	// an earlier evaluation stage - so matching on the reason alone would arm a
	// "denied traffic" policy against traffic that was allowed through.
	trigger := trawlv1alpha1.HubbleDropTrigger{Reasons: []string{"POLICY_DENIED"}}
	forwarded := drop(func(o *observation.Observation) {
		o.Details.ClusterFlow.Verdict = "FORWARDED"
	})

	got := policy.MatchHubbleDrop(trigger, forwarded)

	if got.Matched {
		t.Fatal("a FORWARDED flow matched a denied-flow trigger")
	}
	if got.Reason != policy.ReasonNotDenied {
		t.Errorf("reason = %q, want %q", got.Reason, policy.ReasonNotDenied)
	}
}

func TestSourceNamespacesNarrowByTheSendingNamespace(t *testing.T) {
	// Narrowing is on the source namespace: the policy is about which workload
	// is trying to reach somewhere it may not, so selecting on the destination
	// would arm the policy against the victim rather than the origin.
	trigger := trawlv1alpha1.HubbleDropTrigger{
		Reasons:          []string{"POLICY_DENIED"},
		SourceNamespaces: []string{"payments"},
	}

	if got := policy.MatchHubbleDrop(trigger, drop()); !got.Matched {
		t.Errorf("a drop from payments did not match: %s", got.Reason)
	}

	elsewhere := drop(func(o *observation.Observation) { o.Flow.Source.Namespace = "marketing" })
	got := policy.MatchHubbleDrop(trigger, elsewhere)
	if got.Matched {
		t.Fatal("a drop from marketing matched a trigger listing only payments")
	}
	if got.Reason != policy.ReasonNamespaceNotListed {
		t.Errorf("reason = %q, want %q", got.Reason, policy.ReasonNamespaceNotListed)
	}
}

func TestNamespaceNarrowingToleratesAFlowlessObservation(t *testing.T) {
	// Same class of defect as the absent signature body: the namespace check
	// reads through obs.Flow, and an observation without one would take the
	// event worker down rather than decline the record.
	trigger := trawlv1alpha1.HubbleDropTrigger{
		Reasons:          []string{"POLICY_DENIED"},
		SourceNamespaces: []string{"payments"},
	}
	flowless := drop(func(o *observation.Observation) { o.Flow = nil })

	got := policy.MatchHubbleDrop(trigger, flowless)

	if got.Matched {
		t.Error("an observation with no flow matched a namespace-narrowed trigger")
	}
}

func TestThresholdRequiresTheCountWithinTheWindow(t *testing.T) {
	// A threshold turns "one denied flow" into "a sustained pattern". Until the
	// count is reached the policy has matched the flow but must not capture:
	// the whole point of the threshold is that a single stray denial is noise.
	window := policy.NewThresholdWindow(3, 30*time.Second)
	at := time.Date(2026, 9, 9, 14, 0, 0, 0, time.UTC)

	for i := range 2 {
		if got := window.Observe(seen(i, at.Add(time.Duration(i)*time.Second))); got.Reached {
			t.Fatalf("threshold of 3 reached after %d events", i+1)
		}
	}

	got := window.Observe(seen(2, at.Add(2*time.Second)))
	if !got.Reached {
		t.Error("threshold of 3 not reached on the third event within the window")
	}
	if got.Count != 3 {
		t.Errorf("count = %d, want 3", got.Count)
	}
}

// seen builds a distinct qualifying drop the worker saw at observedAt.
func seen(i int, observedAt time.Time) *observation.Observation {
	return drop(func(o *observation.Observation) {
		o.ID = fmt.Sprintf("event-%02d", i)
		o.ObservedAt = observedAt
		o.EventTime = observedAt
	})
}

func TestEventsOlderThanTheWindowStopCounting(t *testing.T) {
	// "Three in thirty seconds" must mean three in any thirty-second span, not
	// three since the worker started. Without expiry a policy on a cluster with
	// a slow trickle of denials eventually fires on unrelated events minutes or
	// hours apart, and reports it as a burst.
	window := policy.NewThresholdWindow(3, 30*time.Second)
	at := time.Date(2026, 9, 9, 14, 0, 0, 0, time.UTC)

	window.Observe(seen(0, at))
	window.Observe(seen(1, at.Add(5*time.Second)))

	// Far enough past the first two that only this one remains in the window.
	got := window.Observe(seen(2, at.Add(90*time.Second)))

	if got.Reached {
		t.Error("threshold reached across events 90 seconds apart in a 30-second window")
	}
	if got.Count != 1 {
		t.Errorf("count = %d, want 1: only the newest event is still in the window", got.Count)
	}
}

func TestTheWindowIsRollingRatherThanFixed(t *testing.T) {
	// The span is measured from the newest event backwards, not from a fixed
	// origin. Three events at 0s, 25s and 45s are never three within any single
	// 30-second span, and a policy that fired on them would be reporting a
	// burst that did not happen.
	window := policy.NewThresholdWindow(3, 30*time.Second)
	at := time.Date(2026, 9, 9, 14, 0, 0, 0, time.UTC)

	window.Observe(seen(0, at))
	window.Observe(seen(1, at.Add(25*time.Second)))
	got := window.Observe(seen(2, at.Add(45*time.Second)))

	if got.Reached {
		t.Errorf("threshold reached on events spanning 45 seconds in a 30-second window (count %d)", got.Count)
	}
}

func TestAProducerClockSkewDoesNotDistortTheWindow(t *testing.T) {
	// Hubble stamps EventTime from its own clock. If the window were measured
	// on that, one flow stamped an hour ahead would advance the window past
	// every real event and quietly stop the policy firing until local time
	// caught up - a policy that reports itself armed and never triggers, which
	// is the worst failure this component has.
	window := policy.NewThresholdWindow(3, 30*time.Second)
	at := time.Date(2026, 9, 9, 14, 0, 0, 0, time.UTC)

	window.Observe(seen(0, at))

	skewed := seen(1, at.Add(time.Second))
	skewed.EventTime = at.Add(time.Hour) // producer clock an hour fast
	window.Observe(skewed)

	got := window.Observe(seen(2, at.Add(2*time.Second)))

	if !got.Reached {
		t.Errorf("a skewed producer timestamp suppressed the threshold (count %d, want 3)", got.Count)
	}
}

func TestAReplayedEventIsCountedOnce(t *testing.T) {
	// The Loki cursor and the Hubble reconnect watermark both re-deliver around
	// their resume point on purpose, so duplicates are expected rather than
	// exceptional. Counting them would let a threshold of three be reached by
	// one flow delivered three times - a capture triggered by a reconnect
	// rather than by traffic.
	window := policy.NewThresholdWindow(3, 30*time.Second)
	at := time.Date(2026, 9, 9, 14, 0, 0, 0, time.UTC)

	var got policy.ThresholdCount
	for range 5 {
		got = window.Observe(seen(0, at))
	}

	if got.Reached {
		t.Errorf("one event delivered five times reached a threshold of 3 (count %d)", got.Count)
	}
	if got.Count != 1 {
		t.Errorf("count = %d, want 1", got.Count)
	}
}

func TestAnEventOlderThanTheWindowIsNotCounted(t *testing.T) {
	// Out-of-order delivery is normal: the worker can be handed a record older
	// than one it has already seen. Such a record is evidence, but it is not
	// evidence of a burst happening now, and admitting it would let a backlog
	// drained after an outage fire every armed threshold policy at once.
	window := policy.NewThresholdWindow(2, 30*time.Second)
	at := time.Date(2026, 9, 9, 14, 0, 0, 0, time.UTC)

	window.Observe(seen(0, at))
	got := window.Observe(seen(1, at.Add(-10*time.Minute)))

	if got.Reached {
		t.Error("a ten-minute-old event completed a threshold in a 30-second window")
	}
	if got.Count != 1 {
		t.Errorf("count = %d, want 1", got.Count)
	}
}
