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

package policy

import (
	"fmt"
	"slices"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/observation"
)

// verdictDropped is the Hubble verdict naming a denied flow.
const verdictDropped = "DROPPED"

// MatchHubbleDrop evaluates a denied-flow trigger against one observation.
//
// This decides only whether the flow qualifies. A trigger carrying a threshold
// additionally requires enough qualifying flows inside its window, which is
// state rather than a property of a single record and lives in ThresholdWindow.
func MatchHubbleDrop(t trawlv1alpha1.HubbleDropTrigger, obs *observation.Observation) Decision {
	flow := obs.Details.ClusterFlow
	if flow == nil || obs.Source.Kind != observation.SourceHubble {
		return Decision{Reason: ReasonNotAClusterFlow}
	}
	// Verdict before reason. Hubble reports them separately, and a flow that
	// was allowed through is not what a denied-flow policy is armed against
	// however its reason field reads.
	if flow.Verdict != verdictDropped {
		return Decision{Reason: ReasonNotDenied}
	}
	if !slices.Contains(t.Reasons, flow.DropReason) {
		return Decision{Reason: ReasonDropReasonNotListed}
	}
	if len(t.SourceNamespaces) > 0 {
		// An observation with no flow has no source namespace to narrow on, so
		// it cannot satisfy a trigger that narrows by one.
		if obs.Flow == nil || !slices.Contains(t.SourceNamespaces, obs.Flow.Source.Namespace) {
			return Decision{Reason: ReasonNamespaceNotListed}
		}
	}
	return Decision{Matched: true}
}

// ThresholdCount is the result of offering one qualifying flow to a window.
type ThresholdCount struct {
	// Count is how many distinct qualifying events the window now holds.
	Count int

	// Reached says the threshold was met by this event.
	Reached bool
}

// ThresholdWindow counts distinct qualifying events over a rolling period.
//
// One window belongs to one policy. It is not safe for concurrent use; the
// event worker evaluates a policy's events in sequence, and a mutex here would
// hide it if that ever stopped being true.
type ThresholdWindow struct {
	count  int
	window time.Duration

	// newest is the latest event time seen, and the point the window is
	// measured back from.
	newest time.Time

	// events holds the event time of each distinct event still inside the
	// window, keyed by event identity so a replayed delivery is not counted
	// twice.
	events map[string]time.Time
}

// NewThresholdWindow returns a window requiring count events within d.
func NewThresholdWindow(count int, d time.Duration) *ThresholdWindow {
	return &ThresholdWindow{count: count, window: d, events: map[string]time.Time{}}
}

// Observe offers one qualifying observation to the window and reports the
// count.
//
// Counting is done on ObservedAt - when this worker saw the record - and not on
// EventTime, which the producer stamped. Both are kept on the observation and
// the snapshot records EventTime, because an analyst needs the time the traffic
// happened. But a window measured on producer time is a window an unsynchronized
// producer can distort: one flow stamped an hour ahead would advance the window
// past every real event and silently stop the policy firing until the clock
// caught up. ObservedAt comes from one clock - ours - so the count reflects the
// rate the worker actually saw.
func (w *ThresholdWindow) Observe(obs *observation.Observation) ThresholdCount {
	// Keyed by the observation's stable ID, so a record delivered twice - which
	// replay around a cursor does deliberately - counts once. Preserve the
	// first delivery time as well as the count: replacing it on replay would
	// rejuvenate an old occurrence and let it remain in a later rate window.
	if _, seen := w.events[obs.ID]; !seen {
		w.events[obs.ID] = obs.ObservedAt
		if obs.ObservedAt.After(w.newest) {
			w.newest = obs.ObservedAt
		}
	}
	w.expire()

	return ThresholdCount{Count: len(w.events), Reached: len(w.events) >= w.count}
}

// expire drops events that fall outside the window ending at the newest
// observation time seen.
//
// Bounding by time is also what bounds memory: without it the map grows for as
// long as the policy is armed, which on a cluster with steady denials is a leak
// with a slow fuse.
func (w *ThresholdWindow) expire() {
	cutoff := w.newest.Add(-w.window)
	for id, at := range w.events {
		if at.Before(cutoff) {
			delete(w.events, id)
		}
	}
}

// HubbleSnapshot copies the denied flow that fired into the immutable trigger
// context recorded on the CaptureJob.
//
// Like the Suricata snapshot, this is identity and classification only. It
// carries the count that met the threshold, because a capture answering "three
// denials in a minute" explains itself very differently from one answering a
// single drop, and by the time an analyst reads it the flows themselves have
// aged out of the relay's ring buffer.
func HubbleSnapshot(
	obs *observation.Observation, fingerprint string, count int32,
) (*trawlv1alpha1.TriggerSnapshot, error) {
	flow := obs.Details.ClusterFlow
	if flow == nil {
		return nil, fmt.Errorf("observation %s carries no cluster flow", obs.ID)
	}

	context := &trawlv1alpha1.HubbleTriggerContext{
		Reason: truncate(flow.DropReason, maxSnapshotReason),
		Count:  count,
	}
	if obs.Flow != nil {
		context.SourceNamespace = truncate(obs.Flow.Source.Namespace, maxSnapshotNamespace)
		context.DestinationNamespace = truncate(obs.Flow.Destination.Namespace, maxSnapshotNamespace)
	}

	return &trawlv1alpha1.TriggerSnapshot{
		Source:      trawlv1alpha1.TriggerSourceHubbleDrop,
		Fingerprint: fingerprint,
		EventTime:   metav1.NewTime(obs.EventTime),
		ObservedAt:  metav1.NewTime(obs.ObservedAt),
		Flow:        flowSnapshot(obs.Flow),
		Hubble:      context,
	}, nil
}
