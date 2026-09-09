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

package controller

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/status"
)

// healthy is a trigger source that is connected and delivering.
func healthy() map[trawlv1alpha1.CaptureTriggerType]SourceHealth {
	return map[trawlv1alpha1.CaptureTriggerType]SourceHealth{
		trawlv1alpha1.CaptureTriggerSuricataAlert: {Connected: true},
		trawlv1alpha1.CaptureTriggerHubbleDrop:    {Connected: true},
	}
}

// trackerFixture is one status tracker over a fake API.
type trackerFixture struct {
	tracker *PolicyStatusTracker
	client  client.Client
}

func newTracker(t *testing.T, objs ...client.Object) *trackerFixture {
	t.Helper()
	return newTrackerWith(t, interceptor.Funcs{}, objs...)
}

func newTrackerWith(t *testing.T, funcs interceptor.Funcs, objs ...client.Object) *trackerFixture {
	t.Helper()
	c := fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithObjects(objs...).
		WithStatusSubresource(&trawlv1alpha1.NetworkTap{}, &trawlv1alpha1.CapturePolicy{}, &trawlv1alpha1.CaptureJob{}).
		WithInterceptorFuncs(funcs).
		Build()

	return &trackerFixture{
		client: c,
		tracker: &PolicyStatusTracker{
			Client:    c,
			Namespace: testNamespace,
			Now:       func() time.Time { return evaluatedAt },
		},
	}
}

func (f *trackerFixture) flush(t *testing.T) {
	t.Helper()
	if err := f.tracker.Flush(context.Background(), healthy()); err != nil {
		t.Fatalf("flushing status: %v", err)
	}
}

func (f *trackerFixture) read(t *testing.T, name string) trawlv1alpha1.CapturePolicy {
	t.Helper()
	var p trawlv1alpha1.CapturePolicy
	key := types.NamespacedName{Namespace: testNamespace, Name: name}
	if err := f.client.Get(context.Background(), key, &p); err != nil {
		t.Fatalf("reading policy %s: %v", name, err)
	}
	return p
}

// created is the result the engine reports for a capture it made.
func createdResult(name string, at time.Time) PolicyResult {
	return PolicyResult{
		Policy:      types.NamespacedName{Namespace: testNamespace, Name: "ssh-scan"},
		PolicyUID:   policyUID,
		Generation:  3,
		TriggerType: trawlv1alpha1.CaptureTriggerSuricataAlert,
		TapUID:      testTapUID,
		Outcome:     OutcomeCreated,
		CaptureName: name,
		TriggerTime: at,
	}
}

// outcome is a result of some other kind for the same policy.
func policyOutcome(o PolicyOutcome, at time.Time, mutate ...func(*PolicyResult)) PolicyResult {
	r := createdResult("", at)
	r.Outcome = o
	for _, m := range mutate {
		m(&r)
	}
	return r
}

func TestDecisionCountersAccumulateAcrossFlushes(t *testing.T) {
	// The counters are a record of what the policy has been doing, not of what
	// it did since the last write. Recomputing them from the pending batch
	// would reset them on every flush, and a policy that had matched a thousand
	// times would report whatever happened in the last fifteen seconds.
	f := newTracker(t, activeTap(), suricataPolicy())

	f.tracker.Record(createdResult("trawl-policy-aaa", evaluatedAt))
	f.tracker.Record(policyOutcome(OutcomeNotMatched, time.Time{}))
	f.flush(t)

	f.tracker.Record(policyOutcome(OutcomeDuplicate, evaluatedAt, func(r *PolicyResult) {
		r.CaptureName = "trawl-policy-aaa"
	}))
	f.tracker.Record(policyOutcome(OutcomeNotMatched, time.Time{}))
	f.flush(t)

	got := f.read(t, "ssh-scan").Status
	if got.Decisions.Matched != 1 {
		t.Errorf("matched = %d, want 1", got.Decisions.Matched)
	}
	if got.Decisions.NotMatched != 2 {
		t.Errorf("notMatched = %d, want 2 - the first flush's count was lost", got.Decisions.NotMatched)
	}
	if got.Decisions.Duplicate != 1 {
		t.Errorf("duplicate = %d, want 1", got.Decisions.Duplicate)
	}
	if got.TotalCaptures != 1 {
		t.Errorf("totalCaptures = %d, want 1 - a duplicate is not a new capture", got.TotalCaptures)
	}
}

func TestAnArmedPolicyWithAHealthySourceIsArmed(t *testing.T) {
	f := newTracker(t, activeTap(), suricataPolicy())

	f.flush(t)

	got := f.read(t, "ssh-scan").Status
	if got.Phase != trawlv1alpha1.CapturePolicyArmed {
		t.Errorf("phase = %s, want Armed", got.Phase)
	}
	if !status.IsTrue(got.Conditions, status.TypeReady, 3) {
		t.Errorf("Ready is not true: %+v", got.Conditions)
	}
	if got.ObservedGeneration != 3 {
		t.Errorf("observedGeneration = %d, want 3", got.ObservedGeneration)
	}
	if got.ResolvedTapUID != testTapUID {
		t.Errorf("resolvedTapUID = %q, want %q", got.ResolvedTapUID, testTapUID)
	}
}

func TestAPolicyIsReconciledEvenWhenNothingHasHappened(t *testing.T) {
	// A policy that has never seen a matching event still has to say whether
	// it is watching. Reconciling only the policies with pending decisions
	// would leave a newly armed policy with an empty status indefinitely -
	// indistinguishable from a worker that is not running.
	f := newTracker(t, activeTap(), suricataPolicy(), hubblePolicy())

	f.flush(t)

	if got := f.read(t, "denied-egress").Status.Phase; got != trawlv1alpha1.CapturePolicyArmed {
		t.Errorf("phase of the policy with no decisions = %q, want Armed", got)
	}
}

func TestADisarmedPolicyReportsDisarmedRatherThanReady(t *testing.T) {
	// Arming is what starts collecting packets, so the distinction has to be
	// legible at a glance: a disarmed policy is not a broken one, and a broken
	// one must not be able to look disarmed.
	f := newTracker(t, activeTap(), suricataPolicy(func(p *trawlv1alpha1.CapturePolicy) {
		p.Spec.Armed = false
	}))

	f.flush(t)

	got := f.read(t, "ssh-scan").Status
	if got.Phase != trawlv1alpha1.CapturePolicyDisarmed {
		t.Errorf("phase = %s, want Disarmed", got.Phase)
	}
	ready := status.Get(got.Conditions, status.TypeReady)
	if ready == nil || ready.Status != metav1.ConditionFalse || ready.Reason != status.ReasonDisarmed {
		t.Errorf("Ready = %+v, want False/Disarmed", ready)
	}
}

func TestAPolicyAtItsHourlyLimitReportsRateLimited(t *testing.T) {
	// Derived from the captures rather than from the last decision, so it
	// clears itself as they age out of the hour. A phase latched on the last
	// suppressed event would leave a recovered policy reporting RateLimited
	// until the next event happened to arrive.
	objs := append(make([]client.Object, 0, 7), activeTap(), suricataPolicy())
	for i := range 5 {
		objs = append(objs, policyJob(i, evaluatedAt.Add(-time.Duration(i+1)*time.Minute),
			trawlv1alpha1.CapturePhaseCompleted))
	}
	f := newTracker(t, objs...)

	f.flush(t)

	got := f.read(t, "ssh-scan").Status
	if got.Phase != trawlv1alpha1.CapturePolicyRateLimited {
		t.Errorf("phase = %s, want RateLimited at five captures with a limit of five", got.Phase)
	}
	limit := status.Get(got.Conditions, status.TypeWithinRateLimit)
	if limit == nil || limit.Status != metav1.ConditionFalse || limit.Reason != status.ReasonRateLimited {
		t.Errorf("WithinRateLimit = %+v, want False/RateLimited", limit)
	}
}

func TestActiveCapturesAreCountedFromTheCapturesThemselves(t *testing.T) {
	// Rebuilt from the jobs on every flush, so a restart does not lose the
	// count and a job that finished while the worker was down is not still
	// reported as running.
	f := newTracker(t, activeTap(), suricataPolicy(),
		policyJob(0, evaluatedAt.Add(-time.Minute), trawlv1alpha1.CapturePhaseCapturing),
		policyJob(1, evaluatedAt.Add(-2*time.Minute), trawlv1alpha1.CapturePhaseCompleted))

	f.flush(t)

	if got := f.read(t, "ssh-scan").Status.ActiveCaptures; got != 1 {
		t.Errorf("activeCaptures = %d, want 1 - only the capturing job is still in flight", got)
	}
}

func TestADisconnectedSourceLeavesThePolicyDegraded(t *testing.T) {
	// Absence of captures has two explanations: quiet traffic, and nobody
	// looking. Degraded is how an armed policy says which one applies to it,
	// and without it a broken source looks exactly like a quiet network.
	f := newTracker(t, activeTap(), suricataPolicy())

	health := healthy()
	health[trawlv1alpha1.CaptureTriggerSuricataAlert] = SourceHealth{
		Connected: false,
		Reason:    status.ReasonSourceDisconnected,
		Message:   "the alert query path is not answering",
	}
	if err := f.tracker.Flush(context.Background(), health); err != nil {
		t.Fatalf("flushing status: %v", err)
	}

	got := f.read(t, "ssh-scan").Status
	if got.Phase != trawlv1alpha1.CapturePolicyDegraded {
		t.Errorf("phase = %s, want Degraded", got.Phase)
	}
	source := status.Get(got.Conditions, status.TypeSourceConnected)
	if source == nil || source.Status != metav1.ConditionFalse {
		t.Errorf("SourceConnected = %+v, want False", source)
	}
}

func TestTheHubblePolicyIsUnaffectedByTheAlertSourceFailing(t *testing.T) {
	// FR-038 again, at the status layer. The two sources fail independently,
	// and a Hubble policy reported Degraded because Loki is down would send an
	// operator looking in the wrong place.
	f := newTracker(t, activeTap(), suricataPolicy(), hubblePolicy())

	health := healthy()
	health[trawlv1alpha1.CaptureTriggerSuricataAlert] = SourceHealth{
		Connected: false, Reason: status.ReasonSourceDisconnected,
	}
	if err := f.tracker.Flush(context.Background(), health); err != nil {
		t.Fatalf("flushing status: %v", err)
	}

	if got := f.read(t, "denied-egress").Status.Phase; got != trawlv1alpha1.CapturePolicyArmed {
		t.Errorf("the Hubble policy's phase = %s, want Armed", got)
	}
}

func TestAMissingTapLeavesThePolicyDegraded(t *testing.T) {
	f := newTracker(t, suricataPolicy())

	f.flush(t)

	got := f.read(t, "ssh-scan").Status
	if got.Phase != trawlv1alpha1.CapturePolicyDegraded {
		t.Errorf("phase = %s, want Degraded when the tap does not exist", got.Phase)
	}
	tap := status.Get(got.Conditions, status.TypeTapResolved)
	if tap == nil || tap.Status != metav1.ConditionFalse || tap.Reason != status.ReasonTapNotFound {
		t.Errorf("TapResolved = %+v, want False/TapNotFound", tap)
	}
}

func TestASuppressedTriggerStillMovesTheLastTriggerTime(t *testing.T) {
	// A policy that is matching and suppressing is working; one that is not
	// matching at all is a different problem. Without the trigger time moving
	// on a suppressed event the two look identical from the status.
	f := newTracker(t, activeTap(), suricataPolicy())
	at := evaluatedAt.Add(-30 * time.Second)

	f.tracker.Record(policyOutcome(OutcomeRateLimited, at))
	f.flush(t)

	got := f.read(t, "ssh-scan").Status
	if got.LastTriggerTime == nil || !got.LastTriggerTime.Time.Equal(at) {
		t.Errorf("lastTriggerTime = %v, want the suppressed trigger's %v", got.LastTriggerTime, at)
	}
	if got.LastCaptureRef != nil {
		t.Errorf("lastCaptureRef = %+v, want none - the capture was refused", got.LastCaptureRef)
	}
	if got.Decisions.RateLimited != 1 {
		t.Errorf("rateLimited = %d, want 1", got.Decisions.RateLimited)
	}
}

func TestAnUnmatchedEventDoesNotMoveTheLastTriggerTime(t *testing.T) {
	// The trigger time answers "when did this policy last see its traffic".
	// Advancing it on every declined record would make it a clock rather than
	// an observation.
	f := newTracker(t, activeTap(), suricataPolicy())

	f.tracker.Record(policyOutcome(OutcomeNotMatched, time.Time{}))
	f.flush(t)

	if got := f.read(t, "ssh-scan").Status.LastTriggerTime; got != nil {
		t.Errorf("lastTriggerTime = %v, want none", got)
	}
}

func TestADuplicateRecordsTheCaptureItCollapsedOnto(t *testing.T) {
	// The reference is what turns "suppressed" into something an analyst can
	// follow: the packets for this event are in that capture.
	f := newTracker(t, activeTap(), suricataPolicy())

	f.tracker.Record(policyOutcome(OutcomeDuplicate, evaluatedAt, func(r *PolicyResult) {
		r.CaptureName = "trawl-policy-aaa"
	}))
	f.flush(t)

	got := f.read(t, "ssh-scan").Status
	if got.LastCaptureRef == nil || got.LastCaptureRef.Name != "trawl-policy-aaa" {
		t.Errorf("lastCaptureRef = %+v, want the capture it collapsed onto", got.LastCaptureRef)
	}
}

func TestOnePolicysStatusWriteFailingDoesNotLoseItsDecisionsOrStopAnother(t *testing.T) {
	// Retry isolation. A status write can fail for reasons that have nothing to
	// do with the policy - a conflict, a brief API outage - and dropping the
	// batch would silently lose the record of decisions that really happened.
	// Blocking the other policies on it would be worse.
	var fail bool
	f := newTrackerWith(t, interceptor.Funcs{
		SubResourceUpdate: func(
			ctx context.Context, c client.Client, subResource string,
			obj client.Object, opts ...client.SubResourceUpdateOption,
		) error {
			if fail && obj.GetName() == "ssh-scan" {
				return errors.New("conflict writing status")
			}
			return c.Status().Update(ctx, obj, opts...)
		},
	}, activeTap(), suricataPolicy(), hubblePolicy())

	fail = true
	f.tracker.Record(createdResult("trawl-policy-aaa", evaluatedAt))
	if err := f.tracker.Flush(context.Background(), healthy()); err == nil {
		t.Fatal("a failing status write was reported as success")
	}

	if got := f.read(t, "denied-egress").Status.Phase; got != trawlv1alpha1.CapturePolicyArmed {
		t.Errorf("the other policy's phase = %q; one policy's write failure stopped it", got)
	}

	fail = false
	f.flush(t)

	got := f.read(t, "ssh-scan").Status
	if got.Decisions.Matched != 1 {
		t.Errorf("matched = %d after the retry, want 1 - the failed batch was dropped", got.Decisions.Matched)
	}
	if got.TotalCaptures != 1 {
		t.Errorf("totalCaptures = %d after the retry, want 1", got.TotalCaptures)
	}
}

func TestDecisionsForADeletedPolicyAreDiscarded(t *testing.T) {
	// A policy can be deleted between the decision and the flush. Retrying its
	// status forever would keep a batch pending that can never be written, and
	// the tracker would grow one entry per deleted policy for as long as the
	// worker runs.
	f := newTracker(t, activeTap())

	f.tracker.Record(createdResult("trawl-policy-aaa", evaluatedAt))
	f.flush(t)
	f.flush(t)
}

// policyJob is a CaptureJob the ssh-scan policy created.
func policyJob(i int, at time.Time, phase trawlv1alpha1.CapturePhase) *trawlv1alpha1.CaptureJob {
	requested := metav1.NewTime(at)
	return &trawlv1alpha1.CaptureJob{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      "trawl-policy-existing-" + strconv.Itoa(i),
		},
		Spec: trawlv1alpha1.CaptureJobSpec{
			RequestType: trawlv1alpha1.CaptureRequestPolicy,
			TapRef:      corev1.LocalObjectReference{Name: "node-eno1"},
			Duration:    "30s",
			MaxSize:     resource.MustParse("64Mi"),
			PolicyRef: &trawlv1alpha1.ImmutablePolicyReference{
				Name: "ssh-scan", UID: policyUID, Generation: 3,
			},
		},
		Status: trawlv1alpha1.CaptureJobStatus{Phase: phase, RequestedAt: &requested},
	}
}
