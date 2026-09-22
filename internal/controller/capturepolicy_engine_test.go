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
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/audit"
	"trawl.cloud/trawl/internal/observation"
	"trawl.cloud/trawl/internal/policy"
	"trawl.cloud/trawl/internal/status"
	"trawl.cloud/trawl/internal/storage"
)

const (
	testNamespace = "trawl-system"
	testTapUID    = types.UID("tap-uid")
	testNode      = "talos-node"
)

// evaluatedAt is the worker's clock in these tests. It sits a few seconds after
// the observation timestamps the shared alert() and drop() helpers carry, which
// is the ordinary relationship: the worker sees a record after it happened.
var evaluatedAt = time.Date(2026, 9, 9, 14, 0, 5, 0, time.UTC)

// policyUID identifies the policy these fixtures belong to.
const policyUID = types.UID("11111111-1111-4111-8111-111111111111")

// alert builds a Suricata signature observation the way the sensor emits one,
// and drop builds a denied cluster flow the way the Hubble client does. Tests
// override the fields they are about and leave the rest realistic, so a test
// that says "severity 2" is not also silently asserting an empty flow.
func alert(mutate ...func(*observation.Observation)) *observation.Observation {
	port := func(v int32) *int32 { return &v }
	obs := &observation.Observation{
		SchemaVersion:   observation.SchemaVersion,
		ID:              "4125e22fe6fad350aa771423a45c643e",
		EventTime:       time.Date(2026, 9, 9, 13, 46, 36, 0, time.UTC),
		ObservedAt:      time.Date(2026, 9, 9, 13, 46, 36, 0, time.UTC),
		Source:          observation.Source{Kind: observation.SourceSuricata, Version: "8.0.6"},
		Tap:             &observation.Tap{Namespace: testNamespace, Name: "node-eno1", UID: string(testTapUID)},
		Target:          observation.Target{Node: testNode, Interface: "eno1"},
		ObservationType: observation.TypeSignature,
		Flow: &observation.Flow{
			CommunityID: "1:jHqeeOu8/MiEmFspokLGdUQj4hE=",
			Protocol:    "tcp",
			Source:      observation.Endpoint{IP: "192.168.0.6", Port: port(51136)},
			Destination: observation.Endpoint{IP: "140.82.113.3", Port: port(22)},
		},
		Details: observation.Details{Signature: &observation.Signature{
			RuleID:   2038968,
			Severity: 2,
			Category: "Misc activity",
			Message:  "ET INFO SSH-2.0-Go version string Observed in Network Traffic",
			Action:   "allowed",
		}},
	}
	for _, m := range mutate {
		m(obs)
	}
	return obs
}

func drop(mutate ...func(*observation.Observation)) *observation.Observation {
	port := func(v int32) *int32 { return &v }
	obs := &observation.Observation{
		SchemaVersion:   observation.SchemaVersion,
		ID:              "31deea5d1f86a8e8026319623eb2be64",
		EventTime:       time.Date(2026, 9, 9, 14, 0, 0, 0, time.UTC),
		ObservedAt:      time.Date(2026, 9, 9, 14, 0, 0, 0, time.UTC),
		Source:          observation.Source{Kind: observation.SourceHubble, Version: "1.16"},
		Target:          observation.Target{Node: testNode},
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

// recordingCommitter stands in for the audit sink.
//
// It records what was committed and can be made to fail, which is the only way
// to test the fail-closed rule: a capture whose intent could not be durably
// recorded must not exist (FR-036).
type recordingCommitter struct {
	mu      sync.Mutex
	records []audit.Record
	err     error

	// steps is a shared log the fake client also writes to, so a test can
	// assert the commit happened before the create rather than merely that
	// both happened.
	steps *[]string
}

func (c *recordingCommitter) Commit(_ context.Context, rec audit.Record) (audit.CommitResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, rec)
	if c.steps != nil {
		*c.steps = append(*c.steps, "audit:"+rec.Decision)
	}
	if c.err != nil {
		return audit.CommitResult{Result: audit.ResultUnavailable}, c.err
	}
	return audit.CommitResult{Result: audit.ResultSuccess, LedgerKey: "audit/v1/records/x"}, nil
}

// commits counts the policy-created-capture records at one decision. The action
// is fixed because it is the only one this engine writes; a second action here
// would be a record nothing in the contract's audit enum accounts for.
func (c *recordingCommitter) commits(decision string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, r := range c.records {
		if r.Action == audit.ActionCaptureJobPolicyCreate && r.Decision == decision {
			n++
		}
	}
	return n
}

// testScheme carries the Trawl types plus core, which the tap and job objects
// need.
func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatalf("adding client-go scheme: %v", err)
	}
	if err := trawlv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("adding trawl scheme: %v", err)
	}
	return s
}

// activeTap is a NetworkTap observing on testNode with a fresh heartbeat - the
// state a policy needs in order to have somewhere to capture.
func activeTap(mutate ...func(*trawlv1alpha1.NetworkTap)) *trawlv1alpha1.NetworkTap {
	tap := &trawlv1alpha1.NetworkTap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  testNamespace,
			Name:       "node-eno1",
			UID:        testTapUID,
			Generation: 1,
		},
		Status: trawlv1alpha1.NetworkTapStatus{
			ObservedGeneration: 1,
			Phase:              trawlv1alpha1.TapPhaseActive,
			Targets: []trawlv1alpha1.TargetStatus{{
				NodeName:      testNode,
				Interface:     "eno1",
				HeartbeatTime: metav1.NewTime(evaluatedAt.Add(-10 * time.Second)),
			}},
			Conditions: []metav1.Condition{{
				Type:               status.TypeAccepted,
				Status:             metav1.ConditionTrue,
				Reason:             status.ReasonAccepted,
				ObservedGeneration: 1,
				LastTransitionTime: metav1.NewTime(evaluatedAt.Add(-time.Hour)),
			}},
		},
	}
	for _, m := range mutate {
		m(tap)
	}
	return tap
}

// suricataPolicy is an armed policy matching the alert() helper's severity.
func suricataPolicy(mutate ...func(*trawlv1alpha1.CapturePolicy)) *trawlv1alpha1.CapturePolicy {
	p := &trawlv1alpha1.CapturePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  testNamespace,
			Name:       "ssh-scan",
			UID:        policyUID,
			Generation: 3,
		},
		Spec: trawlv1alpha1.CapturePolicySpec{
			TapRef: corev1.LocalObjectReference{Name: "node-eno1"},
			Armed:  true,
			Trigger: trawlv1alpha1.CapturePolicyTrigger{
				Type:          trawlv1alpha1.CaptureTriggerSuricataAlert,
				SuricataAlert: &trawlv1alpha1.SuricataAlertTrigger{Severities: []int32{1, 2}},
			},
			Capture: trawlv1alpha1.PolicyCaptureBounds{
				Duration: "30s",
				MaxSize:  resource.MustParse("64Mi"),
			},
			Retention: "7d",
			RateLimit: trawlv1alpha1.CaptureRateLimit{
				MaxCapturesPerHour: 5,
				Cooldown:           metav1.Duration{Duration: 5 * time.Minute},
			},
		},
	}
	for _, m := range mutate {
		m(p)
	}
	return p
}

// hubblePolicy is an armed policy matching the drop() helper's denial reason.
func hubblePolicy(mutate ...func(*trawlv1alpha1.CapturePolicy)) *trawlv1alpha1.CapturePolicy {
	p := suricataPolicy(func(p *trawlv1alpha1.CapturePolicy) {
		p.Name = "denied-egress"
		p.UID = types.UID("22222222-2222-4222-8222-222222222222")
		p.Spec.Trigger = trawlv1alpha1.CapturePolicyTrigger{
			Type:       trawlv1alpha1.CaptureTriggerHubbleDrop,
			HubbleDrop: &trawlv1alpha1.HubbleDropTrigger{Reasons: []string{"POLICY_DENIED"}},
		}
	})
	for _, m := range mutate {
		m(p)
	}
	return p
}

// engineFixture is one assembled engine and the doubles behind it.
type engineFixture struct {
	engine *PolicyEngine
	client client.Client
	audit  *recordingCommitter
	steps  []string
}

func newEngine(t *testing.T, objs ...client.Object) *engineFixture {
	t.Helper()
	return newEngineWith(t, interceptor.Funcs{}, objs...)
}

func newEngineWith(t *testing.T, funcs interceptor.Funcs, objs ...client.Object) *engineFixture {
	t.Helper()
	f := &engineFixture{}
	f.audit = &recordingCommitter{steps: &f.steps}

	create := funcs.Create
	funcs.Create = func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
		// The typed object carries no GVK when it comes from Go rather than
		// the wire, so the type name is what identifies it here.
		f.steps = append(f.steps, "create:"+reflect.TypeOf(obj).Elem().Name())
		if create != nil {
			return create(ctx, c, obj, opts...)
		}
		return c.Create(ctx, obj, opts...)
	}

	f.client = fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithObjects(objs...).
		WithStatusSubresource(&trawlv1alpha1.NetworkTap{}, &trawlv1alpha1.CapturePolicy{}, &trawlv1alpha1.CaptureJob{}).
		WithInterceptorFuncs(funcs).
		Build()

	f.engine = &PolicyEngine{
		Client:    f.client,
		Audit:     f.audit,
		Actor:     audit.Actor{Username: "system:serviceaccount:trawl-system:trawl-event-worker"},
		Namespace: testNamespace,
		Now:       func() time.Time { return evaluatedAt },
	}
	return f
}

// jobs lists every CaptureJob the engine created.
func (f *engineFixture) jobs(t *testing.T) []trawlv1alpha1.CaptureJob {
	t.Helper()
	var list trawlv1alpha1.CaptureJobList
	if err := f.client.List(context.Background(), &list); err != nil {
		t.Fatalf("listing capture jobs: %v", err)
	}
	return list.Items
}

// evaluate runs one observation through the engine. The error return is
// reserved for "nothing could be evaluated at all", which no test here induces.
func (f *engineFixture) evaluate(t *testing.T, obs *observation.Observation) []PolicyResult {
	t.Helper()
	results, err := f.engine.Evaluate(context.Background(), obs)
	if err != nil {
		t.Fatalf("evaluating: %v", err)
	}
	return results
}

// only returns the single result the engine produced, failing otherwise.
func only(t *testing.T, results []PolicyResult) PolicyResult {
	t.Helper()
	if len(results) != 1 {
		t.Fatalf("got %d results, want exactly 1: %+v", len(results), results)
	}
	return results[0]
}

func TestAMatchingAlertCreatesOneCaptureDescribingWhyItExists(t *testing.T) {
	// The whole point of the engine. A policy-created capture has to explain
	// itself long after the alert has aged out of Loki (FR-032), so the job
	// carries the policy generation that was armed and an immutable snapshot
	// of the event - not a reference to a policy that may since have changed.
	f := newEngine(t, activeTap(), suricataPolicy(func(p *trawlv1alpha1.CapturePolicy) {
		p.Spec.Capture.FilterTemplate = "host {{source.ip}} and port {{destination.port}}"
	}))

	got := only(t, f.evaluate(t, alert()))

	if got.Outcome != OutcomeCreated {
		t.Fatalf("outcome = %s (%v), want Created", got.Outcome, got.Err)
	}
	jobs := f.jobs(t)
	if len(jobs) != 1 {
		t.Fatalf("got %d capture jobs, want 1", len(jobs))
	}
	job := jobs[0]

	if job.Name != got.CaptureName {
		t.Errorf("result names capture %q, but the job is %q", got.CaptureName, job.Name)
	}
	if job.Spec.RequestType != trawlv1alpha1.CaptureRequestPolicy {
		t.Errorf("request type = %q, want Policy", job.Spec.RequestType)
	}
	if job.Spec.TargetNode != testNode {
		t.Errorf("target node = %q, want %q - the node that observed the traffic", job.Spec.TargetNode, testNode)
	}
	if job.Spec.Filter != "host 192.168.0.6 and port 22" {
		t.Errorf("filter = %q, want the template rendered from the alert's flow", job.Spec.Filter)
	}
	if job.Spec.Duration != "30s" || job.Spec.Retention != "7d" {
		t.Errorf("capture bounds = %s/%s, want the policy's 30s/7d", job.Spec.Duration, job.Spec.Retention)
	}
	if job.Spec.PolicyRef == nil {
		t.Fatal("the job carries no policy reference, so nothing records which policy collected this evidence")
	}
	if job.Spec.PolicyRef.UID != policyUID || job.Spec.PolicyRef.Generation != 3 {
		t.Errorf("policy ref = %+v, want the armed policy's UID and generation 3", *job.Spec.PolicyRef)
	}
	if job.Spec.Trigger == nil || job.Spec.Trigger.Suricata == nil {
		t.Fatal("the job carries no trigger snapshot")
	}
	if job.Spec.Trigger.Suricata.RuleID != 2038968 {
		t.Errorf("snapshot rule ID = %d, want the alert's 2038968", job.Spec.Trigger.Suricata.RuleID)
	}
	if job.Spec.DeduplicationKey == "" {
		t.Error("the job carries no deduplication key, so a repeat of this event cannot collapse onto it")
	}
}

func TestACreatedCaptureIsNotOwnedByThePolicyThatAskedForIt(t *testing.T) {
	// Deliberately no owner reference. An owner reference would make the
	// capture garbage-collected when the policy is deleted, and the capture is
	// evidence: deleting the rule that collected it must not delete what it
	// collected. The policy reference on the spec records the relationship
	// without handing it the object's lifetime.
	f := newEngine(t, activeTap(), suricataPolicy())

	f.evaluate(t, alert())

	jobs := f.jobs(t)
	if len(jobs) != 1 {
		t.Fatalf("got %d capture jobs, want 1", len(jobs))
	}
	if refs := jobs[0].OwnerReferences; len(refs) != 0 {
		t.Errorf("the capture is owned by %+v; deleting the policy would delete the evidence", refs)
	}
}

func TestTheAuditRecordIsCommittedBeforeTheCaptureExists(t *testing.T) {
	// FR-036 orders these: the intent is durably recorded, then the work
	// happens. Committing after the create would leave a window in which a
	// capture exists that the ledger never authorized, and a crash inside that
	// window makes it permanent.
	f := newEngine(t, activeTap(), suricataPolicy())

	f.evaluate(t, alert())

	if len(f.steps) < 2 {
		t.Fatalf("steps = %v, want an audit commit and a create", f.steps)
	}
	if f.steps[0] != "audit:"+audit.DecisionAllowed {
		t.Errorf("first step = %q, want the allowed audit commit before anything else", f.steps[0])
	}
	if f.steps[1] != "create:CaptureJob" {
		t.Errorf("second step = %q, want the CaptureJob create", f.steps[1])
	}
	if n := f.audit.commits(audit.DecisionSucceeded); n != 1 {
		t.Errorf("committed %d succeeded records, want 1 - the outcome record completes the pair", n)
	}
}

func TestACaptureIsNotCreatedWhenItsIntentCannotBeRecorded(t *testing.T) {
	// Fail closed (FR-036). A capture the ledger does not know about is
	// evidence with no provenance, which is worse than no capture: it cannot be
	// relied on and it consumed the policy's budget anyway.
	f := newEngine(t, activeTap(), suricataPolicy())
	f.audit.err = errors.New("audit sink unavailable")

	got := only(t, f.evaluate(t, alert()))

	if got.Outcome != OutcomeFailed {
		t.Errorf("outcome = %s, want Failed when the audit commit fails", got.Outcome)
	}
	if jobs := f.jobs(t); len(jobs) != 0 {
		t.Errorf("got %d capture jobs, want none - the intent was never recorded", len(jobs))
	}
}

func TestARepeatOfTheSameEventCollapsesOntoTheExistingCapture(t *testing.T) {
	// FR-031: at most one capture for the equivalent source and traffic within
	// the cooldown. The second evaluation must find the first job by its
	// deterministic name rather than create a second capture of the same
	// conversation.
	f := newEngine(t, activeTap(), suricataPolicy())

	first := only(t, f.evaluate(t, alert()))
	second := only(t, f.evaluate(t, alert(func(o *observation.Observation) {
		// A different record - the same conversation alerting again a moment
		// later, well inside the five-minute cooldown.
		o.ID = "0e1cb0c6a3b04b4fa2a1f2a44f2b9a01"
		o.ObservedAt = o.ObservedAt.Add(30 * time.Second)
	})))

	if second.Outcome != OutcomeDuplicate {
		t.Errorf("second outcome = %s, want Duplicate", second.Outcome)
	}
	if second.CaptureName != first.CaptureName {
		t.Errorf("second names capture %q, want the existing %q", second.CaptureName, first.CaptureName)
	}
	if jobs := f.jobs(t); len(jobs) != 1 {
		t.Errorf("got %d capture jobs, want 1 - the repeat should have collapsed", len(jobs))
	}
}

func TestHubbleCaptureIdentityDoesNotChangeWhenRedeliveryCrossesACooldownBoundary(t *testing.T) {
	// Hubble reconstructs ObservedAt when it normalizes each delivery. EventTime
	// and ID describe the immutable occurrence. Using the fresh delivery time
	// in the cooldown bucket lets reconnect replay manufacture a second
	// privileged capture for the same flow.
	f := newEngine(t, activeTap(), hubblePolicy())

	first := only(t, f.evaluate(t, drop()))
	replayed := only(t, f.evaluate(t, drop(func(o *observation.Observation) {
		o.ObservedAt = o.ObservedAt.Add(10 * time.Minute)
	})))

	if first.Outcome != OutcomeCreated {
		t.Fatalf("first outcome = %s (%v), want Created", first.Outcome, first.Err)
	}
	if replayed.Outcome != OutcomeDuplicate {
		t.Fatalf("replayed outcome = %s (%v), want Duplicate", replayed.Outcome, replayed.Err)
	}
	if replayed.CaptureName != first.CaptureName {
		t.Errorf("redelivery names capture %q, want original %q", replayed.CaptureName, first.CaptureName)
	}

	newOccurrence := only(t, f.evaluate(t, drop(func(o *observation.Observation) {
		o.ID = "genuinely-later-flow"
		o.EventTime = o.EventTime.Add(10 * time.Minute)
		o.ObservedAt = o.ObservedAt.Add(10 * time.Minute)
	})))
	if newOccurrence.Outcome != OutcomeCreated {
		t.Fatalf("later occurrence outcome = %s (%v), want Created", newOccurrence.Outcome, newOccurrence.Err)
	}
	if newOccurrence.CaptureName == first.CaptureName {
		t.Error("genuinely later occurrence collapsed onto the earlier cooldown bucket")
	}
}

func TestLosingTheCreateRaceAdoptsTheExistingCapture(t *testing.T) {
	// Two workers can evaluate the same event at once - during a leader
	// handoff, the old leader may still be draining. Both propose the same
	// name, so the loser gets AlreadyExists. Treating that as a failure would
	// report a capture that does not exist as lost; it is the deduplication
	// working.
	existing := "already-there"
	f := newEngineWith(t, interceptor.Funcs{
		Create: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.CreateOption) error {
			return apierrors.NewAlreadyExists(
				trawlv1alpha1.GroupVersion.WithResource("capturejobs").GroupResource(), obj.GetName())
		},
	}, activeTap(), suricataPolicy())
	_ = existing

	got := only(t, f.evaluate(t, alert()))

	if got.Outcome != OutcomeDuplicate {
		t.Errorf("outcome = %s (%v), want Duplicate when the create loses the race", got.Outcome, got.Err)
	}
	if got.CaptureName == "" {
		t.Error("the result names no capture, so the policy cannot report what its event collapsed into")
	}
}

func TestTwoPoliciesMatchingOneEventCollapseToOneCapture(t *testing.T) {
	// Settled deliberately: the deduplication key covers the tap, the flow and
	// the cooldown bucket, and not the policy. Two policies wanting the same
	// packets get one capture rather than two of the same conversation
	// (spec.md, "Several policies may match one event"). Both policies still
	// record a decision - the second one's is Duplicate.
	second := suricataPolicy(func(p *trawlv1alpha1.CapturePolicy) {
		p.Name = "any-alert"
		p.UID = types.UID("33333333-3333-4333-8333-333333333333")
	})
	f := newEngine(t, activeTap(), suricataPolicy(), second)

	results := f.evaluate(t, alert())

	if len(results) != 2 {
		t.Fatalf("got %d results, want one per matching policy: %+v", len(results), results)
	}
	outcomes := map[PolicyOutcome]int{}
	for _, r := range results {
		outcomes[r.Outcome]++
	}
	if outcomes[OutcomeCreated] != 1 || outcomes[OutcomeDuplicate] != 1 {
		t.Errorf("outcomes = %v, want one Created and one Duplicate", outcomes)
	}
	if jobs := f.jobs(t); len(jobs) != 1 {
		t.Errorf("got %d capture jobs, want 1", len(jobs))
	}
}

func TestOnePolicysFailureDoesNotStopAnother(t *testing.T) {
	// FR-038. The policies share a worker, so a failure that escaped one
	// evaluation would silently disarm every other policy on the same event -
	// the failure mode where one bad rule takes out the monitoring.
	broken := hubblePolicy(func(p *trawlv1alpha1.CapturePolicy) {
		p.Name = "broken-tap"
		p.UID = types.UID("44444444-4444-4444-8444-444444444444")
		p.Spec.TapRef.Name = "no-such-tap"
	})
	f := newEngine(t, activeTap(), broken, hubblePolicy())

	results := f.evaluate(t, drop())

	if len(results) != 2 {
		t.Fatalf("got %d results, want one per policy: %+v", len(results), results)
	}
	var sawFailed, sawCreated bool
	for _, r := range results {
		switch r.Outcome {
		case OutcomeFailed:
			sawFailed = true
		case OutcomeCreated:
			sawCreated = true
		}
	}
	if !sawFailed {
		t.Error("the policy pointing at a missing tap did not report a failure")
	}
	if !sawCreated {
		t.Error("the healthy policy did not capture; one policy's failure stopped another")
	}
}

func TestThePolicyStopsCapturingAtItsHourlyLimit(t *testing.T) {
	// The limit is counted from the policy's own CaptureJobs, so it holds
	// across restarts. Reaching it suppresses the capture and records the
	// decision - the policy recovers on its own as captures age out.
	objs := make([]client.Object, 0, 7)
	objs = append(objs, activeTap(), suricataPolicy())
	for i := range 5 {
		at := metav1.NewTime(evaluatedAt.Add(-time.Duration(i+1) * time.Minute))
		objs = append(objs, &trawlv1alpha1.CaptureJob{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: testNamespace,
				Name:      "trawl-policy-earlier-" + strconv.Itoa(i),
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
			Status: trawlv1alpha1.CaptureJobStatus{
				Phase:       trawlv1alpha1.CapturePhaseCompleted,
				RequestedAt: &at,
			},
		})
	}
	f := newEngine(t, objs...)

	got := only(t, f.evaluate(t, alert()))

	if got.Outcome != OutcomeRateLimited {
		t.Fatalf("outcome = %s, want RateLimited at five captures with a limit of five", got.Outcome)
	}
	if n := len(f.jobs(t)); n != 5 {
		t.Errorf("got %d capture jobs, want the 5 that already existed", n)
	}
	if n := f.audit.commits(audit.DecisionAllowed); n != 0 {
		t.Errorf("committed %d intent records for a capture that was never requested, want 0", n)
	}
}

func TestADisarmedPolicyReportsWhatItWouldHaveCapturedWithoutCapturing(t *testing.T) {
	// Arming is the act that starts collecting packets, so a disarmed policy
	// must create nothing. It is still worth evaluating: "this rule would have
	// fired eleven times today" is what an operator needs in order to decide
	// whether to arm it, and it costs one pure match per event.
	f := newEngine(t, activeTap(), suricataPolicy(func(p *trawlv1alpha1.CapturePolicy) {
		p.Spec.Armed = false
	}))

	got := only(t, f.evaluate(t, alert()))

	if got.Outcome != OutcomeDisarmed {
		t.Errorf("outcome = %s, want Disarmed", got.Outcome)
	}
	if jobs := f.jobs(t); len(jobs) != 0 {
		t.Errorf("a disarmed policy created %d captures, want none", len(jobs))
	}
	if n := f.audit.commits(audit.DecisionAllowed); n != 0 {
		t.Errorf("a disarmed policy committed %d capture intents, want none", n)
	}
}

func TestADisarmedPolicyIsSilentAboutEventsItWouldNotHaveMatched(t *testing.T) {
	// The other half. If a disarmed policy reported every event it declined,
	// its counters would climb with ordinary traffic and say nothing about the
	// rule.
	f := newEngine(t, activeTap(), suricataPolicy(func(p *trawlv1alpha1.CapturePolicy) {
		p.Spec.Armed = false
		p.Spec.Trigger.SuricataAlert.Severities = []int32{1}
	}))

	results := f.evaluate(t, alert())

	if len(results) != 0 {
		t.Errorf("got %+v, want no result for a disarmed policy that did not match", results)
	}
}

func TestAnEventThatDoesNotMatchIsReportedWithItsReason(t *testing.T) {
	// The reason is what separates "the policy is watching and the traffic is
	// quiet" from "the policy is narrower than the operator thinks".
	f := newEngine(t, activeTap(), suricataPolicy(func(p *trawlv1alpha1.CapturePolicy) {
		p.Spec.Trigger.SuricataAlert.Severities = []int32{1}
	}))

	got := only(t, f.evaluate(t, alert()))

	if got.Outcome != OutcomeNotMatched {
		t.Fatalf("outcome = %s, want NotMatched", got.Outcome)
	}
	if got.Reason != policy.ReasonSeverityNotListed {
		t.Errorf("reason = %q, want SeverityNotListed", got.Reason)
	}
	if jobs := f.jobs(t); len(jobs) != 0 {
		t.Errorf("a non-matching event created %d captures", len(jobs))
	}
}

func TestAnAlertFromAnotherTapIsNotThisPolicysTraffic(t *testing.T) {
	// A policy watches one tap. An alert carrying a different tap's identity
	// describes traffic this policy never armed against, and capturing on its
	// own tap in response would collect the wrong packets entirely.
	f := newEngine(t, activeTap(), suricataPolicy())

	got := only(t, f.evaluate(t, alert(func(o *observation.Observation) {
		o.Tap = &observation.Tap{Namespace: testNamespace, Name: "other-tap", UID: "other-uid"}
	})))

	if got.Outcome != OutcomeNotMatched {
		t.Errorf("outcome = %s, want NotMatched for another tap's alert", got.Outcome)
	}
	if jobs := f.jobs(t); len(jobs) != 0 {
		t.Errorf("another tap's alert created %d captures", len(jobs))
	}
}

func TestAnAlertFromARecreatedTapUnderTheSameNameIsNotMatched(t *testing.T) {
	// A tap deleted and recreated keeps its name and gets a new UID. An
	// observation still in flight from the old one describes an observation
	// point that no longer exists, and attributing it to the new tap would
	// silently mix two taps' evidence.
	f := newEngine(t, activeTap(), suricataPolicy())

	got := only(t, f.evaluate(t, alert(func(o *observation.Observation) {
		o.Tap = &observation.Tap{Namespace: testNamespace, Name: "node-eno1", UID: "stale-uid"}
	})))

	if got.Outcome != OutcomeNotMatched {
		t.Errorf("outcome = %s, want NotMatched for a stale tap UID", got.Outcome)
	}
}

func TestACaptureWithNoEligibleTargetIsStillRecorded(t *testing.T) {
	// FR-034 wants the failure visible on both the policy and the attempted
	// execution. A capture request that is simply dropped leaves nothing to
	// look at: the policy's counters move and no object explains why. Creating
	// the job without a target node is what gives the controller something to
	// fail, in the open, with a reason.
	stale := activeTap(func(tap *trawlv1alpha1.NetworkTap) {
		tap.Status.Targets[0].HeartbeatTime = metav1.NewTime(evaluatedAt.Add(-10 * time.Minute))
	})
	f := newEngine(t, stale, suricataPolicy())

	got := only(t, f.evaluate(t, alert()))

	if got.Outcome != OutcomeCreated {
		t.Fatalf("outcome = %s (%v), want Created - the attempt must be recorded", got.Outcome, got.Err)
	}
	jobs := f.jobs(t)
	if len(jobs) != 1 {
		t.Fatalf("got %d capture jobs, want 1", len(jobs))
	}
	if jobs[0].Spec.TargetNode != "" {
		t.Errorf("target node = %q, want empty - no target was eligible", jobs[0].Spec.TargetNode)
	}
}

func TestAFilterTemplateThatCannotBeRenderedDoesNotCapture(t *testing.T) {
	// The rendered filter is the difference between capturing the implicated
	// conversation and capturing everything on the interface. An event that
	// cannot supply the placeholders is not a reason to fall back to a wider
	// capture - it is a reason to refuse and say so.
	f := newEngine(t, activeTap(), suricataPolicy(func(p *trawlv1alpha1.CapturePolicy) {
		p.Spec.Capture.FilterTemplate = "host {{source.ip}}"
	}))

	got := only(t, f.evaluate(t, alert(func(o *observation.Observation) {
		o.Flow = nil
	})))

	if got.Outcome != OutcomeFailed {
		t.Fatalf("outcome = %s, want Failed when the filter cannot be rendered", got.Outcome)
	}
	if jobs := f.jobs(t); len(jobs) != 0 {
		t.Errorf("got %d capture jobs, want none rather than one capturing everything", len(jobs))
	}
}

func TestADropBelowItsThresholdDoesNotCaptureYet(t *testing.T) {
	// A threshold policy is armed against a rate, not an event. Capturing on
	// the first drop would defeat the operator's own statement that one denial
	// is not interesting.
	f := newEngine(t, activeTap(), hubblePolicy(func(p *trawlv1alpha1.CapturePolicy) {
		p.Spec.Trigger.HubbleDrop.Threshold = &trawlv1alpha1.DropThreshold{
			Count:  3,
			Window: metav1.Duration{Duration: time.Minute},
		}
	}))

	got := only(t, f.evaluate(t, drop()))

	if got.Outcome != OutcomeNotMatched {
		t.Fatalf("outcome = %s, want NotMatched below the threshold", got.Outcome)
	}
	if got.Reason != policy.ReasonBelowThreshold {
		t.Errorf("reason = %q, want BelowThreshold", got.Reason)
	}
}

func TestADropCapturesOnceItsThresholdIsReached(t *testing.T) {
	// And the window has to be kept across events, or a threshold policy could
	// never fire at all.
	f := newEngine(t, activeTap(), hubblePolicy(func(p *trawlv1alpha1.CapturePolicy) {
		p.Spec.Trigger.HubbleDrop.Threshold = &trawlv1alpha1.DropThreshold{
			Count:  3,
			Window: metav1.Duration{Duration: time.Minute},
		}
	}))

	var last PolicyResult
	for i := range 3 {
		last = only(t, f.evaluate(t, drop(func(o *observation.Observation) {
			o.ID = "drop-" + strconv.Itoa(i)
			o.ObservedAt = o.ObservedAt.Add(time.Duration(i) * time.Second)
		})))
	}

	if last.Outcome != OutcomeCreated {
		t.Fatalf("outcome on the third drop = %s (%v), want Created", last.Outcome, last.Err)
	}
	jobs := f.jobs(t)
	if len(jobs) != 1 {
		t.Fatalf("got %d capture jobs, want 1", len(jobs))
	}
	if jobs[0].Spec.Trigger == nil || jobs[0].Spec.Trigger.Hubble == nil {
		t.Fatal("the job carries no Hubble trigger snapshot")
	}
	if got := jobs[0].Spec.Trigger.Hubble.Count; got != 3 {
		t.Errorf("snapshot count = %d, want the 3 drops that met the threshold", got)
	}
	if got := jobs[0].Spec.Trigger.Hubble.Reason; got != "POLICY_DENIED" {
		t.Errorf("snapshot reason = %q, want POLICY_DENIED", got)
	}
}

func TestAnAlertIsNotOfferedToADenialPolicy(t *testing.T) {
	// The worker reads both streams and offers every record to the engine.
	// Evaluating a Suricata alert against a denied-flow trigger would spend a
	// tap read and a match per policy per event for a decision that is already
	// known from the source kind.
	f := newEngine(t, activeTap(), hubblePolicy())

	results := f.evaluate(t, alert())

	if len(results) != 0 {
		t.Errorf("got %+v, want no results - a Suricata alert is not a denied flow", results)
	}
}

func TestTheRaceLoserStillCompletesItsLedgerPair(t *testing.T) {
	// An intent record is committed before the create. When the create loses the
	// race the capture exists, made by the other worker - but this worker's
	// ledger entry would be an intent with no outcome, which is the shape an
	// operator reads as "a capture was authorized and then went missing". The
	// one situation the ledger must not describe as evidence disappearing is the
	// one where the evidence is fine.
	f := newEngineWith(t, interceptor.Funcs{
		Create: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.CreateOption) error {
			return apierrors.NewAlreadyExists(
				trawlv1alpha1.GroupVersion.WithResource("capturejobs").GroupResource(), obj.GetName())
		},
	}, activeTap(), suricataPolicy())

	got := only(t, f.evaluate(t, alert()))

	if got.Outcome != OutcomeDuplicate {
		t.Fatalf("outcome = %s, want Duplicate", got.Outcome)
	}
	if n := f.audit.commits(audit.DecisionAllowed); n != 1 {
		t.Errorf("committed %d intent records, want 1", n)
	}
	if n := f.audit.commits(audit.DecisionSucceeded); n != 1 {
		t.Errorf("committed %d outcome records, want 1 - the intent is dangling without it", n)
	}
}

func TestEditingAnUnrelatedFieldDoesNotDiscardTheThresholdWindow(t *testing.T) {
	// A rolling window is state gathered over minutes. Rebuilding it on any
	// generation bump meant that arming a policy, changing its retention, or
	// raising its hourly limit silently threw away a count that might have been
	// one flow from firing - and nothing anywhere would record that it had
	// happened.
	f := newEngine(t, activeTap(), hubblePolicy(func(p *trawlv1alpha1.CapturePolicy) {
		p.Spec.Trigger.HubbleDrop.Threshold = &trawlv1alpha1.DropThreshold{
			Count:  3,
			Window: metav1.Duration{Duration: time.Minute},
		}
	}))
	ctx := context.Background()

	for i := range 2 {
		f.evaluate(t, drop(func(o *observation.Observation) {
			o.ID = "drop-" + strconv.Itoa(i)
			o.ObservedAt = o.ObservedAt.Add(time.Duration(i) * time.Second)
		}))
	}

	// An edit that has nothing to do with the threshold.
	var p trawlv1alpha1.CapturePolicy
	key := types.NamespacedName{Namespace: testNamespace, Name: "denied-egress"}
	if err := f.client.Get(ctx, key, &p); err != nil {
		t.Fatalf("reading the policy: %v", err)
	}
	p.Spec.Retention = "3d"
	p.Generation++
	if err := f.client.Update(ctx, &p); err != nil {
		t.Fatalf("updating the policy: %v", err)
	}

	got := only(t, f.evaluate(t, drop(func(o *observation.Observation) {
		o.ID = "drop-2"
		o.ObservedAt = o.ObservedAt.Add(2 * time.Second)
	})))

	if got.Outcome != OutcomeCreated {
		t.Errorf("outcome on the third drop = %s (%v), want Created - the window was discarded",
			got.Outcome, got.Err)
	}
}

func TestChangingTheThresholdDoesDiscardTheWindow(t *testing.T) {
	// The other direction, and the reason the rebuild exists at all. An operator
	// who narrows a window expects the new one to apply; carrying the old counts
	// forward would fire the policy on a threshold nobody has written down.
	f := newEngine(t, activeTap(), hubblePolicy(func(p *trawlv1alpha1.CapturePolicy) {
		p.Spec.Trigger.HubbleDrop.Threshold = &trawlv1alpha1.DropThreshold{
			Count:  3,
			Window: metav1.Duration{Duration: time.Minute},
		}
	}))
	ctx := context.Background()

	for i := range 2 {
		f.evaluate(t, drop(func(o *observation.Observation) {
			o.ID = "drop-" + strconv.Itoa(i)
			o.ObservedAt = o.ObservedAt.Add(time.Duration(i) * time.Second)
		}))
	}

	var p trawlv1alpha1.CapturePolicy
	key := types.NamespacedName{Namespace: testNamespace, Name: "denied-egress"}
	if err := f.client.Get(ctx, key, &p); err != nil {
		t.Fatalf("reading the policy: %v", err)
	}
	p.Spec.Trigger.HubbleDrop.Threshold.Count = 4
	p.Generation++
	if err := f.client.Update(ctx, &p); err != nil {
		t.Fatalf("updating the policy: %v", err)
	}

	got := only(t, f.evaluate(t, drop(func(o *observation.Observation) {
		o.ID = "drop-2"
		o.ObservedAt = o.ObservedAt.Add(2 * time.Second)
	})))

	if got.Outcome != OutcomeNotMatched || got.Reason != policy.ReasonBelowThreshold {
		t.Errorf("outcome = %s/%s, want NotMatched/BelowThreshold on a rebuilt window",
			got.Outcome, got.Reason)
	}
}

func TestAClusterQualifiedNodeNameResolvesNoTarget(t *testing.T) {
	// Hubble can report the observing node as "<cluster>/<node>" depending on
	// the Cilium version and its cluster configuration. Stripping the qualifier
	// to make it match looks like the obvious fix and is the wrong one: under
	// ClusterMesh the relay serves flows from peer clusters, node names repeat
	// across them, and "prod-eu/worker-1" would match a healthy local target
	// called "worker-1". The capture would collect the local node's unrelated
	// traffic and file it as evidence for a flow in another cluster.
	//
	// So the comparison stays exact and this fails the loud way: a capture with
	// no target, which the capture controller fails naming the node. Withholding
	// evidence is recoverable; manufacturing the wrong evidence is not.
	f := newEngine(t, activeTap(), hubblePolicy())

	got := only(t, f.evaluate(t, drop(func(o *observation.Observation) {
		o.Target.Node = "prod-eu/" + testNode
	})))

	if got.Outcome != OutcomeCreated {
		t.Fatalf("outcome = %s (%v), want Created - the attempt must still be recorded", got.Outcome, got.Err)
	}
	jobs := f.jobs(t)
	if len(jobs) != 1 {
		t.Fatalf("got %d captures, want 1", len(jobs))
	}
	if jobs[0].Spec.TargetNode != "" {
		t.Errorf("target node = %q, want empty - a qualified name may name another cluster's node",
			jobs[0].Spec.TargetNode)
	}
}

// realLedger is the actual sink over an in-memory store.
//
// recordingCommitter cannot answer the question below: it returns success for
// anything and does no stable-key resolution, so two records claiming one
// identity with different content look identical to it. That is exactly the
// defect this test exists to catch, and it is why the fake is not enough here.
func realLedger(t *testing.T) *audit.Sink {
	t.Helper()
	sink, err := audit.NewSink(audit.Options{
		Store:     storage.NewFake(),
		Prefix:    audit.DefaultPrefix,
		Retention: 90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("building the audit sink: %v", err)
	}
	return sink
}

func TestTwoWorkersRacingWriteOneLedgerPairAndNoConflict(t *testing.T) {
	// A stable key is an identity claim. Two records claiming one identity with
	// different content is an integrity error by construction - the sink refuses
	// the second and counts a conflict - and a deduplication race is the one
	// situation where that must not happen, because nothing is actually wrong.
	//
	// Both workers derive the same deduplication key from the same event and the
	// same policy, so both derive the same stable keys. Their records therefore
	// have to be byte-identical for the same act, or the loser turns a healthy
	// collapse into an integrity alarm an operator has to go and disprove.
	ledger := realLedger(t)

	winner := newEngine(t, activeTap(), suricataPolicy())
	winner.engine.Audit = ledger

	// The second worker sees the same cluster state but loses the create.
	loser := newEngineWith(t, interceptor.Funcs{
		Create: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.CreateOption) error {
			return apierrors.NewAlreadyExists(
				trawlv1alpha1.GroupVersion.WithResource("capturejobs").GroupResource(), obj.GetName())
		},
	}, activeTap(), suricataPolicy())
	loser.engine.Audit = ledger

	if got := only(t, winner.evaluate(t, alert())).Outcome; got != OutcomeCreated {
		t.Fatalf("the winner's outcome = %s, want Created", got)
	}

	got := only(t, loser.evaluate(t, alert()))

	if got.Outcome != OutcomeDuplicate {
		t.Fatalf("the loser's outcome = %s, want Duplicate", got.Outcome)
	}
	if got.Err != nil {
		t.Errorf("the loser reported %v; a collapse onto an existing capture is "+
			"the deduplication working, not something to raise against the ledger", got.Err)
	}
}

func TestAFailedCaptureAndASucceededOneDoNotClaimTheSameLedgerIdentity(t *testing.T) {
	// The outcome half of the pair carries a decision, and the two decisions are
	// different acts. Keyed without it, a worker whose create failed and a worker
	// whose create succeeded would write two different records under one
	// identity - and the ledger would report the disagreement rather than the
	// two outcomes.
	ledger := realLedger(t)

	failing := newEngineWith(t, interceptor.Funcs{
		Create: func(_ context.Context, _ client.WithWatch, _ client.Object, _ ...client.CreateOption) error {
			return apierrors.NewInternalError(errors.New("the API server is unavailable"))
		},
	}, activeTap(), suricataPolicy())
	failing.engine.Audit = ledger

	if got := only(t, failing.evaluate(t, alert())).Outcome; got != OutcomeFailed {
		t.Fatalf("outcome = %s, want Failed", got)
	}

	// The same event, the same policy, now succeeding - as it would on a retry
	// or from the other worker.
	succeeding := newEngine(t, activeTap(), suricataPolicy())
	succeeding.engine.Audit = ledger

	got := only(t, succeeding.evaluate(t, alert()))

	if got.Outcome != OutcomeCreated {
		t.Fatalf("outcome = %s (%v), want Created", got.Outcome, got.Err)
	}
	if got.Err != nil {
		t.Errorf("recording the successful outcome reported %v; it claims the same "+
			"ledger identity as the earlier failure", got.Err)
	}
}
