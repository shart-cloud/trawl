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

package integration

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/audit"
	"trawl.cloud/trawl/internal/controller"
	"trawl.cloud/trawl/internal/observation"
	"trawl.cloud/trawl/internal/status"
)

// T102. These run against a real API server because the thing most likely to be
// wrong about a policy-created CaptureJob is not the logic that built it but
// whether the API server will accept it. The CaptureJob schema carries a dozen
// CEL rules about what a Policy request must and must not carry, and a fake
// client enforces none of them: an engine that builds a job the cluster rejects
// passes every unit test it has and captures nothing.

// ledger records what the engine committed, and can be made to fail.
type ledger struct {
	mu      sync.Mutex
	records []audit.Record
	fail    bool
}

func (l *ledger) Commit(_ context.Context, rec audit.Record) (audit.CommitResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fail {
		return audit.CommitResult{Result: audit.ResultUnavailable}, errors.New("the audit sink is unavailable")
	}
	l.records = append(l.records, rec)
	return audit.CommitResult{Result: audit.ResultSuccess, LedgerKey: "audit/v1/records/x"}, nil
}

func (l *ledger) decisions(decision string) []audit.Record {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []audit.Record
	for _, r := range l.records {
		if r.Decision == decision {
			out = append(out, r)
		}
	}
	return out
}

// workerFixture is one namespace with a tap, an engine and a status tracker.
type workerFixture struct {
	namespace string
	tap       *trawlv1alpha1.NetworkTap
	engine    *controller.PolicyEngine
	tracker   *controller.PolicyStatusTracker
	ledger    *ledger
	now       time.Time
}

func newWorkerFixture(t *testing.T) *workerFixture {
	t.Helper()
	ns := NewNamespace(t)
	f := &workerFixture{
		namespace: ns,
		ledger:    &ledger{},
		now:       time.Now(),
	}
	f.tap = f.observingTap(t)
	f.engine = f.newEngine()
	f.tracker = &controller.PolicyStatusTracker{
		Client:    Client(),
		Namespace: ns,
		Now:       func() time.Time { return f.now },
	}
	return f
}

// newEngine returns a second engine over the same namespace and ledger.
//
// A separate instance is how a leader handoff and a two-worker race are
// expressed here: nothing is shared but the API server and the ledger, which is
// exactly the situation two pods are in.
func (f *workerFixture) newEngine() *controller.PolicyEngine {
	return &controller.PolicyEngine{
		Client:    Client(),
		Policies:  eventReader,
		APIReader: Client(),
		Jobs:      eventReader,
		Audit:     f.ledger,
		Actor:     audit.Actor{Username: "system:serviceaccount:trawl-system:event-worker"},
		Namespace: f.namespace,
		Now:       func() time.Time { return f.now },
	}
}

// observingTap creates a tap reporting a healthy target on node-a.
func (f *workerFixture) observingTap(t *testing.T) *trawlv1alpha1.NetworkTap {
	t.Helper()
	ctx := context.Background()

	tap := &trawlv1alpha1.NetworkTap{
		ObjectMeta: metav1.ObjectMeta{Namespace: f.namespace, Name: "node-eno1"},
		Spec: trawlv1alpha1.NetworkTapSpec{
			Type: trawlv1alpha1.TapSourceMirrorInterface,
			MirrorInterface: &trawlv1alpha1.InterfaceSource{
				Interface:   "eno1",
				Promiscuous: true,
				NodeSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"kubernetes.io/hostname": "node-a"},
				},
			},
			Analyzers: trawlv1alpha1.AnalyzerSelection{
				Suricata: trawlv1alpha1.AnalyzerConfig{Enabled: true, Resources: analyzerResources()},
			},
		},
	}
	if err := Client().Create(ctx, tap); err != nil {
		t.Fatalf("creating the tap: %v", err)
	}

	tap.Status = trawlv1alpha1.NetworkTapStatus{
		ObservedGeneration: tap.Generation,
		Phase:              trawlv1alpha1.TapPhaseActive,
		Targets: []trawlv1alpha1.TargetStatus{{
			NodeName:      "node-a",
			Interface:     "eno1",
			HeartbeatTime: metav1.NewTime(f.now),
		}},
		Conditions: []metav1.Condition{{
			Type:               status.TypeAccepted,
			Status:             metav1.ConditionTrue,
			Reason:             status.ReasonAccepted,
			ObservedGeneration: tap.Generation,
			LastTransitionTime: metav1.NewTime(f.now),
		}},
	}
	if err := Client().Status().Update(ctx, tap); err != nil {
		t.Fatalf("writing tap status: %v", err)
	}
	return tap
}

// armPolicy creates an armed policy against the fixture's tap.
func (f *workerFixture) armPolicy(
	t *testing.T, name string, mutate ...func(*trawlv1alpha1.CapturePolicySpec),
) *trawlv1alpha1.CapturePolicy {
	t.Helper()

	spec := trawlv1alpha1.CapturePolicySpec{
		TapRef:    corev1.LocalObjectReference{Name: f.tap.Name},
		Armed:     true,
		Retention: "7d",
		Trigger: trawlv1alpha1.CapturePolicyTrigger{
			Type:          trawlv1alpha1.CaptureTriggerSuricataAlert,
			SuricataAlert: &trawlv1alpha1.SuricataAlertTrigger{Severities: []int32{1, 2}},
		},
		Capture: trawlv1alpha1.PolicyCaptureBounds{
			Duration: "60s",
			MaxSize:  resource.MustParse("64Mi"),
		},
		RateLimit: trawlv1alpha1.CaptureRateLimit{
			MaxCapturesPerHour: 5,
			Cooldown:           metav1.Duration{Duration: 5 * time.Minute},
		},
	}
	for _, m := range mutate {
		m(&spec)
	}

	p := &trawlv1alpha1.CapturePolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: f.namespace, Name: name},
		Spec:       spec,
	}
	if err := Client().Create(context.Background(), p); err != nil {
		t.Fatalf("creating policy %s: %v", name, err)
	}
	if err := wait.PollUntilContextTimeout(t.Context(), 10*time.Millisecond, 5*time.Second, true,
		func(ctx context.Context) (bool, error) {
			var policies trawlv1alpha1.CapturePolicyList
			if err := eventReader.List(ctx, &policies,
				client.InNamespace(f.namespace),
				client.MatchingFields{
					controller.CapturePolicyTriggerTypeIndex: string(p.Spec.Trigger.Type),
				},
			); err != nil {
				return false, err
			}
			for i := range policies.Items {
				if policies.Items[i].UID == p.UID {
					return true, nil
				}
			}
			return false, nil
		}); err != nil {
		t.Fatalf("waiting for policy %s in the indexed cache: %v", name, err)
	}
	return p
}

// alertOn builds a Suricata alert observed by the fixture's tap on node-a.
func (f *workerFixture) alertOn(id string, mutate ...func(*observation.Observation)) *observation.Observation {
	port := func(v int32) *int32 { return &v }
	obs := &observation.Observation{
		SchemaVersion:   observation.SchemaVersion,
		ID:              id,
		EventTime:       f.now.Add(-30 * time.Second),
		ObservedAt:      f.now.Add(-30 * time.Second),
		Source:          observation.Source{Kind: observation.SourceSuricata, Version: "8.0.6"},
		Tap:             &observation.Tap{Namespace: f.namespace, Name: f.tap.Name, UID: string(f.tap.UID)},
		Target:          observation.Target{Node: "node-a", Interface: "eno1"},
		ObservationType: observation.TypeSignature,
		Flow: &observation.Flow{
			Protocol:    "tcp",
			Source:      observation.Endpoint{IP: "192.0.2.10", Port: port(39510)},
			Destination: observation.Endpoint{IP: "198.51.100.20", Port: port(22)},
		},
		Details: observation.Details{Signature: &observation.Signature{
			RuleID: 2038968, Severity: 2, Category: "Misc activity",
			Message: "ET INFO SSH-2.0-Go version string Observed in Network Traffic",
		}},
	}
	for _, m := range mutate {
		m(obs)
	}
	return obs
}

func (f *workerFixture) evaluate(t *testing.T, obs *observation.Observation) []controller.PolicyResult {
	t.Helper()
	results, err := f.engine.Evaluate(context.Background(), obs)
	if err != nil {
		t.Fatalf("evaluating: %v", err)
	}
	return results
}

func (f *workerFixture) captures(t *testing.T) []trawlv1alpha1.CaptureJob {
	t.Helper()
	var list trawlv1alpha1.CaptureJobList
	if err := Client().List(context.Background(), &list, client.InNamespace(f.namespace)); err != nil {
		t.Fatalf("listing captures: %v", err)
	}
	return list.Items
}

func (f *workerFixture) readPolicy(t *testing.T, name string) trawlv1alpha1.CapturePolicy {
	t.Helper()
	var p trawlv1alpha1.CapturePolicy
	key := types.NamespacedName{Namespace: f.namespace, Name: name}
	if err := Client().Get(context.Background(), key, &p); err != nil {
		t.Fatalf("reading policy %s: %v", name, err)
	}
	return p
}

func TestThePolicyCreatedCaptureIsAdmittedByTheAPIServer(t *testing.T) {
	// The test this file exists for. CaptureJobSpec carries CEL rules that a
	// Policy request must satisfy - policyRef, trigger and deduplicationKey all
	// present, no targetNode requirement, bounds in range - and none of them run
	// against a fake client. An engine that builds a job the cluster refuses
	// would pass every unit test and capture nothing.
	f := newWorkerFixture(t)
	f.armPolicy(t, "ssh-scan", func(s *trawlv1alpha1.CapturePolicySpec) {
		s.Capture.FilterTemplate = "host {{source.ip}} and port {{destination.port}}"
	})

	results := f.evaluate(t, f.alertOn("4125e22fe6fad350aa771423a45c643e"))

	if len(results) != 1 || results[0].Outcome != controller.OutcomeCreated {
		t.Fatalf("results = %+v, want one Created", results)
	}
	jobs := f.captures(t)
	if len(jobs) != 1 {
		t.Fatalf("got %d captures, want 1", len(jobs))
	}
	job := jobs[0]

	if job.Spec.RequestType != trawlv1alpha1.CaptureRequestPolicy {
		t.Errorf("requestType = %q, want Policy", job.Spec.RequestType)
	}
	if job.Spec.TargetNode != "node-a" {
		t.Errorf("targetNode = %q, want node-a", job.Spec.TargetNode)
	}
	if job.Spec.Filter != "host 192.0.2.10 and port 22" {
		t.Errorf("filter = %q, want the template rendered from the alert", job.Spec.Filter)
	}
	if job.Spec.Trigger == nil || job.Spec.Trigger.Suricata == nil {
		t.Fatal("the admitted job carries no Suricata trigger snapshot")
	}
	if job.Spec.Trigger.Suricata.RuleID != 2038968 {
		t.Errorf("snapshot rule ID = %d, want 2038968", job.Spec.Trigger.Suricata.RuleID)
	}
	// Both are pattern-validated as sha256 digests by the schema, so a
	// malformed one is a rejection rather than a wrong string.
	if job.Spec.DeduplicationKey == "" || job.Spec.Trigger.Fingerprint == "" {
		t.Error("the admitted job is missing its deduplication key or event fingerprint")
	}
}

func TestACaptureWithNoEligibleTargetIsAdmittedWithoutOne(t *testing.T) {
	// The CaptureJob schema requires targetNode for a Manual request and allows
	// a Policy request to omit it, precisely so a failed target resolution has
	// an object to be visible on (FR-034). That rule only means anything if the
	// API server actually admits such a job.
	f := newWorkerFixture(t)
	f.armPolicy(t, "ssh-scan")

	results := f.evaluate(t, f.alertOn("aa25e22fe6fad350aa771423a45c643e", func(o *observation.Observation) {
		o.Target.Node = "a-node-with-no-sensor"
	}))

	if len(results) != 1 || results[0].Outcome != controller.OutcomeCreated {
		t.Fatalf("results = %+v, want one Created", results)
	}
	jobs := f.captures(t)
	if len(jobs) != 1 {
		t.Fatalf("got %d captures, want 1", len(jobs))
	}
	if jobs[0].Spec.TargetNode != "" {
		t.Errorf("targetNode = %q, want empty", jobs[0].Spec.TargetNode)
	}
}

func TestTheIntentIsInTheLedgerBeforeTheCaptureExists(t *testing.T) {
	// FR-036. Both halves of the pair are written, and the intent names the job
	// that had not yet been created when it was committed.
	f := newWorkerFixture(t)
	f.armPolicy(t, "ssh-scan")

	f.evaluate(t, f.alertOn("bb25e22fe6fad350aa771423a45c643e"))

	allowed := f.ledger.decisions(audit.DecisionAllowed)
	if len(allowed) != 1 {
		t.Fatalf("committed %d intent records, want 1", len(allowed))
	}
	if len(f.ledger.decisions(audit.DecisionSucceeded)) != 1 {
		t.Error("no outcome record was committed; the pair is incomplete")
	}

	jobs := f.captures(t)
	if len(jobs) != 1 {
		t.Fatalf("got %d captures, want 1", len(jobs))
	}
	if allowed[0].Resource.Name != jobs[0].Name {
		t.Errorf("the intent names %q but the capture is %q", allowed[0].Resource.Name, jobs[0].Name)
	}
	if allowed[0].InitiatedBy != f.namespace+"/ssh-scan" {
		t.Errorf("initiatedBy = %q, want the policy that asked", allowed[0].InitiatedBy)
	}
}

func TestAnAuditOutageStopsCapturesRatherThanRecords(t *testing.T) {
	// Fail closed. The capture must not exist, and the policy must say why -
	// silently declining would be indistinguishable from quiet traffic.
	f := newWorkerFixture(t)
	f.armPolicy(t, "ssh-scan")
	f.ledger.fail = true

	results := f.evaluate(t, f.alertOn("cc25e22fe6fad350aa771423a45c643e"))

	if len(results) != 1 || results[0].Outcome != controller.OutcomeFailed {
		t.Fatalf("results = %+v, want one Failed", results)
	}
	if results[0].FailureReason != status.ReasonAuditUnavailable {
		t.Errorf("failure reason = %q, want AuditUnavailable", results[0].FailureReason)
	}
	if jobs := f.captures(t); len(jobs) != 0 {
		t.Errorf("got %d captures, want none - none was recorded", len(jobs))
	}
}

func TestTwoWorkersRacingOnOneEventCreateOneCapture(t *testing.T) {
	// The situation during a leader handoff: the outgoing leader may still be
	// draining while the incoming one starts. Both derive the same name from
	// the same event, so the API server settles it and the loser adopts rather
	// than reporting a capture that does exist as lost.
	f := newWorkerFixture(t)
	f.armPolicy(t, "ssh-scan")
	obs := f.alertOn("dd25e22fe6fad350aa771423a45c643e")

	engines := []*controller.PolicyEngine{f.engine, f.newEngine()}
	outcomes := make([]controller.PolicyOutcome, len(engines))
	var wg sync.WaitGroup
	for i, engine := range engines {
		wg.Go(func() {
			results, err := engine.Evaluate(context.Background(), obs)
			if err != nil || len(results) != 1 {
				t.Errorf("engine %d: results = %+v, err = %v", i, results, err)
				return
			}
			outcomes[i] = results[0].Outcome
		})
	}
	wg.Wait()

	if jobs := f.captures(t); len(jobs) != 1 {
		t.Fatalf("got %d captures for one event, want 1", len(jobs))
	}
	var created, duplicate int
	for _, o := range outcomes {
		switch o {
		case controller.OutcomeCreated:
			created++
		case controller.OutcomeDuplicate:
			duplicate++
		}
	}
	if created != 1 || duplicate != 1 {
		t.Errorf("outcomes = %v, want one Created and one Duplicate", outcomes)
	}
}

func TestTwoPoliciesMatchingOneEventDecideIndependentlyAndShareTheCapture(t *testing.T) {
	// Settled deliberately: the deduplication key excludes the policy, so two
	// policies wanting the same packets get one capture. Both still record a
	// decision, because each one's evaluation is its own (FR-033).
	f := newWorkerFixture(t)
	f.armPolicy(t, "ssh-scan")
	f.armPolicy(t, "any-alert")

	results := f.evaluate(t, f.alertOn("ee25e22fe6fad350aa771423a45c643e"))

	if len(results) != 2 {
		t.Fatalf("got %d results, want one per policy: %+v", len(results), results)
	}
	if jobs := f.captures(t); len(jobs) != 1 {
		t.Errorf("got %d captures, want 1", len(jobs))
	}
	counts := map[controller.PolicyOutcome]int{}
	for _, r := range results {
		counts[r.Outcome]++
	}
	if counts[controller.OutcomeCreated] != 1 || counts[controller.OutcomeDuplicate] != 1 {
		t.Errorf("outcomes = %v, want one Created and one Duplicate", counts)
	}
}

func TestABrokenPolicyDoesNotStopAHealthyOne(t *testing.T) {
	// FR-038. The two share a worker and an event, so a failure that escaped one
	// evaluation would silently disarm the other.
	f := newWorkerFixture(t)
	// Its filter names a placeholder this alert can supply, but the alert below
	// carries no flow, so rendering fails for this policy and only this one.
	f.armPolicy(t, "needs-a-flow", func(s *trawlv1alpha1.CapturePolicySpec) {
		s.Capture.FilterTemplate = "host {{source.ip}}"
	})
	f.armPolicy(t, "no-filter")

	results := f.evaluate(t, f.alertOn("ff25e22fe6fad350aa771423a45c643e", func(o *observation.Observation) {
		o.Flow = nil
	}))

	if len(results) != 2 {
		t.Fatalf("got %d results, want one per policy: %+v", len(results), results)
	}
	var failed, created int
	for _, r := range results {
		switch r.Outcome {
		case controller.OutcomeFailed:
			failed++
		case controller.OutcomeCreated:
			created++
		}
	}
	if failed != 1 {
		t.Errorf("outcomes = %+v, want the unrenderable policy to fail", results)
	}
	if created != 1 {
		t.Errorf("outcomes = %+v, want the healthy policy to capture anyway", results)
	}
}

func TestANewLeaderInheritsTheHourlyCountFromTheCaptures(t *testing.T) {
	// The limit is counted from the CaptureJobs rather than held in memory,
	// which is what makes it survive a handoff. A fresh engine with no history
	// must reach the same answer - restarts are most likely exactly when a
	// policy is firing hard.
	f := newWorkerFixture(t)
	f.armPolicy(t, "ssh-scan", func(s *trawlv1alpha1.CapturePolicySpec) {
		s.RateLimit.MaxCapturesPerHour = 2
		// A short cooldown so successive events fall in different buckets and
		// each one asks for its own capture.
		s.RateLimit.Cooldown = metav1.Duration{Duration: time.Second}
	})

	outcomes := make([]controller.PolicyOutcome, 0, 3)
	for i := range 3 {
		// A fresh engine every time: three consecutive leaders, none of which
		// saw what the others did.
		f.engine = f.newEngine()
		obs := f.alertOn("handoff-" + strconv.Itoa(i))
		obs.ObservedAt = f.now.Add(time.Duration(i) * 10 * time.Second)
		obs.EventTime = obs.ObservedAt
		results := f.evaluate(t, obs)
		if len(results) != 1 {
			t.Fatalf("evaluation %d: results = %+v, want one", i, results)
		}
		outcomes = append(outcomes, results[0].Outcome)
	}

	if jobs := f.captures(t); len(jobs) != 2 {
		t.Errorf("got %d captures, want the 2 the limit allows", len(jobs))
	}
	if outcomes[2] != controller.OutcomeRateLimited {
		t.Errorf("the third leader's outcome = %s, want RateLimited", outcomes[2])
	}
}

func TestTheStatusSubresourceCarriesTheDecisionsAndTheCapture(t *testing.T) {
	// Written through the status subresource against a real API server, which
	// is the only place the spec/status split is actually enforced: a write
	// that went to the main resource would silently revert the spec.
	f := newWorkerFixture(t)
	f.armPolicy(t, "ssh-scan")
	ctx := context.Background()

	for _, r := range f.evaluate(t, f.alertOn("11115e22fe6fad350aa771423a45c643e")) {
		f.tracker.Record(r)
	}
	if err := f.tracker.Flush(ctx, healthySources()); err != nil {
		t.Fatalf("flushing status: %v", err)
	}

	got := f.readPolicy(t, "ssh-scan")
	if got.Status.Phase != trawlv1alpha1.CapturePolicyArmed {
		t.Errorf("phase = %s, want Armed", got.Status.Phase)
	}
	if got.Status.Decisions.Matched != 1 || got.Status.TotalCaptures != 1 {
		t.Errorf("decisions = %+v, totalCaptures = %d, want one match and one capture",
			got.Status.Decisions, got.Status.TotalCaptures)
	}
	if got.Status.LastCaptureRef == nil {
		t.Fatal("no lastCaptureRef; nothing points from the policy to what it collected")
	}
	if got.Status.ActiveCaptures != 1 {
		t.Errorf("activeCaptures = %d, want 1 - the new capture has not finished", got.Status.ActiveCaptures)
	}
	if got.Status.ResolvedTapUID != f.tap.UID {
		t.Errorf("resolvedTapUID = %q, want the tap's %q", got.Status.ResolvedTapUID, f.tap.UID)
	}
	if !status.IsTrue(got.Status.Conditions, status.TypeTapResolved, got.Generation) {
		t.Errorf("TapResolved is not true: %+v", got.Status.Conditions)
	}
	// The spec must be untouched by a status write.
	if !got.Spec.Armed {
		t.Error("the status write disarmed the policy")
	}
}

func TestADeletedPolicyStopsBeingEvaluatedAndItsCapturesRemain(t *testing.T) {
	// A capture is evidence. Deleting the rule that collected it must not
	// collect it back - which is what an owner reference would have done - and
	// the deleted policy must stop matching new events.
	f := newWorkerFixture(t)
	p := f.armPolicy(t, "ssh-scan")
	ctx := context.Background()

	f.evaluate(t, f.alertOn("22225e22fe6fad350aa771423a45c643e"))
	if jobs := f.captures(t); len(jobs) != 1 {
		t.Fatalf("got %d captures before the deletion, want 1", len(jobs))
	}

	if err := Client().Delete(ctx, p); err != nil {
		t.Fatalf("deleting the policy: %v", err)
	}

	results := f.evaluate(t, f.alertOn("33335e22fe6fad350aa771423a45c643e"))
	if len(results) != 0 {
		t.Errorf("a deleted policy still decided: %+v", results)
	}
	if jobs := f.captures(t); len(jobs) != 1 {
		t.Errorf("got %d captures after the deletion, want the 1 it collected to remain", len(jobs))
	}
	// And its status batch must not be retried forever against an object that
	// is gone.
	if err := f.tracker.Flush(ctx, healthySources()); err != nil {
		t.Errorf("flushing status after the deletion: %v", err)
	}
}

func TestADisarmedPolicyReportsWhatItWouldHaveCollected(t *testing.T) {
	f := newWorkerFixture(t)
	f.armPolicy(t, "ssh-scan", func(s *trawlv1alpha1.CapturePolicySpec) {
		s.Armed = false
	})
	ctx := context.Background()

	results := f.evaluate(t, f.alertOn("44445e22fe6fad350aa771423a45c643e"))
	if len(results) != 1 || results[0].Outcome != controller.OutcomeDisarmed {
		t.Fatalf("results = %+v, want one Disarmed", results)
	}
	if jobs := f.captures(t); len(jobs) != 0 {
		t.Errorf("a disarmed policy created %d captures", len(jobs))
	}

	for _, r := range results {
		f.tracker.Record(r)
	}
	if err := f.tracker.Flush(ctx, healthySources()); err != nil {
		t.Fatalf("flushing status: %v", err)
	}

	got := f.readPolicy(t, "ssh-scan")
	if got.Status.Phase != trawlv1alpha1.CapturePolicyDisarmed {
		t.Errorf("phase = %s, want Disarmed", got.Status.Phase)
	}
	ready := status.Get(got.Status.Conditions, status.TypeReady)
	if ready == nil || ready.Reason != status.ReasonDisarmed {
		t.Errorf("Ready = %+v, want False/Disarmed", ready)
	}
}

func TestAThresholdPolicyCapturesOnceAndRecordsTheCount(t *testing.T) {
	// The denied-flow path, end to end against the API server: the snapshot's
	// count field is bounded and required to be positive, so a threshold that
	// recorded zero would be a rejection rather than a wrong number.
	f := newWorkerFixture(t)
	f.armPolicy(t, "denied-egress", func(s *trawlv1alpha1.CapturePolicySpec) {
		s.Trigger = trawlv1alpha1.CapturePolicyTrigger{
			Type: trawlv1alpha1.CaptureTriggerHubbleDrop,
			HubbleDrop: &trawlv1alpha1.HubbleDropTrigger{
				Reasons: []string{"POLICY_DENIED"},
				Threshold: &trawlv1alpha1.DropThreshold{
					Count: 3, Window: metav1.Duration{Duration: time.Minute},
				},
			},
		}
	})

	var last controller.PolicyOutcome
	for i := range 3 {
		results := f.evaluate(t, f.deniedFlow("drop-"+strconv.Itoa(i), time.Duration(i)*time.Second))
		if len(results) != 1 {
			t.Fatalf("drop %d: results = %+v, want one", i, results)
		}
		last = results[0].Outcome
	}

	if last != controller.OutcomeCreated {
		t.Fatalf("outcome on the third drop = %s, want Created", last)
	}
	jobs := f.captures(t)
	if len(jobs) != 1 {
		t.Fatalf("got %d captures, want 1", len(jobs))
	}
	if jobs[0].Spec.Trigger == nil || jobs[0].Spec.Trigger.Hubble == nil {
		t.Fatal("the admitted job carries no Hubble trigger snapshot")
	}
	if got := jobs[0].Spec.Trigger.Hubble.Count; got != 3 {
		t.Errorf("snapshot count = %d, want the 3 drops that met the threshold", got)
	}
}

// deniedFlow builds a denied cluster flow observed on node-a.
func (f *workerFixture) deniedFlow(id string, offset time.Duration) *observation.Observation {
	port := func(v int32) *int32 { return &v }
	at := f.now.Add(-time.Minute).Add(offset)
	return &observation.Observation{
		SchemaVersion:   observation.SchemaVersion,
		ID:              id,
		EventTime:       at,
		ObservedAt:      at,
		Source:          observation.Source{Kind: observation.SourceHubble, Version: "1.16"},
		Target:          observation.Target{Node: "node-a"},
		ObservationType: observation.TypeClusterFlow,
		Flow: &observation.Flow{
			Protocol:    "tcp",
			Source:      observation.Endpoint{IP: "10.244.0.11", Port: port(41022), Namespace: "payments"},
			Destination: observation.Endpoint{IP: "10.244.0.42", Port: port(5432), Namespace: "data"},
		},
		Details: observation.Details{ClusterFlow: &observation.ClusterFlow{
			Verdict: "DROPPED", DropReason: "POLICY_DENIED", Direction: "EGRESS",
		}},
	}
}

// healthySources reports both trigger streams as delivering.
func healthySources() map[trawlv1alpha1.CaptureTriggerType]controller.SourceHealth {
	return map[trawlv1alpha1.CaptureTriggerType]controller.SourceHealth{
		trawlv1alpha1.CaptureTriggerSuricataAlert: {Connected: true},
		trawlv1alpha1.CaptureTriggerHubbleDrop:    {Connected: true},
	}
}
