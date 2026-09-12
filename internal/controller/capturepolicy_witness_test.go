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
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/status"
	"trawl.cloud/trawl/internal/witness"
)

// The policy every test in this file reconciles, and the tap UID the worker
// had resolved for it before it died.
const (
	witnessedPolicy = "ssh-scan"
	witnessedTapUID = "tap-uid"
)

// witnessFixture is one CapturePolicy witness over a fake API.
type witnessFixture struct {
	reconciler *CapturePolicyReconciler
	client     client.Client
}

func newWitness(t *testing.T, objs ...client.Object) *witnessFixture {
	t.Helper()
	c := fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithObjects(objs...).
		WithStatusSubresource(&trawlv1alpha1.CapturePolicy{}).
		Build()

	return &witnessFixture{
		client: c,
		reconciler: &CapturePolicyReconciler{
			Client:          c,
			SystemNamespace: testNamespace,
			Now:             func() time.Time { return evaluatedAt },
		},
	}
}

func (f *witnessFixture) reconcile(t *testing.T) {
	t.Helper()
	req := ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: testNamespace, Name: witnessedPolicy,
	}}
	if _, err := f.reconciler.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("reconciling %s: %v", witnessedPolicy, err)
	}
}

func (f *witnessFixture) read(t *testing.T) trawlv1alpha1.CapturePolicy {
	t.Helper()
	var p trawlv1alpha1.CapturePolicy
	key := types.NamespacedName{Namespace: testNamespace, Name: witnessedPolicy}
	if err := f.client.Get(context.Background(), key, &p); err != nil {
		t.Fatalf("reading policy %s: %v", witnessedPolicy, err)
	}
	return p
}

// heartbeat is the worker's status lease, renewed lag ago.
func heartbeat(lag time.Duration) *coordinationv1.Lease {
	renewed := metav1.NewMicroTime(evaluatedAt.Add(-lag))
	holder := "trawl-event-worker-0"
	return &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: witness.LeaseName},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity: &holder,
			RenewTime:      &renewed,
		},
	}
}

// armedAndReportedArmed is the state the bug left behind: a policy the worker
// last described as armed and evaluating, with nothing since.
func armedAndReportedArmed() *trawlv1alpha1.CapturePolicy {
	p := suricataPolicy()
	p.Status.Phase = trawlv1alpha1.CapturePolicyArmed
	status.Set(&p.Status.Conditions, status.New(
		status.TypeSourceConnected, metav1.ConditionTrue, status.ReasonSourceConnected,
		"", p.Generation))
	status.Set(&p.Status.Conditions, status.New(
		status.TypeReady, metav1.ConditionTrue, status.ReasonAccepted,
		"armed and evaluating events", p.Generation))
	p.Status.Decisions.Matched = 12
	p.Status.TotalCaptures = 4
	p.Status.ResolvedTapUID = witnessedTapUID
	return p
}

func TestADeadWorkerStopsAPolicyReportingArmed(t *testing.T) {
	// The worst of the carried gaps. The staleness check that would report the
	// outage lived inside the worker, so the component that should declare it
	// was the component that was down - and an analyst six weeks later reads
	// Armed as a claim of detection coverage.
	f := newWitness(t, armedAndReportedArmed(), heartbeat(10*time.Minute))
	f.reconcile(t)

	got := f.read(t)
	if got.Status.Phase != trawlv1alpha1.CapturePolicyDegraded {
		t.Errorf("phase = %s with a dead worker, want Degraded", got.Status.Phase)
	}
	source := status.Get(got.Status.Conditions, status.TypeSourceConnected)
	if source == nil {
		t.Fatal("no SourceConnected condition")
	}
	if source.Status != metav1.ConditionFalse {
		t.Errorf("SourceConnected = %s, want False", source.Status)
	}
	if source.Reason != status.ReasonWorkerStale {
		t.Errorf("SourceConnected reason = %s, want %s", source.Reason, status.ReasonWorkerStale)
	}
	ready := status.Get(got.Status.Conditions, status.TypeReady)
	if ready == nil || ready.Status != metav1.ConditionFalse {
		t.Error("Ready did not go False with a dead worker")
	}
}

func TestAStaleWorkerIsNotConfusedWithADisconnectedSource(t *testing.T) {
	// SourceDisconnected means the worker looked and the stream was down.
	// WorkerStale means nobody looked. They send an operator to different
	// places, which is why the webhook work drew the same line between
	// DeviceReachable and MirrorConfigured.
	f := newWitness(t, armedAndReportedArmed(), heartbeat(10*time.Minute))
	f.reconcile(t)

	source := status.Get(f.read(t).Status.Conditions, status.TypeSourceConnected)
	if source.Reason == status.ReasonSourceDisconnected {
		t.Error("a stale worker was reported as a disconnected trigger source")
	}
}

func TestALiveWorkerKeepsOwnershipOfPolicyStatus(t *testing.T) {
	// The worker knows what the policy decided, whether its source is
	// connected, and how many captures it has taken. Two writers computing the
	// same status from different information would overwrite each other every
	// flush, so the witness writes nothing while the heartbeat is fresh.
	f := newWitness(t, armedAndReportedArmed(), heartbeat(20*time.Second))
	before := f.read(t)
	f.reconcile(t)

	got := f.read(t)
	if got.ResourceVersion != before.ResourceVersion {
		t.Errorf("the witness wrote status while the worker was alive (resourceVersion %s -> %s)",
			before.ResourceVersion, got.ResourceVersion)
	}
	if got.Status.Phase != trawlv1alpha1.CapturePolicyArmed {
		t.Errorf("phase = %s with a live worker, want the worker's Armed", got.Status.Phase)
	}
}

func TestAMissingHeartbeatIsNotEvidenceOfCoverage(t *testing.T) {
	// A policy created while the worker is down has no heartbeat to read at
	// all. Treating an absent lease as healthy would report the freshly
	// created policy as armed, which is the original bug reached by a
	// different route.
	f := newWitness(t, armedAndReportedArmed())
	f.reconcile(t)

	got := f.read(t)
	if got.Status.Phase != trawlv1alpha1.CapturePolicyDegraded {
		t.Errorf("phase = %s with no heartbeat at all, want Degraded", got.Status.Phase)
	}
}

func TestADisarmedPolicyIsNotDegradedByAStaleWorker(t *testing.T) {
	// Disarmed is a choice rather than a problem - phaseFor puts it ahead of
	// every failure for that reason. A disarmed policy claims no coverage, so
	// there is nothing for the witness to correct.
	p := armedAndReportedArmed()
	p.Spec.Armed = false
	p.Status.Phase = trawlv1alpha1.CapturePolicyDisarmed

	f := newWitness(t, p, heartbeat(10*time.Minute))
	f.reconcile(t)

	if got := f.read(t); got.Status.Phase != trawlv1alpha1.CapturePolicyDisarmed {
		t.Errorf("phase = %s for a disarmed policy, want Disarmed", got.Status.Phase)
	}
}

func TestTheWitnessKeepsTheRecordOfCoverageThatDidExist(t *testing.T) {
	// The decision counters and the resolved tap are the worker's account of
	// what happened while it was running, and they stay true of that period.
	// Clearing them to report the coverage that does not exist would destroy
	// the record of the coverage that did.
	f := newWitness(t, armedAndReportedArmed(), heartbeat(10*time.Minute))
	f.reconcile(t)

	got := f.read(t)
	if got.Status.Decisions.Matched != 12 {
		t.Errorf("matched decisions = %d, want the worker's 12 preserved",
			got.Status.Decisions.Matched)
	}
	if got.Status.TotalCaptures != 4 {
		t.Errorf("total captures = %d, want the worker's 4 preserved", got.Status.TotalCaptures)
	}
	if got.Status.ResolvedTapUID != witnessedTapUID {
		t.Errorf("resolved tap UID = %q, want it preserved", got.Status.ResolvedTapUID)
	}
}

func TestTheWitnessDoesNotClaimToHaveSeenTheSpec(t *testing.T) {
	// ObservedGeneration is the worker's statement that it has evaluated this
	// generation. Nothing here evaluated anything, and advancing it would let
	// a policy edited while the worker was down look like it had taken effect.
	p := armedAndReportedArmed()
	p.Generation = 7
	p.Status.ObservedGeneration = 3

	f := newWitness(t, p, heartbeat(10*time.Minute))
	f.reconcile(t)

	if got := f.read(t); got.Status.ObservedGeneration != 3 {
		t.Errorf("observedGeneration = %d, want 3 left where the worker put it",
			got.Status.ObservedGeneration)
	}
}

func TestTheWitnessWritesOncePerOutageNotOncePerInterval(t *testing.T) {
	// The steady requeue is what observes staleness, so reconciles continue
	// for the whole outage. Writing each time would put one update per armed
	// policy per interval on the API server, saying what it already said.
	f := newWitness(t, armedAndReportedArmed(), heartbeat(10*time.Minute))
	f.reconcile(t)
	first := f.read(t).ResourceVersion

	f.reconcile(t)
	f.reconcile(t)

	if got := f.read(t).ResourceVersion; got != first {
		t.Errorf("resourceVersion %s -> %s across repeat reconciles, want no rewrite",
			first, got)
	}
}

func TestAPolicyOutsideTheSystemNamespaceIsNotWitnessed(t *testing.T) {
	// Admission refuses these and the worker never evaluates them, so there is
	// no coverage claim here to correct.
	p := armedAndReportedArmed()
	p.Namespace = "elsewhere"

	c := fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithObjects(p, heartbeat(10*time.Minute)).
		WithStatusSubresource(&trawlv1alpha1.CapturePolicy{}).
		Build()
	r := &CapturePolicyReconciler{
		Client:          c,
		SystemNamespace: testNamespace,
		Now:             func() time.Time { return evaluatedAt },
	}

	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "elsewhere", Name: witnessedPolicy}}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("reconciling an off-namespace policy: %v", err)
	}

	var got trawlv1alpha1.CapturePolicy
	key := types.NamespacedName{Namespace: "elsewhere", Name: witnessedPolicy}
	if err := c.Get(context.Background(), key, &got); err != nil {
		t.Fatalf("reading the off-namespace policy: %v", err)
	}
	if got.Status.Phase != trawlv1alpha1.CapturePolicyArmed {
		t.Errorf("phase = %s, want the off-namespace policy left untouched", got.Status.Phase)
	}
}
