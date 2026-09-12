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
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/controller"
	"trawl.cloud/trawl/internal/status"
	"trawl.cloud/trawl/internal/witness"
)

// armedPolicy is a policy an operator has armed against Suricata alerts.
func armedPolicy(t *testing.T, ns, name string) *trawlv1alpha1.CapturePolicy {
	t.Helper()
	p := &trawlv1alpha1.CapturePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
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
	if err := k8sClient.Create(context.Background(), p); err != nil {
		t.Fatalf("creating policy %s: %v", name, err)
	}
	return p
}

// reportArmed puts the policy in the state a healthy worker leaves it in, which
// is the state a dead worker used to leave standing indefinitely.
func reportArmed(t *testing.T, p *trawlv1alpha1.CapturePolicy) {
	t.Helper()
	p.Status.Phase = trawlv1alpha1.CapturePolicyArmed
	status.Set(&p.Status.Conditions, status.New(
		status.TypeSourceConnected, metav1.ConditionTrue, status.ReasonSourceConnected,
		"", p.Generation))
	status.Set(&p.Status.Conditions, status.New(
		status.TypeReady, metav1.ConditionTrue, status.ReasonAccepted,
		"armed and evaluating events", p.Generation))
	p.Status.Decisions.Matched = 9
	if err := k8sClient.Status().Update(context.Background(), p); err != nil {
		t.Fatalf("seeding policy status: %v", err)
	}
}

// renewHeartbeat writes the worker's status lease as of lag ago.
func renewHeartbeat(t *testing.T, ns string, lag time.Duration) {
	t.Helper()
	renewed := metav1.NewMicroTime(time.Now().Add(-lag))
	holder := "trawl-event-worker-0"
	lease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Name: witness.LeaseName, Namespace: ns},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity: &holder,
			RenewTime:      &renewed,
		},
	}
	if err := k8sClient.Create(context.Background(), lease); err != nil {
		t.Fatalf("writing the heartbeat lease: %v", err)
	}
}

func witnessFor(ns string) *controller.CapturePolicyReconciler {
	return &controller.CapturePolicyReconciler{
		Client:          k8sClient,
		SystemNamespace: ns,
	}
}

func reconcilePolicy(t *testing.T, r *controller.CapturePolicyReconciler, p *trawlv1alpha1.CapturePolicy) {
	t.Helper()
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: p.Namespace, Name: p.Name},
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
}

func readPolicy(t *testing.T, p *trawlv1alpha1.CapturePolicy) trawlv1alpha1.CapturePolicy {
	t.Helper()
	var got trawlv1alpha1.CapturePolicy
	key := types.NamespacedName{Namespace: p.Namespace, Name: p.Name}
	if err := k8sClient.Get(context.Background(), key, &got); err != nil {
		t.Fatalf("reading policy: %v", err)
	}
	return got
}

func TestAPolicyStopsClaimingCoverageWhenTheWorkerDies(t *testing.T) {
	// Against a real API server, because the whole mechanism turns on the
	// status subresource accepting a write from a second writer without
	// disturbing what the first one recorded.
	t.Parallel()
	ns := NewNamespace(t)

	p := armedPolicy(t, ns, "ssh-scan")
	reportArmed(t, p)
	renewHeartbeat(t, ns, 10*time.Minute)

	reconcilePolicy(t, witnessFor(ns), p)

	got := readPolicy(t, p)
	if got.Status.Phase != trawlv1alpha1.CapturePolicyDegraded {
		t.Errorf("phase = %s after the worker stopped reporting, want Degraded",
			got.Status.Phase)
	}
	source := status.Get(got.Status.Conditions, status.TypeSourceConnected)
	if source == nil || source.Reason != status.ReasonWorkerStale {
		t.Errorf("SourceConnected reason = %v, want %s", source, status.ReasonWorkerStale)
	}
	if got.Status.Decisions.Matched != 9 {
		t.Errorf("matched decisions = %d, want the worker's 9 preserved",
			got.Status.Decisions.Matched)
	}
}

func TestTheWitnessLeavesALivePolicyAlone(t *testing.T) {
	t.Parallel()
	ns := NewNamespace(t)

	p := armedPolicy(t, ns, "ssh-scan")
	reportArmed(t, p)
	renewHeartbeat(t, ns, 5*time.Second)

	before := readPolicy(t, p)
	reconcilePolicy(t, witnessFor(ns), p)

	got := readPolicy(t, p)
	if got.ResourceVersion != before.ResourceVersion {
		t.Errorf("the witness wrote while the worker was alive (%s -> %s)",
			before.ResourceVersion, got.ResourceVersion)
	}
}

func TestAPolicyCreatedWithNoWorkerRunningIsNotReportedArmed(t *testing.T) {
	// No lease exists at all, and no status has ever been written. The
	// original bug reached by a different route: an operator arms a policy
	// while the worker is down and nothing ever contradicts it.
	t.Parallel()
	ns := NewNamespace(t)

	p := armedPolicy(t, ns, "ssh-scan")
	reconcilePolicy(t, witnessFor(ns), p)

	got := readPolicy(t, p)
	if got.Status.Phase != trawlv1alpha1.CapturePolicyDegraded {
		t.Errorf("phase = %q with no worker and no heartbeat, want Degraded",
			got.Status.Phase)
	}
}
