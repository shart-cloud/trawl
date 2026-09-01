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
	"fmt"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/config"
	"trawl.cloud/trawl/internal/controller"
	"trawl.cloud/trawl/internal/telemetry"
)

// Reconciliation is exercised against a real apiserver. Owner references,
// finalizers, status subresources, and optimistic concurrency are all apiserver
// behaviours; a fake client models none of them faithfully enough for a
// reconciler that depends on all four.

func reconcilerFor(t *testing.T, namespace string) *controller.NetworkTapReconciler {
	t.Helper()
	cfg := &config.Config{
		ClusterID:       "homelab",
		SystemNamespace: namespace,
		SensorAgentResources: config.ResourceRequirements{
			RequestsCPU: "50m", RequestsMemory: "64Mi",
			LimitsCPU: "200m", LimitsMemory: "256Mi",
		},
		Content: config.ContentConfig{
			SuricataFeedURL: "https://rules.example/x.tar.gz",
			ZeekScriptRepo:  "https://github.com/zeek/packages",
		},
		Images: config.ImageConfig{
			Suricata:      "ghcr.io/t/s@sha256:" + strings.Repeat("a", 64),
			Zeek:          "ghcr.io/t/z@sha256:" + strings.Repeat("b", 64),
			SensorAgent:   "ghcr.io/t/a@sha256:" + strings.Repeat("c", 64),
			CaptureRunner: "ghcr.io/t/r@sha256:" + strings.Repeat("d", 64),
			ContentInit:   "ghcr.io/t/i@sha256:" + strings.Repeat("e", 64),
		},
	}
	return &controller.NetworkTapReconciler{
		Client:   Client(),
		Scheme:   Scheme(),
		Config:   cfg,
		Renderer: &controller.WorkloadRenderer{Config: cfg},
		Metrics:  telemetry.NewMetrics(),
	}
}

func reconcile(t *testing.T, r *controller.NetworkTapReconciler, tap *trawlv1alpha1.NetworkTap) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(t.Context(), ctrl.Request{
		NamespacedName: client.ObjectKeyFromObject(tap),
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	return res
}

// createNode makes a node the selector can match.
func createNode(t *testing.T, name string, labels map[string]string) {
	t.Helper()
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
	if err := Client().Create(t.Context(), node); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatalf("creating node: %v", err)
	}
	t.Cleanup(func() {
		_ = Client().Delete(t.Context(), node)
	})
}

func reload(t *testing.T, tap *trawlv1alpha1.NetworkTap) *trawlv1alpha1.NetworkTap {
	t.Helper()
	var fresh trawlv1alpha1.NetworkTap
	if err := Client().Get(t.Context(), client.ObjectKeyFromObject(tap), &fresh); err != nil {
		t.Fatalf("reloading tap: %v", err)
	}
	return &fresh
}

func TestReconcileCreatesOwnedResources(t *testing.T) {
	ns := NewNamespace(t)
	createNode(t, "recon-node-a", map[string]string{"trawl-test": "recon-a"})

	tap := mirrorTap(ns, "creates-resources")
	tap.Spec.MirrorInterface.NodeSelector = metav1.LabelSelector{
		MatchLabels: map[string]string{"trawl-test": "recon-a"},
	}
	if err := Client().Create(t.Context(), tap); err != nil {
		t.Fatalf("create: %v", err)
	}

	r := reconcilerFor(t, ns)
	reconcile(t, r, tap)

	name, saName, cmName, roleName := controller.Names(reload(t, tap))

	var deployment appsv1.Deployment
	if err := Client().Get(t.Context(), client.ObjectKey{Namespace: ns, Name: name}, &deployment); err != nil {
		t.Fatalf("deployment was not created: %v", err)
	}
	for _, obj := range []struct {
		name string
		into client.Object
	}{
		{saName, &corev1.ServiceAccount{}},
		{cmName, &corev1.ConfigMap{}},
		{roleName, &rbacv1.Role{}},
		{roleName, &rbacv1.RoleBinding{}},
	} {
		if err := Client().Get(t.Context(), client.ObjectKey{Namespace: ns, Name: obj.name}, obj.into); err != nil {
			t.Errorf("%T %s was not created: %v", obj.into, obj.name, err)
		}
	}
}

func TestOwnedResourcesCarryAnOwnerReference(t *testing.T) {
	// Owner references are what make deletion the garbage collector's job.
	// Without them, deleting a tap would leave privileged analyzer pods running
	// with nothing managing them.
	ns := NewNamespace(t)
	createNode(t, "recon-node-b", map[string]string{"trawl-test": "recon-b"})

	tap := mirrorTap(ns, "owner-refs")
	tap.Spec.MirrorInterface.NodeSelector = metav1.LabelSelector{
		MatchLabels: map[string]string{"trawl-test": "recon-b"},
	}
	if err := Client().Create(t.Context(), tap); err != nil {
		t.Fatalf("create: %v", err)
	}

	r := reconcilerFor(t, ns)
	reconcile(t, r, tap)

	stored := reload(t, tap)
	name, _, _, _ := controller.Names(stored)

	var deployment appsv1.Deployment
	if err := Client().Get(t.Context(), client.ObjectKey{Namespace: ns, Name: name}, &deployment); err != nil {
		t.Fatalf("get deployment: %v", err)
	}
	if len(deployment.OwnerReferences) != 1 {
		t.Fatalf("got %d owner references, want 1", len(deployment.OwnerReferences))
	}
	ref := deployment.OwnerReferences[0]
	if ref.UID != stored.UID {
		t.Errorf("owner UID = %q, want the tap's %q", ref.UID, stored.UID)
	}
	if ref.Controller == nil || !*ref.Controller {
		t.Error("owner reference is not marked as the controller")
	}
}

func TestReconcileIsIdempotent(t *testing.T) {
	// Reconcile runs constantly. A second pass must reach the same result
	// rather than accumulating changes or fighting itself.
	ns := NewNamespace(t)
	createNode(t, "recon-node-c", map[string]string{"trawl-test": "recon-c"})

	tap := mirrorTap(ns, "idempotent")
	tap.Spec.MirrorInterface.NodeSelector = metav1.LabelSelector{
		MatchLabels: map[string]string{"trawl-test": "recon-c"},
	}
	if err := Client().Create(t.Context(), tap); err != nil {
		t.Fatalf("create: %v", err)
	}

	r := reconcilerFor(t, ns)
	reconcile(t, r, tap)

	name, _, _, _ := controller.Names(reload(t, tap))
	var first appsv1.Deployment
	if err := Client().Get(t.Context(), client.ObjectKey{Namespace: ns, Name: name}, &first); err != nil {
		t.Fatalf("get: %v", err)
	}

	reconcile(t, r, reload(t, tap))
	reconcile(t, r, reload(t, tap))

	var third appsv1.Deployment
	if err := Client().Get(t.Context(), client.ObjectKey{Namespace: ns, Name: name}, &third); err != nil {
		t.Fatalf("get: %v", err)
	}
	if first.UID != third.UID {
		t.Error("the deployment was replaced rather than updated in place")
	}
}

func TestMirrorSourceMatchingSeveralNodesIsAnError(t *testing.T) {
	// Only one node is wired to the SPAN port. Guessing which would either miss
	// the traffic entirely or open capture sockets on machines that have none.
	ns := NewNamespace(t)
	createNode(t, "ambiguous-1", map[string]string{"trawl-test": "ambiguous"})
	createNode(t, "ambiguous-2", map[string]string{"trawl-test": "ambiguous"})

	tap := mirrorTap(ns, "ambiguous-targets")
	tap.Spec.MirrorInterface.NodeSelector = metav1.LabelSelector{
		MatchLabels: map[string]string{"trawl-test": "ambiguous"},
	}
	if err := Client().Create(t.Context(), tap); err != nil {
		t.Fatalf("create: %v", err)
	}

	r := reconcilerFor(t, ns)
	reconcile(t, r, tap)

	stored := reload(t, tap)
	if stored.Status.Phase != trawlv1alpha1.TapPhaseError {
		t.Errorf("phase = %q, want Error", stored.Status.Phase)
	}
	accepted := findCondition(stored.Status.Conditions, "Accepted")
	if accepted == nil || accepted.Status != metav1.ConditionFalse {
		t.Fatalf("Accepted condition = %+v, want False", accepted)
	}
	if accepted.Reason != "AmbiguousTargets" {
		t.Errorf("reason = %q, want AmbiguousTargets", accepted.Reason)
	}
}

func TestZeroMatchedNodesIsAnObservableError(t *testing.T) {
	// A selector matching nothing is a misconfiguration, not a transient state
	// to wait out silently. FR-007 requires an actionable status.
	ns := NewNamespace(t)

	tap := mirrorTap(ns, "no-targets")
	tap.Spec.MirrorInterface.NodeSelector = metav1.LabelSelector{
		MatchLabels: map[string]string{"trawl-test": "nothing-matches-this"},
	}
	if err := Client().Create(t.Context(), tap); err != nil {
		t.Fatalf("create: %v", err)
	}

	r := reconcilerFor(t, ns)
	reconcile(t, r, tap)

	stored := reload(t, tap)
	if stored.Status.Phase != trawlv1alpha1.TapPhaseError {
		t.Errorf("phase = %q, want Error", stored.Status.Phase)
	}
	if c := findCondition(stored.Status.Conditions, "Accepted"); c == nil || c.Reason != "NoEligibleTargets" {
		t.Errorf("Accepted condition = %+v, want reason NoEligibleTargets", c)
	}
}

func TestTapDoesNotReportActiveBeforeSensorsReport(t *testing.T) {
	// Constitution II: a resource must not report Active until the capability
	// is verifiably available. An analyst reading Active must be able to trust
	// the evidence is complete.
	ns := NewNamespace(t)
	createNode(t, "pending-node", map[string]string{"trawl-test": "pending"})

	tap := mirrorTap(ns, "not-active-yet")
	tap.Spec.MirrorInterface.NodeSelector = metav1.LabelSelector{
		MatchLabels: map[string]string{"trawl-test": "pending"},
	}
	if err := Client().Create(t.Context(), tap); err != nil {
		t.Fatalf("create: %v", err)
	}

	r := reconcilerFor(t, ns)
	reconcile(t, r, tap)

	stored := reload(t, tap)
	if stored.Status.Phase == trawlv1alpha1.TapPhaseActive {
		t.Error("tap reported Active with no sensor having reported and no ready workload")
	}
	if stored.Status.Phase != trawlv1alpha1.TapPhasePending {
		t.Errorf("phase = %q, want Pending", stored.Status.Phase)
	}
}

func TestAnalyzersHealthyIsUnknownBeforeAnySensorReports(t *testing.T) {
	// Unknown, not False: nothing has been observed to be wrong, and nothing
	// has been observed to be right.
	ns := NewNamespace(t)
	createNode(t, "unknown-node", map[string]string{"trawl-test": "unknown"})

	tap := mirrorTap(ns, "analyzers-unknown")
	tap.Spec.MirrorInterface.NodeSelector = metav1.LabelSelector{
		MatchLabels: map[string]string{"trawl-test": "unknown"},
	}
	if err := Client().Create(t.Context(), tap); err != nil {
		t.Fatalf("create: %v", err)
	}

	r := reconcilerFor(t, ns)
	reconcile(t, r, tap)

	c := findCondition(reload(t, tap).Status.Conditions, "AnalyzersHealthy")
	if c == nil || c.Status != metav1.ConditionUnknown {
		t.Errorf("AnalyzersHealthy = %+v, want Unknown", c)
	}
}

func TestStaleHeartbeatDoesNotCountAsReady(t *testing.T) {
	// A dead sensor's last report describes a process that may no longer
	// exist. Carrying it forward would let it hold the tap in Active.
	ns := NewNamespace(t)
	createNode(t, "stale-node", map[string]string{"trawl-test": "stale"})

	tap := mirrorTap(ns, "stale-heartbeat")
	tap.Spec.MirrorInterface.NodeSelector = metav1.LabelSelector{
		MatchLabels: map[string]string{"trawl-test": "stale"},
	}
	if err := Client().Create(t.Context(), tap); err != nil {
		t.Fatalf("create: %v", err)
	}

	stored := reload(t, tap)
	stored.Status.Targets = []trawlv1alpha1.TargetStatus{{
		NodeName:  "stale-node",
		Interface: "enp5s0",
		// Well beyond the staleness threshold.
		HeartbeatTime: metav1.NewTime(time.Now().Add(-10 * time.Minute)),
		Analyzers: []trawlv1alpha1.AnalyzerStatus{
			{Name: trawlv1alpha1.AnalyzerSuricata, Healthy: true},
		},
	}}
	if err := Client().Status().Update(t.Context(), stored); err != nil {
		t.Fatalf("seeding stale target: %v", err)
	}

	r := reconcilerFor(t, ns)
	reconcile(t, r, reload(t, tap))

	after := reload(t, tap)
	if after.Status.ReadyTargets != 0 {
		t.Errorf("readyTargets = %d with a stale heartbeat, want 0", after.Status.ReadyTargets)
	}
	if after.Status.Phase == trawlv1alpha1.TapPhaseActive {
		t.Error("a stale sensor held the tap in Active")
	}
}

func TestPartialAnalyzerHealthIsDegradedNotError(t *testing.T) {
	// FR-007 and the edge case in the spec: one analyzer failing while another
	// works must be Degraded, and must name which one failed.
	ns := NewNamespace(t)
	createNode(t, "degraded-node", map[string]string{"trawl-test": "degraded"})

	tap := mirrorTap(ns, "degraded")
	tap.Spec.MirrorInterface.NodeSelector = metav1.LabelSelector{
		MatchLabels: map[string]string{"trawl-test": "degraded"},
	}
	tap.Spec.Analyzers.Zeek = tap.Spec.Analyzers.Suricata
	if err := Client().Create(t.Context(), tap); err != nil {
		t.Fatalf("create: %v", err)
	}

	stored := reload(t, tap)
	stored.Status.Targets = []trawlv1alpha1.TargetStatus{{
		NodeName:      "degraded-node",
		Interface:     "enp5s0",
		HeartbeatTime: metav1.NewTime(time.Now()),
		Analyzers: []trawlv1alpha1.AnalyzerStatus{
			{Name: trawlv1alpha1.AnalyzerSuricata, Healthy: true},
			{Name: trawlv1alpha1.AnalyzerZeek, Healthy: false, Reason: "no records"},
		},
	}}
	if err := Client().Status().Update(t.Context(), stored); err != nil {
		t.Fatalf("seeding target: %v", err)
	}

	r := reconcilerFor(t, ns)
	reconcile(t, r, reload(t, tap))

	after := reload(t, tap)
	c := findCondition(after.Status.Conditions, "AnalyzersHealthy")
	if c == nil || c.Status != metav1.ConditionFalse {
		t.Fatalf("AnalyzersHealthy = %+v, want False", c)
	}
	if !strings.Contains(c.Message, "Zeek") {
		t.Errorf("condition does not name the failed analyzer: %q", c.Message)
	}
	if after.Status.Phase == trawlv1alpha1.TapPhaseError {
		t.Error("partial analyzer health was reported as Error rather than Degraded")
	}
}

func TestConditionsCarryObservedGeneration(t *testing.T) {
	// A True condition from an older generation is not evidence about the spec
	// in front of you.
	ns := NewNamespace(t)
	createNode(t, "gen-node", map[string]string{"trawl-test": "gen"})

	tap := mirrorTap(ns, "observed-generation")
	tap.Spec.MirrorInterface.NodeSelector = metav1.LabelSelector{
		MatchLabels: map[string]string{"trawl-test": "gen"},
	}
	if err := Client().Create(t.Context(), tap); err != nil {
		t.Fatalf("create: %v", err)
	}

	r := reconcilerFor(t, ns)
	reconcile(t, r, tap)

	stored := reload(t, tap)
	if stored.Status.ObservedGeneration != stored.Generation {
		t.Errorf("observedGeneration = %d, want %d", stored.Status.ObservedGeneration, stored.Generation)
	}
	for _, c := range stored.Status.Conditions {
		if c.ObservedGeneration != stored.Generation {
			t.Errorf("condition %s observedGeneration = %d, want %d",
				c.Type, c.ObservedGeneration, stored.Generation)
		}
	}
}

func TestReconcileAddsAFinalizer(t *testing.T) {
	ns := NewNamespace(t)
	createNode(t, "final-node", map[string]string{"trawl-test": "final"})

	tap := mirrorTap(ns, "finalizer")
	tap.Spec.MirrorInterface.NodeSelector = metav1.LabelSelector{
		MatchLabels: map[string]string{"trawl-test": "final"},
	}
	if err := Client().Create(t.Context(), tap); err != nil {
		t.Fatalf("create: %v", err)
	}

	r := reconcilerFor(t, ns)
	reconcile(t, r, tap)

	stored := reload(t, tap)
	if len(stored.Finalizers) == 0 {
		t.Fatal("no finalizer was added")
	}
}

func TestDeletionReleasesTheFinalizer(t *testing.T) {
	// Deleting a tap stops monitoring; it must not leave the object wedged.
	ns := NewNamespace(t)
	createNode(t, "delete-node", map[string]string{"trawl-test": "delete"})

	tap := mirrorTap(ns, "deletion")
	tap.Spec.MirrorInterface.NodeSelector = metav1.LabelSelector{
		MatchLabels: map[string]string{"trawl-test": "delete"},
	}
	if err := Client().Create(t.Context(), tap); err != nil {
		t.Fatalf("create: %v", err)
	}

	r := reconcilerFor(t, ns)
	reconcile(t, r, tap)

	if err := Client().Delete(t.Context(), reload(t, tap)); err != nil {
		t.Fatalf("delete: %v", err)
	}
	reconcile(t, r, reload(t, tap))

	var after trawlv1alpha1.NetworkTap
	err := Client().Get(t.Context(), client.ObjectKeyFromObject(tap), &after)
	if err == nil && len(after.Finalizers) > 0 {
		t.Errorf("finalizer still present after deletion: %v", after.Finalizers)
	}
}

func TestReconcileRejectsATapOutsideTheSystemNamespace(t *testing.T) {
	// Defence in depth: this tap never passed the webhook, as would happen with
	// a direct etcd restore or a webhook outage.
	ns := NewNamespace(t)
	createNode(t, "wrong-ns-node", map[string]string{"trawl-test": "wrong-ns"})

	tap := mirrorTap(ns, "wrong-namespace")
	tap.Spec.MirrorInterface.NodeSelector = metav1.LabelSelector{
		MatchLabels: map[string]string{"trawl-test": "wrong-ns"},
	}
	if err := Client().Create(t.Context(), tap); err != nil {
		t.Fatalf("create: %v", err)
	}

	// The reconciler is configured for a different system namespace.
	r := reconcilerFor(t, "some-other-namespace")
	reconcile(t, r, tap)

	stored := reload(t, tap)
	if stored.Status.Phase != trawlv1alpha1.TapPhaseError {
		t.Errorf("phase = %q, want Error", stored.Status.Phase)
	}
	if c := findCondition(stored.Status.Conditions, "Accepted"); c == nil || c.Reason != "WrongNamespace" {
		t.Errorf("Accepted condition = %+v, want reason WrongNamespace", c)
	}

	name, _, _, _ := controller.Names(stored)
	var deployment appsv1.Deployment
	if err := Client().Get(t.Context(), client.ObjectKey{Namespace: ns, Name: name}, &deployment); err == nil {
		t.Error("a workload was created for a tap outside the system namespace")
	}
}

func TestReconcileRequeuesToKeepStalenessObservable(t *testing.T) {
	// Without a steady requeue, a tap whose sensor died silently would keep its
	// last reported status forever, because nothing else triggers a reconcile.
	ns := NewNamespace(t)
	createNode(t, "requeue-node", map[string]string{"trawl-test": "requeue"})

	tap := mirrorTap(ns, "requeue")
	tap.Spec.MirrorInterface.NodeSelector = metav1.LabelSelector{
		MatchLabels: map[string]string{"trawl-test": "requeue"},
	}
	if err := Client().Create(t.Context(), tap); err != nil {
		t.Fatalf("create: %v", err)
	}

	r := reconcilerFor(t, ns)
	res := reconcile(t, r, tap)

	if res.RequeueAfter <= 0 {
		t.Error("reconcile did not schedule a requeue")
	}
}

func findCondition(conds []metav1.Condition, condType string) *metav1.Condition {
	for i := range conds {
		if conds[i].Type == condType {
			return &conds[i]
		}
	}
	return nil
}

// Two taps may legitimately select the same node - a different interface, a
// different analyzer - and nothing in the API forbids it. Both sensor pods run
// on the host network, so if they also derive the same probe port the second pod
// to schedule exits with "bind: address already in use" and crash-loops. That is
// invisible in the API: the tap reports WorkloadReady=False and sits in Pending
// with nothing naming the cause. SensorProbePort makes the collision rare; this
// is what makes it legible when it happens.
func TestTapsCollidingOnAProbePortSayWhichOneYielded(t *testing.T) {
	ns := NewNamespace(t)
	createNode(t, "probe-conflict-node", map[string]string{"trawl-test": "probe-conflict"})
	selector := metav1.LabelSelector{MatchLabels: map[string]string{"trawl-test": "probe-conflict"}}

	first := mirrorTap(ns, "probe-conflict-a")
	first.Spec.MirrorInterface.NodeSelector = selector
	if err := Client().Create(t.Context(), first); err != nil {
		t.Fatalf("create: %v", err)
	}

	// A colliding name is searched for rather than hard-coded, so this test does
	// not encode the hash and break the day the derivation is retuned.
	second := mirrorTap(ns, collidingName(t, ns, first))
	second.Spec.MirrorInterface.NodeSelector = selector
	second.Spec.MirrorInterface.Interface = "enp6s0"
	if err := Client().Create(t.Context(), second); err != nil {
		t.Fatalf("create: %v", err)
	}

	r := reconcilerFor(t, ns)
	reconcile(t, r, first)
	reconcile(t, r, second)

	// Exactly one yields, and the other keeps the port. Which one is decided by
	// creation time, with the UID as a tie-break - and these two are created in
	// the same second, because metav1.Time has second granularity. Asserting
	// which name wins would either encode that tie-break or be flaky; what has
	// to hold is that both taps reach the same answer, so a collision costs one
	// sensor rather than both.
	yielded := map[string]*metav1.Condition{}
	kept := map[string]*metav1.Condition{}
	for _, tap := range []*trawlv1alpha1.NetworkTap{first, second} {
		stored := reload(t, tap)
		c := findCondition(stored.Status.Conditions, "Accepted")
		if c == nil {
			t.Fatalf("%s has no Accepted condition", tap.Name)
		}
		if c.Status == metav1.ConditionFalse && c.Reason == "ProbePortConflict" {
			yielded[tap.Name] = c
			if stored.Status.Phase != trawlv1alpha1.TapPhaseError {
				t.Errorf("%s phase = %q, want Error", tap.Name, stored.Status.Phase)
			}
			continue
		}
		if c.Status != metav1.ConditionTrue {
			t.Errorf("%s Accepted = %+v, want either True or a ProbePortConflict", tap.Name, c)
		}
		kept[tap.Name] = c
	}

	if len(yielded) != 1 || len(kept) != 1 {
		t.Fatalf("%d taps yielded and %d kept the port, want exactly one of each: "+
			"neither running is as bad as both crash-looping, and both running is the bug",
			len(yielded), len(kept))
	}

	for name, c := range yielded {
		other := first.Name
		if name == first.Name {
			other = second.Name
		}
		if !strings.Contains(c.Message, other) || !strings.Contains(c.Message, "probe-conflict-node") {
			t.Errorf("message = %q, want it to name the tap it yielded to and the shared node", c.Message)
		}
	}
}

// collidingName finds a tap name in ns whose derived probe port matches tap's.
func collidingName(t *testing.T, ns string, tap *trawlv1alpha1.NetworkTap) string {
	t.Helper()
	want := controller.SensorProbePort(tap)
	for i := range 1000 {
		candidate := fmt.Sprintf("probe-conflict-b-%d", i)
		probe := &trawlv1alpha1.NetworkTap{
			ObjectMeta: metav1.ObjectMeta{Name: candidate, Namespace: ns},
		}
		if controller.SensorProbePort(probe) == want {
			return candidate
		}
	}
	t.Fatalf("no name collided with probe port %d in 1000 tries", want)
	return ""
}
