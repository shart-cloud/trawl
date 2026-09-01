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
	"fmt"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
)

// These tests run the reconciler under a real manager rather than calling
// Reconcile directly.
//
// Everything else in this package drives Reconcile by hand, which is the right
// level for what a reconcile does but says nothing about when one happens. The
// defect these cover was exactly that gap: the reconcile was correct and simply
// never ran, because nothing was watching the objects that would have triggered
// it. A test that called Reconcile would have passed throughout.

// startManager runs the reconciler under a manager for the life of one test.
func startManager(t *testing.T, namespace string) {
	t.Helper()

	mgr, err := ctrl.NewManager(RESTConfig(), ctrl.Options{
		Scheme: Scheme(),
		// The metrics listener would bind a port per test and collide.
		Metrics: metricsserver.Options{BindAddress: "0"},
		// Each test starts its own manager in the same process, and the
		// controller's name is the same every time. The uniqueness check exists
		// to stop two controllers reporting one metric, which is a real hazard
		// in a manager that serves metrics and not one here.
		Controller: ctrlconfig.Controller{SkipNameValidation: ptr.To(true)},
	})
	if err != nil {
		t.Fatalf("creating a manager: %v", err)
	}

	r := reconcilerFor(t, namespace)
	r.Client = mgr.GetClient()
	r.Scheme = mgr.GetScheme()
	if err := r.SetupWithManager(mgr); err != nil {
		t.Fatalf("setting up the reconciler: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("the manager did not stop within 30s")
		}
	})

	if !mgr.GetCache().WaitForCacheSync(ctx) {
		t.Fatal("the manager's cache did not sync")
	}
}

// awaitTap waits for a tap's status to satisfy want.
func awaitTap(t *testing.T, namespace, name, describe string,
	want func(trawlv1alpha1.NetworkTapStatus) bool) trawlv1alpha1.NetworkTapStatus {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	var last trawlv1alpha1.NetworkTapStatus
	for time.Now().Before(deadline) {
		var tap trawlv1alpha1.NetworkTap
		if err := Client().Get(t.Context(),
			client.ObjectKey{Namespace: namespace, Name: name}, &tap); err != nil {
			t.Fatalf("reading tap %s: %v", name, err)
		}
		last = tap.Status
		if want(last) {
			return last
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("tap %s did not reach %s within 30s; phase was %q with %d matched target(s)",
		name, describe, last.Phase, last.MatchedTargets)
	return last
}

// A tap that matched no node is reconciled again when a node appears.
//
// This is the regression test for the defect the cluster acceptance suite found
// (T034). A tap whose selector matched nothing was marked Error before anything
// was rendered, so it owned no Deployment, DaemonSet or ConfigMap - and with
// only For and Owns registered, owning nothing meant no event could ever reach
// it again. Labelling the node it was waiting for changed nothing; the tap sat
// reporting "the node selector matched no nodes" about a node that now matched.
//
// The failure is worse than a stuck object. The status describes a
// misconfiguration, so it reads as a problem the operator still has to fix,
// when in fact they have already fixed it and the tap will never notice.
func TestATapThatMatchedNoNodeIsReconciledWhenOneAppears(t *testing.T) {
	ns := NewNamespace(t)
	startManager(t, ns)

	// Unique to this test: nodes are cluster-scoped, so a label another test
	// used would let its nodes satisfy this selector.
	label := fmt.Sprintf("trawl-test-watch-%d", time.Now().UnixNano())

	tap := mirrorTap(ns, "waits-for-a-node")
	tap.Spec.MirrorInterface.NodeSelector = metav1.LabelSelector{
		MatchLabels: map[string]string{label: "yes"},
	}
	if err := Client().Create(t.Context(), tap); err != nil {
		t.Fatalf("create: %v", err)
	}

	awaitTap(t, ns, tap.Name, "Error with no eligible targets",
		func(s trawlv1alpha1.NetworkTapStatus) bool {
			return s.Phase == trawlv1alpha1.TapPhaseError
		})

	createNode(t, "watch-target-"+tap.Name, map[string]string{label: "yes"})

	status := awaitTap(t, ns, tap.Name, "one matched target",
		func(s trawlv1alpha1.NetworkTapStatus) bool { return s.MatchedTargets == 1 })

	if status.Phase == trawlv1alpha1.TapPhaseError {
		t.Errorf("the tap matched a node but still reports phase %q", status.Phase)
	}
}

// Labelling an existing node so that it matches is enough on its own.
//
// The node in the case above was created after the tap, and a create is the
// easier event to notice. This covers the shape the acceptance suite exercises
// against a real cluster, where the node exists throughout and only its labels
// move - which on a single-node cluster is the only way a target can appear or
// disappear at all.
func TestATapNoticesANodeThatGainsItsLabel(t *testing.T) {
	ns := NewNamespace(t)
	startManager(t, ns)

	label := fmt.Sprintf("trawl-test-relabel-%d", time.Now().UnixNano())
	nodeName := "relabel-target-" + ns

	// The node exists first, without the label, so nothing about its existence
	// can be what wakes the tap.
	createNode(t, nodeName, map[string]string{"kubernetes.io/hostname": nodeName})

	tap := mirrorTap(ns, "waits-for-a-label")
	tap.Spec.MirrorInterface.NodeSelector = metav1.LabelSelector{
		MatchLabels: map[string]string{label: "yes"},
	}
	if err := Client().Create(t.Context(), tap); err != nil {
		t.Fatalf("create: %v", err)
	}

	awaitTap(t, ns, tap.Name, "Error with no eligible targets",
		func(s trawlv1alpha1.NetworkTapStatus) bool {
			return s.Phase == trawlv1alpha1.TapPhaseError
		})

	labelNode(t, nodeName, label, "yes")

	status := awaitTap(t, ns, tap.Name, "one matched target",
		func(s trawlv1alpha1.NetworkTapStatus) bool { return s.MatchedTargets == 1 })

	if status.Phase == trawlv1alpha1.TapPhaseError {
		t.Errorf("the tap matched the relabelled node but still reports phase %q", status.Phase)
	}
}

// labelNode adds a label to an existing node.
func labelNode(t *testing.T, name, key, value string) {
	t.Helper()

	var node corev1.Node
	if err := Client().Get(t.Context(), client.ObjectKey{Name: name}, &node); err != nil {
		t.Fatalf("reading node %s: %v", name, err)
	}
	patched := node.DeepCopy()
	if patched.Labels == nil {
		patched.Labels = map[string]string{}
	}
	patched.Labels[key] = value
	if err := Client().Patch(t.Context(), patched, client.MergeFrom(&node)); err != nil && !apierrors.IsNotFound(err) {
		t.Fatalf("labelling node %s: %v", name, err)
	}
}

// A tap that loses its target withdraws what it said about that target.
//
// Marking the phase Error is not enough on its own. Every other status field
// describes a reconcile that resolved nodes and read sensors back, and the
// error path does neither, so without clearing them they keep describing the
// last pass that did. Status then contradicts itself: Accepted=False saying the
// selector matched no nodes, beside TargetsResolved=True and a non-zero ready
// count.
//
// The ready count is the reason this matters. It claims a target has a working
// sensor when the tap has no targets at all.
func TestATapThatLosesItsTargetStopsClaimingOne(t *testing.T) {
	ns := NewNamespace(t)
	startManager(t, ns)

	label := fmt.Sprintf("trawl-test-lost-%d", time.Now().UnixNano())
	nodeName := "lost-target-" + ns
	createNode(t, nodeName, map[string]string{label: "yes"})

	tap := mirrorTap(ns, "loses-its-target")
	tap.Spec.MirrorInterface.NodeSelector = metav1.LabelSelector{
		MatchLabels: map[string]string{label: "yes"},
	}
	if err := Client().Create(t.Context(), tap); err != nil {
		t.Fatalf("create: %v", err)
	}

	// The tap resolves the node first, so there is a claim to withdraw. Envtest
	// runs no kubelet, so it never becomes Active; matching the node is enough
	// to put a non-zero count in status.
	awaitTap(t, ns, tap.Name, "one matched target",
		func(s trawlv1alpha1.NetworkTapStatus) bool { return s.MatchedTargets == 1 })

	unlabelNode(t, nodeName, label)

	status := awaitTap(t, ns, tap.Name, "Error after losing its target",
		func(s trawlv1alpha1.NetworkTapStatus) bool {
			return s.Phase == trawlv1alpha1.TapPhaseError
		})

	if status.MatchedTargets != 0 {
		t.Errorf("matchedTargets = %d after the selector stopped matching, want 0",
			status.MatchedTargets)
	}
	if status.ReadyTargets != 0 {
		t.Errorf("readyTargets = %d for a tap with no targets; it is claiming a working sensor",
			status.ReadyTargets)
	}
	if len(status.Targets) != 0 {
		t.Errorf("status still carries %d per-target report(s) for targets that no longer match",
			len(status.Targets))
	}
	for _, c := range status.Conditions {
		if c.Type == "Accepted" {
			continue
		}
		if c.Status == metav1.ConditionTrue {
			t.Errorf("condition %s is still True (%s: %s) beside Accepted=False; "+
				"status is describing a reconcile that did not happen",
				c.Type, c.Reason, c.Message)
		}
	}
}

// unlabelNode removes a label from an existing node.
func unlabelNode(t *testing.T, name, key string) {
	t.Helper()

	var node corev1.Node
	if err := Client().Get(t.Context(), client.ObjectKey{Name: name}, &node); err != nil {
		t.Fatalf("reading node %s: %v", name, err)
	}
	patched := node.DeepCopy()
	delete(patched.Labels, key)
	if err := Client().Patch(t.Context(), patched, client.MergeFrom(&node)); err != nil {
		t.Fatalf("removing label %s from node %s: %v", key, name, err)
	}
}
