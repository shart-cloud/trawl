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
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/sanitize"
	"trawl.cloud/trawl/internal/status"
	"trawl.cloud/trawl/internal/telemetry"
	"trawl.cloud/trawl/internal/witness"
)

// CapturePolicyReconciler speaks for armed policies when the event worker has
// stopped speaking for them.
//
// It writes no policy status while the worker is alive. The worker owns the
// field - it is the only component that knows what a policy decided, whether
// its trigger source is connected, and how many captures it has taken this
// hour - and two writers computing the same status from different information
// would take turns overwriting each other every flush interval.
//
// What this reconciler owns is the one statement the worker cannot make: that
// nobody is watching. An armed CapturePolicy reads as a claim of detection
// coverage, and a dead worker used to leave that claim standing indefinitely
// because the component that reports the outage was the component that was
// down.
type CapturePolicyReconciler struct {
	client.Client

	// SystemNamespace is the only namespace Trawl resources are honoured in.
	SystemNamespace string

	// Metrics is optional.
	Metrics *telemetry.Metrics

	// Now is time.Now unless a test replaced it.
	Now func() time.Time
}

// Markers live in their own comment block, separated from the doc comment
// below. Inside a declaration's doc comment controller-gen reads them as
// markers on that declaration and generates nothing from them - the RBAC is
// silently absent, the code compiles, and the controller fails at runtime with
// a Forbidden nobody predicted.
//
// +kubebuilder:rbac:groups=trawl.cloud,resources=capturepolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=trawl.cloud,resources=capturepolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch

// Reconcile reports a policy whose worker has gone quiet.
func (r *CapturePolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	result := telemetry.ReconcileSuccess
	defer func() {
		if r.Metrics != nil {
			r.Metrics.ReconcileTotal.WithLabelValues(telemetry.ControllerCapturePolicy, result).Inc()
		}
	}()

	var policy trawlv1alpha1.CapturePolicy
	if err := r.Get(ctx, req.NamespacedName, &policy); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		result = telemetry.ReconcileError
		return ctrl.Result{}, sanitize.Errorf("reading the capture policy: %v", err)
	}

	// Off-namespace policies are refused by admission and never evaluated by
	// the worker, so there is no coverage claim here to correct.
	if policy.Namespace != r.SystemNamespace || !policy.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	// A disarmed policy claims nothing. Reporting a stale worker on one would
	// turn a deliberate choice into a problem an operator has to triage, which
	// is why phaseFor puts Disarmed ahead of every failure.
	if !policy.Spec.Armed {
		return ctrl.Result{}, nil
	}

	fresh, err := r.workerIsFlushing(ctx)
	if err != nil {
		result = telemetry.ReconcileError
		return ctrl.Result{}, err
	}
	if fresh {
		// The worker is writing status. Anything this reconciler wrote now
		// would be overwritten by the next flush, and would be computed from
		// less information than the worker has.
		return ctrl.Result{RequeueAfter: witness.Stale / 3}, nil
	}

	if err := r.reportStaleWorker(ctx, &policy); err != nil {
		result = telemetry.ReconcileError
		return ctrl.Result{}, err
	}

	// A steady requeue, for the reason the tap reconciler has one: nothing else
	// triggers a reconcile when a worker dies. The worker's own writes stop, so
	// a reconciler waiting on a policy event would wait forever - which is the
	// bug rather than a longer version of it.
	return ctrl.Result{RequeueAfter: witness.Stale / 3}, nil
}

// workerIsFlushing reads the heartbeat.
func (r *CapturePolicyReconciler) workerIsFlushing(ctx context.Context) (bool, error) {
	var lease coordinationv1.Lease
	key := types.NamespacedName{Namespace: r.SystemNamespace, Name: witness.LeaseName}
	switch err := r.Get(ctx, key, &lease); {
	case apierrors.IsNotFound(err):
		// No heartbeat has ever been written, so no flush has ever completed.
		return false, nil
	case err != nil:
		// Unreadable is not the same as absent. Reporting every policy
		// Degraded because this process cannot read one Lease would turn a
		// local RBAC or API problem into an apparent detection outage.
		return false, sanitize.Errorf("reading the worker heartbeat lease: %v", err)
	}
	return witness.Fresh(&lease, r.now()), nil
}

// reportStaleWorker records that nothing is evaluating this policy.
//
// Only SourceConnected, Ready and Phase are touched. The decision counters, the
// resolved tap and the rate-limit condition are the worker's account of what
// happened while it was running, and they remain true of that period - a
// witness that cleared them would destroy the record of the coverage that did
// exist in order to report the coverage that does not.
func (r *CapturePolicyReconciler) reportStaleWorker(
	ctx context.Context, policy *trawlv1alpha1.CapturePolicy,
) error {
	desired := policy.Status.DeepCopy()

	const message = "no event worker has reported for longer than the heartbeat window, " +
		"so this policy is not being evaluated"

	status.Set(&desired.Conditions, status.New(
		status.TypeSourceConnected, metav1.ConditionFalse, status.ReasonWorkerStale,
		message, policy.Generation))
	status.Set(&desired.Conditions, status.New(
		status.TypeReady, metav1.ConditionFalse, status.ReasonWorkerStale,
		"", policy.Generation))

	// Degraded, which is what phaseFor returns for an armed policy whose source
	// condition is failing. Called rather than assumed so the two agree about
	// precedence: a policy that is also rate-limited must not be reported as
	// RateLimited while nothing is evaluating it at all.
	desired.Phase, _ = phaseFor(policy, "", status.ReasonWorkerStale, "")

	// ObservedGeneration is deliberately not advanced. It is the worker's
	// statement that it has seen this generation of the spec, and nothing here
	// has evaluated the spec - claiming otherwise would let a policy edited
	// while the worker was down look like it had taken effect.
	if equality.Semantic.DeepEqual(policy.Status, *desired) {
		// Already reported. Without this the steady requeue would write every
		// armed policy once per interval for the whole outage.
		return nil
	}

	policy.Status = *desired
	if err := r.Status().Update(ctx, policy); err != nil {
		if r.Metrics != nil {
			r.Metrics.StatusUpdateFailures.
				WithLabelValues("CapturePolicy", status.ReasonWorkerStale).Inc()
		}
		return sanitize.Errorf("reporting a stale event worker: %v", err)
	}
	return nil
}

func (r *CapturePolicyReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SetupWithManager registers the reconciler.
func (r *CapturePolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// The heartbeat is deliberately not watched. It is renewed every status
	// interval, and a watch would reconcile every armed policy on every
	// renewal - turning a healthy worker into a steady reconcile load
	// proportional to the number of policies. The requeue above is what
	// observes staleness, exactly as it does for sensor heartbeats.
	return ctrl.NewControllerManagedBy(mgr).
		For(&trawlv1alpha1.CapturePolicy{}).
		Named("capturepolicy-witness").
		Complete(r)
}
