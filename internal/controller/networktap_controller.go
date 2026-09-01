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
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/admission"
	"trawl.cloud/trawl/internal/config"
	"trawl.cloud/trawl/internal/sanitize"
	"trawl.cloud/trawl/internal/status"
	"trawl.cloud/trawl/internal/telemetry"
)

// finalizer marks taps whose owned workloads must be removed before the object
// disappears.
const finalizer = "trawl.cloud/networktap-cleanup"

// staleHeartbeat is how long a target's heartbeat may lag before its sensor is
// treated as gone.
//
// A sensor reports on a short interval, so several missed heartbeats mean the
// pod is unhealthy rather than briefly busy. Treating a stale heartbeat as
// healthy would let a dead sensor hold a tap in Active.
const staleHeartbeat = 90 * time.Second

// NetworkTapReconciler reconciles NetworkTap resources.
type NetworkTapReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Config   *config.Config
	Renderer *WorkloadRenderer
	Metrics  *telemetry.Metrics
}

// +kubebuilder:rbac:groups=trawl.cloud,resources=networktaps,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=trawl.cloud,resources=networktaps/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=trawl.cloud,resources=networktaps/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=deployments;daemonsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=configmaps;serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;rolebindings,verbs=get;list;watch;create;update;delete
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile converges a tap's workloads and status.
//
// It is idempotent and safe to retry: every write is a create-or-update keyed by
// a deterministic name, and status is derived from observation rather than
// accumulated, so a repeat pass reaches the same result.
func (r *NetworkTapReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	start := time.Now()
	result := telemetry.ReconcileSuccess
	defer func() {
		if r.Metrics != nil {
			r.Metrics.ReconcileTotal.WithLabelValues(telemetry.ControllerNetworkTap, result).Inc()
			r.Metrics.ReconcileDurationSeconds.
				WithLabelValues(telemetry.ControllerNetworkTap).
				Observe(time.Since(start).Seconds())
		}
	}()

	var tap trawlv1alpha1.NetworkTap
	if err := r.Get(ctx, req.NamespacedName, &tap); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		result = telemetry.ReconcileError
		return ctrl.Result{}, sanitize.Error(err)
	}

	// Defence in depth against a tap that reached etcd without passing the
	// webhook — a direct restore, or a webhook that was unavailable when the
	// object was written.
	if tap.Namespace != r.Config.SystemNamespace {
		result = telemetry.ReconcileInvalid
		return ctrl.Result{}, r.markError(ctx, &tap, status.ReasonWrongNamespace,
			fmt.Sprintf("NetworkTap resources are reconciled only in %q", r.Config.SystemNamespace))
	}

	if !tap.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.finalize(ctx, &tap)
	}

	if !controllerutil.ContainsFinalizer(&tap, finalizer) {
		controllerutil.AddFinalizer(&tap, finalizer)
		if err := r.Update(ctx, &tap); err != nil {
			result = telemetry.ReconcileError
			return ctrl.Result{}, sanitize.Error(err)
		}
	}

	// Re-validate the stored spec for the same reason the namespace is checked.
	if errs := admission.ValidateNetworkTapSpec(&tap.Spec); len(errs) > 0 {
		result = telemetry.ReconcileInvalid
		return ctrl.Result{}, r.markError(ctx, &tap, status.ReasonInvalidSpec,
			errs.ToAggregate().Error())
	}

	nodes, err := r.eligibleNodes(ctx, &tap)
	if err != nil {
		result = telemetry.ReconcileDependencyUnavailable
		return ctrl.Result{}, sanitize.Error(err)
	}

	// checkTargetCardinality writes its own terminal status, so a false result
	// means "stop here", not "an error occurred". Continuing would let the
	// status update below overwrite the error it just recorded.
	if ok, err := r.checkTargetCardinality(ctx, &tap, nodes); !ok {
		result = telemetry.ReconcileInvalid
		return ctrl.Result{}, err
	}

	if err := r.applyOwnedResources(ctx, &tap); err != nil {
		result = telemetry.ReconcileError
		return ctrl.Result{}, sanitize.Error(err)
	}

	if err := r.updateStatus(ctx, &tap, len(nodes)); err != nil {
		result = telemetry.ReconcileError
		return ctrl.Result{}, sanitize.Error(err)
	}

	// A steady requeue keeps heartbeat staleness observable. Without it a tap
	// whose sensor died silently would keep its last reported status forever,
	// because nothing else would trigger a reconcile.
	return ctrl.Result{RequeueAfter: staleHeartbeat / 3}, nil
}

// eligibleNodes resolves the tap's node selector.
func (r *NetworkTapReconciler) eligibleNodes(ctx context.Context, tap *trawlv1alpha1.NetworkTap) ([]corev1.Node, error) {
	src := sourceOf(tap)
	selector, err := metav1.LabelSelectorAsSelector(&src.NodeSelector)
	if err != nil {
		return nil, sanitize.Errorf("invalid node selector: %v", err)
	}

	var nodes corev1.NodeList
	if err := r.List(ctx, &nodes, &client.ListOptions{LabelSelector: selector}); err != nil {
		return nil, sanitize.Errorf("listing nodes: %v", err)
	}
	return nodes.Items, nil
}

// checkTargetCardinality enforces the mirror source's single-node rule.
//
// A mirror selector matching several nodes is ambiguous: only one node is wired
// to the SPAN port, and guessing which would either miss the traffic or open
// capture sockets on machines that have none. Zero nodes is equally a
// misconfiguration rather than a transient state to wait out silently.
// It returns ok=false when the tap cannot proceed, having already recorded the
// reason in status.
func (r *NetworkTapReconciler) checkTargetCardinality(ctx context.Context, tap *trawlv1alpha1.NetworkTap, nodes []corev1.Node) (bool, error) {
	if len(nodes) == 0 {
		return false, r.markError(ctx, tap, status.ReasonNoEligibleTargets,
			"the node selector matched no nodes")
	}
	if tap.Spec.Type == trawlv1alpha1.TapSourceMirrorInterface && len(nodes) > 1 {
		return false, r.markError(ctx, tap, status.ReasonAmbiguousTargets,
			fmt.Sprintf("a mirror source must match exactly one node; the selector matched %d", len(nodes)))
	}
	return true, nil
}

// applyOwnedResources creates or updates everything the tap owns.
//
// Owner references are set on every object so deletion is the garbage
// collector's job for the common case, with the finalizer covering what it
// cannot reach.
func (r *NetworkTapReconciler) applyOwnedResources(ctx context.Context, tap *trawlv1alpha1.NetworkTap) error {
	sa := r.Renderer.ServiceAccount(tap)
	role := r.Renderer.StatusRole(tap)
	binding := r.Renderer.StatusRoleBinding(tap)
	cm := r.Renderer.ConfigMap(tap)

	for _, obj := range []client.Object{sa, role, binding, cm} {
		if err := r.applyOwned(ctx, tap, obj); err != nil {
			return err
		}
	}

	deployment, daemonSet := r.Renderer.Workload(tap)
	switch {
	case deployment != nil:
		return r.applyOwned(ctx, tap, deployment)
	case daemonSet != nil:
		return r.applyOwned(ctx, tap, daemonSet)
	default:
		return fmt.Errorf("no workload rendered for source type %q", tap.Spec.Type)
	}
}

// applyOwned creates the object or updates it in place, preserving ownership.
func (r *NetworkTapReconciler) applyOwned(ctx context.Context, tap *trawlv1alpha1.NetworkTap, desired client.Object) error {
	if err := controllerutil.SetControllerReference(tap, desired, r.Scheme); err != nil {
		return sanitize.Errorf("setting owner reference: %v", err)
	}

	existing, ok := desired.DeepCopyObject().(client.Object)
	if !ok {
		return fmt.Errorf("unexpected object type %T", desired)
	}
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	switch {
	case apierrors.IsNotFound(err):
		if err := r.Create(ctx, desired); err != nil && !apierrors.IsAlreadyExists(err) {
			return sanitize.Errorf("creating owned resource: %v", err)
		}
		return nil
	case err != nil:
		return sanitize.Errorf("reading owned resource: %v", err)
	}

	// Carry the resourceVersion so the update is a compare-and-swap: a
	// concurrent writer causes a conflict and a retry rather than a silent
	// overwrite.
	desired.SetResourceVersion(existing.GetResourceVersion())
	if err := r.Update(ctx, desired); err != nil {
		return sanitize.Errorf("updating owned resource: %v", err)
	}
	return nil
}

// updateStatus derives the tap's aggregate status from what is observed.
func (r *NetworkTapReconciler) updateStatus(ctx context.Context, tap *trawlv1alpha1.NetworkTap, matched int) error {
	gen := tap.Generation

	tap.Status.ObservedGeneration = gen
	//nolint:gosec // node counts are bounded by cluster size
	tap.Status.MatchedTargets = int32(matched)

	ready, lastPacket := r.summarizeTargets(tap)
	tap.Status.ReadyTargets = ready
	tap.Status.LastPacketTime = lastPacket

	workloadReady, workloadReason := r.workloadReady(ctx, tap)

	status.Set(&tap.Status.Conditions, status.New(status.TypeAccepted,
		metav1.ConditionTrue, status.ReasonAccepted, "spec accepted", gen))

	status.Set(&tap.Status.Conditions, status.New(status.TypeTargetsResolved,
		boolCondition(matched > 0), targetsReason(matched),
		fmt.Sprintf("%d eligible node(s)", matched), gen))

	status.Set(&tap.Status.Conditions, status.New(status.TypeWorkloadReady,
		boolCondition(workloadReady), workloadReasonEnum(workloadReady), workloadReason, gen))

	analyzersHealthy, analyzerReason := r.analyzersHealthy(tap)
	status.Set(&tap.Status.Conditions, status.New(status.TypeAnalyzersHealthy,
		analyzersHealthy, analyzerReasonEnum(analyzersHealthy), analyzerReason, gen))

	packetsSeen := lastPacket != nil
	status.Set(&tap.Status.Conditions, status.New(status.TypePacketsObserved,
		boolCondition(packetsSeen), packetsReason(packetsSeen),
		packetsMessage(lastPacket), gen))

	tap.Status.Phase = derivePhase(matched, ready, workloadReady, analyzersHealthy)

	if err := r.Status().Update(ctx, tap); err != nil {
		if r.Metrics != nil {
			r.Metrics.StatusUpdateFailures.WithLabelValues("NetworkTap", status.ReasonPending).Inc()
		}
		return err
	}
	return nil
}

// summarizeTargets counts healthy targets and finds the most recent packet.
//
// A target whose heartbeat has gone stale is not counted ready. Its last
// reported state describes a sensor that may no longer exist, and carrying it
// forward would let a dead sensor hold the tap in Active.
func (r *NetworkTapReconciler) summarizeTargets(tap *trawlv1alpha1.NetworkTap) (ready int32, lastPacket *metav1.Time) {
	now := time.Now()
	for i := range tap.Status.Targets {
		target := &tap.Status.Targets[i]

		if now.Sub(target.HeartbeatTime.Time) > staleHeartbeat {
			continue
		}
		if allAnalyzersHealthy(target) {
			ready++
		}
		if target.LastPacketTime != nil {
			if lastPacket == nil || target.LastPacketTime.After(lastPacket.Time) {
				lastPacket = target.LastPacketTime
			}
		}
	}
	return ready, lastPacket
}

func allAnalyzersHealthy(target *trawlv1alpha1.TargetStatus) bool {
	if len(target.Analyzers) == 0 {
		return false
	}
	for _, a := range target.Analyzers {
		if !a.Healthy {
			return false
		}
	}
	return true
}

func (r *NetworkTapReconciler) analyzersHealthy(tap *trawlv1alpha1.NetworkTap) (metav1.ConditionStatus, string) {
	if len(tap.Status.Targets) == 0 {
		// No sensor has reported yet. Unknown, not False: nothing has been
		// observed to be wrong, and nothing has been observed to be right.
		return metav1.ConditionUnknown, "no sensor has reported yet"
	}

	var unhealthy []string
	for i := range tap.Status.Targets {
		target := &tap.Status.Targets[i]
		for _, a := range target.Analyzers {
			if !a.Healthy {
				unhealthy = append(unhealthy, fmt.Sprintf("%s/%s", target.NodeName, a.Name))
			}
		}
	}
	if len(unhealthy) == 0 {
		return metav1.ConditionTrue, "all analyzers healthy"
	}
	// Naming the specific failure is what makes Degraded actionable rather than
	// merely alarming.
	return metav1.ConditionFalse, sanitize.String(fmt.Sprintf("unhealthy: %v", unhealthy))
}

// workloadReady reports whether the rendered workload has available replicas.
func (r *NetworkTapReconciler) workloadReady(ctx context.Context, tap *trawlv1alpha1.NetworkTap) (bool, string) {
	name, _, _, _ := Names(tap)
	key := client.ObjectKey{Namespace: tap.Namespace, Name: name}

	if tap.Spec.Type == trawlv1alpha1.TapSourceMirrorInterface {
		var d appsv1.Deployment
		if err := r.Get(ctx, key, &d); err != nil {
			return false, "workload not created yet"
		}
		if d.Status.ReadyReplicas < 1 {
			return false, fmt.Sprintf("%d/%d replicas ready", d.Status.ReadyReplicas, d.Status.Replicas)
		}
		return true, "workload ready"
	}

	var ds appsv1.DaemonSet
	if err := r.Get(ctx, key, &ds); err != nil {
		return false, "workload not created yet"
	}
	if ds.Status.NumberReady < ds.Status.DesiredNumberScheduled || ds.Status.DesiredNumberScheduled == 0 {
		return false, fmt.Sprintf("%d/%d nodes ready", ds.Status.NumberReady, ds.Status.DesiredNumberScheduled)
	}
	return true, "workload ready"
}

// derivePhase aggregates the tap's state.
//
// Active is deliberately the strictest outcome: it requires every matched
// target ready and every analyzer healthy. An analyst reading Active must be
// able to trust that the evidence is complete, so partial health is Degraded.
func derivePhase(matched int, ready int32, workloadReady bool, analyzers metav1.ConditionStatus) trawlv1alpha1.TapPhase {
	switch {
	case matched == 0:
		return trawlv1alpha1.TapPhaseError
	case !workloadReady, analyzers == metav1.ConditionUnknown, ready == 0:
		return trawlv1alpha1.TapPhasePending
	case int(ready) < matched, analyzers == metav1.ConditionFalse:
		return trawlv1alpha1.TapPhaseDegraded
	default:
		return trawlv1alpha1.TapPhaseActive
	}
}

// finalize removes what the tap owns and releases the finalizer.
//
// Only owned monitoring resources are removed. Observations already in Loki and
// any CaptureJobs remain under their own retention: deleting a tap stops
// collection, it does not destroy the evidence already collected (FR-008).
func (r *NetworkTapReconciler) finalize(ctx context.Context, tap *trawlv1alpha1.NetworkTap) error {
	if !controllerutil.ContainsFinalizer(tap, finalizer) {
		return nil
	}

	// Owner references handle the deletion; the finalizer exists so the tap
	// object outlives its workloads long enough for that to be observable.
	controllerutil.RemoveFinalizer(tap, finalizer)
	if err := r.Update(ctx, tap); err != nil {
		if r.Metrics != nil {
			r.Metrics.FinalizerFailures.WithLabelValues("NetworkTap", status.ReasonPending).Inc()
		}
		return sanitize.Error(err)
	}
	return nil
}

// markError records an invalid or unresolvable tap without retrying forever.
// markError records that the tap is not proceeding, and withdraws everything
// status previously claimed about its targets.
//
// Setting the phase and the Accepted condition is not enough. Every other field
// here describes a reconcile that rendered a workload and read sensors back,
// and on this path none of that happened - so left alone they keep reporting
// the last pass that did. For a tap that was never healthy they are zero and
// nothing shows, which is why this went unnoticed. For a tap that was working
// and then lost its target, status ends up contradicting itself: Accepted=False
// saying the selector matched no nodes, beside TargetsResolved=True saying one
// node is eligible, matchedTargets=1, and readyTargets=1.
//
// readyTargets is the one that matters. It claims a target has a ready sensor
// while the DaemonSet it refers to has been scaled to zero pods and nothing is
// capturing - a tap reporting healthy and producing nothing, which is the
// failure this project's status rules exist to make impossible.
//
// The counts go to zero rather than to the number the selector saw. The field
// means how many targets the tap resolved to, and a tap that is not proceeding
// resolved to none; where the count is the point of the error, as it is for an
// ambiguous mirror selector, it is already in the message.
func (r *NetworkTapReconciler) markError(ctx context.Context, tap *trawlv1alpha1.NetworkTap, reason, message string) error {
	gen := tap.Generation
	tap.Status.ObservedGeneration = gen
	tap.Status.Phase = trawlv1alpha1.TapPhaseError

	tap.Status.MatchedTargets = 0
	tap.Status.ReadyTargets = 0
	tap.Status.Targets = nil

	status.Set(&tap.Status.Conditions, status.New(status.TypeAccepted,
		metav1.ConditionFalse, reason, message, gen))

	// The remaining conditions are answers this pass cannot give. They carry the
	// same reason so an operator reading any one of them is sent to the same
	// cause rather than to a stale explanation of its own.
	for _, condType := range []string{
		status.TypeTargetsResolved,
		status.TypeWorkloadReady,
		status.TypeAnalyzersHealthy,
		status.TypePacketsObserved,
	} {
		status.Set(&tap.Status.Conditions, status.New(condType,
			metav1.ConditionFalse, reason, message, gen))
	}

	if err := r.Status().Update(ctx, tap); err != nil {
		return sanitize.Error(err)
	}
	return nil
}

// SetupWithManager registers the controller.
func (r *NetworkTapReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&trawlv1alpha1.NetworkTap{}).
		Owns(&appsv1.Deployment{}).
		Owns(&appsv1.DaemonSet{}).
		Owns(&corev1.ConfigMap{}).
		// Nodes are what a tap's selector resolves against, and Owns cannot
		// reach them: a tap that matched no node owns nothing at all, so
		// without this watch there is no event left that could ever wake it.
		// It stayed in Error reporting "the node selector matched no nodes"
		// after the node had been given the matching label, which describes a
		// misconfiguration the operator has already corrected.
		//
		// The predicate is not an optimisation. Kubelet rewrites node status
		// every few seconds, and enqueueing every tap on every one of those
		// would keep the reconciler busy rewriting status it already agrees
		// with. Only label changes can alter which nodes a selector matches;
		// creates and deletes pass because the default Funcs admit them.
		Watches(&corev1.Node{},
			handler.EnqueueRequestsFromMapFunc(r.tapsForNodeChange),
			builder.WithPredicates(predicate.LabelChangedPredicate{})).
		Complete(r)
}

// tapsForNodeChange enqueues every tap when the node set changes.
//
// It enqueues all of them rather than the ones whose selector matches. A tap
// that must be woken here is precisely one whose selector matched nothing
// before the change, so a mapper that filtered by current match would skip the
// case the watch exists for. Reconciliation is idempotent and taps are few, so
// the cost of the wider fan-out is a status read per tap per label change.
func (r *NetworkTapReconciler) tapsForNodeChange(ctx context.Context, _ client.Object) []reconcile.Request {
	var taps trawlv1alpha1.NetworkTapList
	if err := r.List(ctx, &taps); err != nil {
		// Returning nothing is the only option here, so it is logged rather
		// than swallowed: the symptom would otherwise be a tap that never
		// notices a node, which is the defect this watch exists to fix.
		log.FromContext(ctx).Error(sanitize.Error(err),
			"Failed to list NetworkTaps for a node change")
		return nil
	}
	requests := make([]reconcile.Request, 0, len(taps.Items))
	for i := range taps.Items {
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKeyFromObject(&taps.Items[i]),
		})
	}
	return requests
}

func boolCondition(b bool) metav1.ConditionStatus {
	if b {
		return metav1.ConditionTrue
	}
	return metav1.ConditionFalse
}

func targetsReason(matched int) string {
	if matched > 0 {
		return status.ReasonTargetsResolved
	}
	return status.ReasonNoEligibleTargets
}

func workloadReasonEnum(ready bool) string {
	if ready {
		return status.ReasonWorkloadReady
	}
	return status.ReasonWorkloadProgressing
}

func analyzerReasonEnum(s metav1.ConditionStatus) string {
	switch s {
	case metav1.ConditionTrue:
		return status.ReasonAnalyzersHealthy
	case metav1.ConditionUnknown:
		return status.ReasonProbeUnavailable
	default:
		return status.ReasonAnalyzerDegraded
	}
}

func packetsReason(seen bool) string {
	if seen {
		return status.ReasonPacketsObserved
	}
	return status.ReasonNoPacketsObserved
}

func packetsMessage(last *metav1.Time) string {
	if last == nil {
		return "no packets observed yet"
	}
	return "last packet at " + last.UTC().Format(time.RFC3339)
}
