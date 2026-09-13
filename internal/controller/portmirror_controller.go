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
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/audit"
	"trawl.cloud/trawl/internal/fabric"
	"trawl.cloud/trawl/internal/sanitize"
	"trawl.cloud/trawl/internal/status"
)

// portMirrorFinalizer keeps a PortMirror around long enough to un-configure the
// device it changed.
//
// Without it, deleting the resource would leave the switch mirroring
// indefinitely with nothing in the cluster recording that it does - the exact
// shape of leftover this project keeps finding, except on hardware where a
// `kubectl get` will never show it.
const portMirrorFinalizer = "trawl.cloud/portmirror-revert"

// mirrorResyncInterval is how often a healthy mirror is re-read.
//
// A device is not a Kubernetes object: nothing watches it, nobody sends an
// event when somebody logs into the switch and changes the mirror by hand. The
// only way drift becomes visible is by asking, so a healthy mirror is
// deliberately re-reconciled rather than left alone.
const mirrorResyncInterval = 5 * time.Minute

// PortMirrorReconciler configures traffic mirroring on network devices.
type PortMirrorReconciler struct {
	client.Client

	// Providers holds the device drivers this binary was built with.
	Providers *fabric.Registry

	// Audit records device changes. Required: a controller that can change
	// network hardware without leaving a record is the least auditable and
	// most physically consequential thing in the installation.
	Audit audit.Committer

	// SystemNamespace is the only namespace PortMirrors are honoured in.
	SystemNamespace string

	// Actor identifies this controller in the ledger. Optional; defaults to
	// the manager's own workload identity.
	Actor func() audit.Actor
}

// +kubebuilder:rbac:groups=trawl.cloud,resources=portmirrors,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=trawl.cloud,resources=portmirrors/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=trawl.cloud,resources=portmirrors/finalizers,verbs=update

// Reconcile drives one PortMirror toward the device.
func (r *PortMirrorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var mirror trawlv1alpha1.PortMirror
	if err := r.Get(ctx, req.NamespacedName, &mirror); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Off-namespace resources are refused rather than serviced. Admission
	// rejects them too; this is the controller declining to act on one that
	// reached etcd by some other path.
	if mirror.Namespace != r.SystemNamespace {
		return r.fail(ctx, &mirror, status.ReasonAccepted,
			fmt.Errorf("PortMirror is only honoured in %s", r.SystemNamespace))
	}

	if !mirror.DeletionTimestamp.IsZero() {
		return r.revert(ctx, &mirror)
	}

	// Contention is settled before the finalizer is taken, and before the
	// device is so much as read. Both orderings are deliberate: see
	// checkDeviceConflict.
	if conflict, err := r.checkDeviceConflict(ctx, &mirror); conflict || err != nil {
		return ctrl.Result{RequeueAfter: mirrorResyncInterval}, err
	}

	if !controllerutil.ContainsFinalizer(&mirror, portMirrorFinalizer) {
		controllerutil.AddFinalizer(&mirror, portMirrorFinalizer)
		if err := r.Update(ctx, &mirror); err != nil {
			return ctrl.Result{}, err
		}
	}

	provider, err := r.Providers.Get(string(mirror.Spec.Provider))
	if err != nil {
		return r.fail(ctx, &mirror, status.ReasonAccepted, err)
	}

	device, err := r.device(ctx, &mirror)
	if err != nil {
		return r.fail(ctx, &mirror, status.ReasonCredentialMissing, err)
	}

	want := fabric.Mirror{
		Sources:   mirror.Spec.Sources,
		Target:    mirror.Spec.Target,
		Direction: fabric.Direction(mirror.Spec.Direction),
	}

	// Read before writing. A mirror that is already correct must not be
	// rewritten on every resync: the device logs a configuration change each
	// time, and filling somebody else's audit log with our reconcile loop is
	// its own kind of harm.
	observed, err := provider.Observe(ctx, device)
	if err != nil {
		return r.fail(ctx, &mirror, status.ReasonDeviceUnreachable, err)
	}

	if !observed.Matches(want) {
		if err := r.auditDevice(ctx, &mirror, audit.ActionPortMirrorConfigure,
			audit.DecisionAllowed, "configuring the device mirror"); err != nil {
			return r.fail(ctx, &mirror, status.ReasonAuditUnavailable, err)
		}
		if err := provider.Configure(ctx, device, want); err != nil {
			// The failure is audited too. An attempt to change network
			// hardware that was refused is exactly as interesting as one that
			// succeeded, and more so during an incident.
			if auditErr := r.auditDevice(ctx, &mirror, audit.ActionPortMirrorConfigure,
				audit.DecisionFailed, sanitize.Error(err).Error()); auditErr != nil {
				return r.fail(ctx, &mirror, status.ReasonAuditUnavailable, auditErr)
			}
			// The observation is recorded alongside the refusal. Without it
			// the operator sees only "the device refused", and has to log into
			// the switch to learn what it actually has - which is the question
			// this status field exists to answer, and is most pressing exactly
			// when Trawl has lost the ability to correct it.
			r.recordObservation(&mirror, observed)
			return r.fail(ctx, &mirror, status.ReasonDeviceRefused,
				fmt.Errorf("%w; the device currently reports target %q and sources %v",
					err, observed.Target, observed.Sources))
		}

		// Read back rather than assuming. Configure returning nil means every
		// request was accepted, not that the device is in the state asked for.
		observed, err = provider.Observe(ctx, device)
		if err != nil {
			return r.fail(ctx, &mirror, status.ReasonDeviceUnreachable, err)
		}
		if err := r.auditDevice(ctx, &mirror, audit.ActionPortMirrorConfigure,
			audit.DecisionSucceeded, "the device reports the requested mirror"); err != nil {
			return r.fail(ctx, &mirror, status.ReasonAuditUnavailable, err)
		}
	}

	return r.report(ctx, &mirror, observed, want)
}

// recordObservation copies what the device said onto the resource.
//
// Split out because it is wanted on the failure path as well as the success
// one: a refused change is exactly when somebody needs to know what the device
// has instead.
func (r *PortMirrorReconciler) recordObservation(mirror *trawlv1alpha1.PortMirror, observed fabric.State) {
	now := metav1.Now()
	mirror.Status.ObservedSources = observed.Sources
	mirror.Status.ObservedTarget = observed.Target
	if observed.Identity != "" {
		mirror.Status.DeviceIdentity = observed.Identity
	}
	mirror.Status.LastVerifiedTime = &now
}

// report writes status from what the device said.
func (r *PortMirrorReconciler) report(
	ctx context.Context,
	mirror *trawlv1alpha1.PortMirror,
	observed fabric.State,
	want fabric.Mirror,
) (ctrl.Result, error) {
	mirror.Status.ObservedGeneration = mirror.Generation
	r.recordObservation(mirror, observed)

	status.Set(&mirror.Status.Conditions, status.New(status.TypeDeviceReachable,
		metav1.ConditionTrue, status.ReasonDeviceReachable, observed.Identity, mirror.Generation))

	if observed.Matches(want) {
		mirror.Status.Phase = trawlv1alpha1.PortMirrorActive
		status.Set(&mirror.Status.Conditions, status.New(status.TypeMirrorConfigured,
			metav1.ConditionTrue, status.ReasonMirrorConfigured,
			"the device reports the requested mirror", mirror.Generation))
	} else {
		// Reachable and wrong. Recorded as drift rather than as an error
		// because the difference matters to whoever reads it: the device is
		// answering, and somebody or something changed it.
		mirror.Status.Phase = trawlv1alpha1.PortMirrorDegraded
		status.Set(&mirror.Status.Conditions, status.New(status.TypeMirrorConfigured,
			metav1.ConditionFalse, status.ReasonMirrorDrifted,
			fmt.Sprintf("the device reports target %q and sources %v", observed.Target, observed.Sources),
			mirror.Generation))
	}

	if err := r.Status().Update(ctx, mirror); err != nil {
		return ctrl.Result{}, err
	}
	// Re-read on a timer: nothing sends an event when a switch is edited.
	return ctrl.Result{RequeueAfter: mirrorResyncInterval}, nil
}

// revert un-configures the device and releases the finalizer.
func (r *PortMirrorReconciler) revert(ctx context.Context, mirror *trawlv1alpha1.PortMirror) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(mirror, portMirrorFinalizer) {
		return ctrl.Result{}, nil
	}

	provider, err := r.Providers.Get(string(mirror.Spec.Provider))
	if err == nil {
		var device fabric.Device
		device, err = r.device(ctx, mirror)
		if err == nil {
			if auditErr := r.auditDevice(ctx, mirror, audit.ActionPortMirrorRevert,
				audit.DecisionAllowed, "removing the device mirror"); auditErr != nil {
				return ctrl.Result{}, auditErr
			}
			err = provider.Revert(ctx, device)
		}
	}

	if err != nil {
		// The finalizer is deliberately held. Releasing it here would delete
		// the only record that this device is still mirroring, leaving traffic
		// copied to a port with nothing in the cluster explaining why - and an
		// operator with no way to find it short of logging into the switch.
		if auditErr := r.auditDevice(ctx, mirror, audit.ActionPortMirrorRevert,
			audit.DecisionFailed, sanitize.Error(err).Error()); auditErr != nil {
			return ctrl.Result{}, auditErr
		}
		return r.fail(ctx, mirror, status.ReasonDeviceUnreachable,
			fmt.Errorf("the device mirror could not be removed, so this resource is kept: %w", err))
	}

	if auditErr := r.auditDevice(ctx, mirror, audit.ActionPortMirrorRevert,
		audit.DecisionSucceeded, "the device mirror was removed"); auditErr != nil {
		return ctrl.Result{}, auditErr
	}

	controllerutil.RemoveFinalizer(mirror, portMirrorFinalizer)
	return ctrl.Result{}, r.Update(ctx, mirror)
}

// checkDeviceConflict refuses to drive a device another PortMirror already holds.
//
// A RouterOS switch has one global mirror-target. Two PortMirrors naming the
// same deviceRef therefore describe one piece of hardware and disagree about
// it, and left alone each observes the other's configuration as drift and
// rewrites it on the next resync. That is not a slow leak: it is indefinite
// flapping, and every lap of it writes a configuration change to the device log
// and a record to the write-once ledger. The ledger cannot be pruned, so a
// contention nobody noticed is a contention nobody can clean up after.
//
// Admission cannot do this. Whether two resources contend depends on what else
// is stored at the moment they are compared, and an admission webhook sees one
// object with no reliable view of the rest - so a pair created concurrently
// would both pass and both be wrong. It belongs at reconcile time, which is
// also where ProbePortConflict settles the same shape of question.
//
// The younger claim yields, so contention can never take down a mirror that is
// already running: the incumbent keeps the device and keeps mirroring. The
// yielding resource does not take the finalizer either, because the finalizer's
// whole purpose is to revert the device on deletion - and a resource that never
// configured the device would, in reverting it, tear down the mirror the
// incumbent owns.
func (r *PortMirrorReconciler) checkDeviceConflict(
	ctx context.Context,
	mirror *trawlv1alpha1.PortMirror,
) (bool, error) {
	var mirrors trawlv1alpha1.PortMirrorList
	if err := r.List(ctx, &mirrors, client.InNamespace(r.SystemNamespace)); err != nil {
		_, statusErr := r.fail(ctx, mirror, status.ReasonDependencyUnavailable,
			fmt.Errorf("listing PortMirrors to check for device contention: %w", err))
		if statusErr != nil {
			return true, statusErr
		}
		return true, nil
	}

	for i := range mirrors.Items {
		other := &mirrors.Items[i]
		if other.UID == mirror.UID || !other.DeletionTimestamp.IsZero() {
			continue
		}
		if other.Spec.DeviceRef.Name != mirror.Spec.DeviceRef.Name {
			continue
		}
		if !olderClaim(other, mirror) {
			continue
		}
		// Deliberately not conditioned on the incumbent's phase. An incumbent
		// that is currently failing - an unreachable device, a missing
		// credential - may recover at any time, and a rule that let the
		// younger claim seize the device whenever the older one stumbled would
		// hand the two of them the device in turn, which is the flapping this
		// exists to prevent.
		_, err := r.fail(ctx, mirror, status.ReasonDeviceConflict,
			fmt.Errorf("PortMirror %s/%s already holds device %q; a device has one mirror target, "+
				"so the older claim keeps it and this resource makes no device changes",
				other.Namespace, other.Name, sanitize.String(other.Spec.DeviceRef.Name)))
		return true, err
	}
	return false, nil
}

// olderClaim reports whether other has the prior claim on a contended resource.
//
// Creation time decides it, with the UID as a tie-break so that two objects
// created in the same instant still agree on which of them yields. They
// reconcile independently, and a rule they could read differently would yield
// both or neither.
func olderClaim(other, mine metav1.Object) bool {
	otherAt, mineAt := other.GetCreationTimestamp(), mine.GetCreationTimestamp()
	if !otherAt.Equal(&mineAt) {
		return otherAt.Before(&mineAt)
	}
	return string(other.GetUID()) < string(mine.GetUID())
}

// device resolves the credential Secret into a fabric.Device.
func (r *PortMirrorReconciler) device(ctx context.Context, mirror *trawlv1alpha1.PortMirror) (fabric.Device, error) {
	var secret corev1.Secret
	key := client.ObjectKey{Namespace: mirror.Namespace, Name: mirror.Spec.DeviceRef.Name}
	if err := r.Get(ctx, key, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			return fabric.Device{}, fmt.Errorf("device Secret %q does not exist", sanitize.String(key.Name))
		}
		return fabric.Device{}, err
	}

	device := fabric.Device{
		Address:   string(secret.Data["address"]),
		Username:  string(secret.Data["username"]),
		Password:  string(secret.Data["password"]),
		CACertPEM: secret.Data["ca.crt"],
	}
	// Opt-in per device and only when no CA is pinned, so an installation that
	// trusts whatever answers is visible in the Secret that chose it.
	if len(device.CACertPEM) == 0 && string(secret.Data["insecureSkipVerify"]) == "true" {
		device.InsecureSkipVerify = true
	}

	var missing []string
	if device.Address == "" {
		missing = append(missing, "address")
	}
	if device.Username == "" {
		missing = append(missing, "username")
	}
	if device.Password == "" {
		missing = append(missing, "password")
	}
	if len(missing) > 0 {
		return fabric.Device{}, fmt.Errorf("device Secret %q is missing %v",
			sanitize.String(key.Name), missing)
	}
	return device, nil
}

// auditDevice records one device change.
func (r *PortMirrorReconciler) auditDevice(
	ctx context.Context,
	mirror *trawlv1alpha1.PortMirror,
	action, decision, message string,
) error {
	if r.Audit == nil {
		return errors.New("no audit committer, so a device change cannot be recorded")
	}
	actor := r.defaultActor()
	if r.Actor != nil {
		actor = r.Actor()
	}
	_, err := r.Audit.Commit(ctx, audit.Record{
		Action:   action,
		Decision: decision,
		Reason:   "PortMirrorReconcile",
		Message:  message,
		Actor:    actor,
		Resource: audit.Resource{
			Group:     trawlv1alpha1.GroupVersion.Group,
			Kind:      "PortMirror",
			Namespace: mirror.Namespace,
			Name:      mirror.Name,
			UID:       string(mirror.UID),
		},
		StableKey: audit.StableKeyForAutomatic(action, string(mirror.UID),
			fmt.Sprintf("%s/%d", decision, mirror.Generation)),
	})
	return err
}

// defaultActor is the manager's own identity.
//
// The *deployed* name, with the namePrefix the overlay applies. Naming the
// pre-prefix "controller-manager" here would put an identity in the ledger
// that does not exist, which is exactly the defect T119 found in the event
// worker's configuration.
func (r *PortMirrorReconciler) defaultActor() audit.Actor {
	return audit.Actor{
		Username: "system:serviceaccount:" + r.SystemNamespace + ":trawl-controller-manager",
	}
}

// fail records an error on the resource and requeues.
func (r *PortMirrorReconciler) fail(
	ctx context.Context,
	mirror *trawlv1alpha1.PortMirror,
	reason string,
	cause error,
) (ctrl.Result, error) {
	mirror.Status.Phase = trawlv1alpha1.PortMirrorError
	mirror.Status.ObservedGeneration = mirror.Generation

	condition := status.TypeDeviceReachable
	switch reason {
	case status.ReasonDeviceRefused, status.ReasonAccepted, status.ReasonDeviceConflict:
		// None of these are statements about reachability. A contended mirror
		// in particular has not spoken to the device at all, so claiming it
		// unreachable would be inventing an observation nobody made.
		condition = status.TypeMirrorConfigured
	}
	status.Set(&mirror.Status.Conditions, status.New(condition,
		metav1.ConditionFalse, reason, sanitize.Error(cause).Error(), mirror.Generation))

	if err := r.Status().Update(ctx, mirror); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: mirrorResyncInterval}, nil
}

// SetupWithManager registers the controller.
func (r *PortMirrorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&trawlv1alpha1.PortMirror{}).
		Named("portmirror").
		Complete(r)
}
