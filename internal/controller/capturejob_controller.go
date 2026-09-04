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

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/admission"
	"trawl.cloud/trawl/internal/audit"
	"trawl.cloud/trawl/internal/capture"
	"trawl.cloud/trawl/internal/config"
	"trawl.cloud/trawl/internal/sanitize"
	"trawl.cloud/trawl/internal/status"
	"trawl.cloud/trawl/internal/storage"
	"trawl.cloud/trawl/internal/telemetry"
)

const (
	captureFinalizer = "trawl.cloud/capturejob-cleanup"

	// captureRequeue is the safety requeue while a capture is in flight. The
	// reporter's status writes and the Job's own events are the primary wake
	// signals; this covers a tap heartbeat going stale while nothing else
	// changes.
	captureRequeue = 15 * time.Second

	// jobDeletionRequeue is how long to wait for a foreground-deleted Job to
	// take its pod with it before the finalizer looks again.
	jobDeletionRequeue = 5 * time.Second

	// runnerContainerName is the container whose exit code is the capture's.
	runnerContainerName = "capture-runner"

	// rootCAConfigMap and rootCAKey locate the cluster CA every namespace
	// carries, projected next to a service account token.
	rootCAConfigMap = "kube-root-ca.crt"
	rootCAKey       = "ca.crt"

	// capNetRaw and capNetAdmin are the two capabilities a packet capture
	// needs and the only two any Trawl workload is ever granted.
	capNetRaw   corev1.Capability = "NET_RAW"
	capNetAdmin corev1.Capability = "NET_ADMIN"

	// jobNameLabel is what the Job controller stamps on the pods it creates.
	jobNameLabel = "batch.kubernetes.io/job-name"

	kindCaptureJob = "CaptureJob"

	// artifactProfile names the installation bucket profile captures are
	// stored in. It is the key of the profile in the installation config,
	// not the bucket itself, so status never repeats storage coordinates.
	artifactProfile = "artifacts"
)

// CaptureJobReconciler drives a CaptureJob from request to verified artifact.
//
// The decision of what a capture's state is lives in capture.Evaluate, which
// is pure; this type gathers the facts that decision needs, applies the side
// effects it asks for, and persists the result. Every write it makes is
// derived from what it observed on this pass, so a repeat pass over the same
// cluster state reaches the same result and writes nothing new.
type CaptureJobReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Config   *config.Config
	Renderer *CaptureRenderer
	// Store is the artifact bucket. The controller only ever reads it and
	// deletes from it; the runner is the only writer.
	Store storage.Store
	// Audit commits transition records. A transition is not made until its
	// record is durable (ADR-0003).
	Audit   audit.Committer
	Metrics *telemetry.Metrics
	// Now is the clock; tests fix it.
	Now func() time.Time
}

// +kubebuilder:rbac:groups=trawl.cloud,resources=capturejobs,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=trawl.cloud,resources=capturejobs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=trawl.cloud,resources=capturejobs/finalizers,verbs=update
// +kubebuilder:rbac:groups=trawl.cloud,resources=networktaps,verbs=get;list;watch
// +kubebuilder:rbac:groups=batch,resources=jobs,verbs=get;list;watch;create;delete
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;rolebindings,verbs=get;list;watch;create;update;delete
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

func (r *CaptureJobReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Reconcile converges one CaptureJob.
func (r *CaptureJobReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	start := time.Now()
	result := telemetry.ReconcileSuccess
	defer func() {
		if r.Metrics != nil {
			r.Metrics.ReconcileTotal.WithLabelValues(telemetry.ControllerCaptureJob, result).Inc()
			r.Metrics.ReconcileDurationSeconds.
				WithLabelValues(telemetry.ControllerCaptureJob).
				Observe(time.Since(start).Seconds())
		}
	}()

	var job trawlv1alpha1.CaptureJob
	if err := r.Get(ctx, req.NamespacedName, &job); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		result = telemetry.ReconcileError
		return ctrl.Result{}, sanitize.Error(err)
	}

	if !job.DeletionTimestamp.IsZero() {
		res, err := r.finalize(ctx, &job)
		result = reconcileOutcome(err)
		if err == nil {
			result = telemetry.ReconcileSuccess
		}
		return res, err
	}

	// Defence in depth against an object that reached etcd without passing
	// the webhook. It fails rather than errors: the spec is what it is, and
	// retrying would not change it.
	if job.Namespace != r.Config.SystemNamespace {
		result = telemetry.ReconcileInvalid
		return ctrl.Result{}, r.reject(ctx, &job, status.ReasonWrongNamespace, trawlv1alpha1.FailureInternalError,
			fmt.Sprintf("CaptureJob resources are reconciled only in %q", r.Config.SystemNamespace))
	}

	if !controllerutil.ContainsFinalizer(&job, captureFinalizer) {
		controllerutil.AddFinalizer(&job, captureFinalizer)
		if err := r.Update(ctx, &job); err != nil {
			result = telemetry.ReconcileError
			return ctrl.Result{}, sanitize.Error(err)
		}
	}

	if capture.IsTerminal(job.Status.Phase) {
		return ctrl.Result{}, r.reconcileTerminal(ctx, &job)
	}

	if errs := admission.ValidateCaptureJobSpec(&job.Spec, r.retentionCeiling()); len(errs) > 0 {
		result = telemetry.ReconcileInvalid
		return ctrl.Result{}, r.reject(ctx, &job, status.ReasonInvalidSpec, trawlv1alpha1.FailureInvalidBounds,
			errs.ToAggregate().Error())
	}

	obs, runnerJob, err := r.observe(ctx, &job)
	if err != nil {
		result = telemetry.ReconcileDependencyUnavailable
		return ctrl.Result{}, r.reportUnavailable(ctx, &job, "observing the capture's dependencies", err)
	}

	outcome, err := capture.Evaluate(&job, obs, staleHeartbeat)
	if err != nil {
		result = telemetry.ReconcileError
		return ctrl.Result{}, sanitize.Error(err)
	}

	if outcome.Action == capture.ActionCreateJob {
		created, err := r.createRunner(ctx, &job, outcome)
		switch {
		case err != nil:
			result = telemetry.ReconcileDependencyUnavailable
			return ctrl.Result{}, r.reportUnavailable(ctx, &job, "creating the runner Job", err)
		case created == nil:
			// The apiserver rejected the Job outright; the outcome is
			// rewritten to say so and persisted below.
			outcome = rejectedRunner(job.Status.Phase)
		default:
			runnerJob = created
		}
	}

	if err := r.persist(ctx, &job, obs, outcome, runnerJob); err != nil {
		result = reconcileOutcome(err)
		return ctrl.Result{}, err
	}

	if outcome.Action == capture.ActionCleanupArtifact {
		if err := r.deleteArtifact(ctx, &job); err != nil {
			result = telemetry.ReconcileDependencyUnavailable
			return ctrl.Result{}, err
		}
	}

	if capture.IsTerminal(outcome.Phase) {
		return ctrl.Result{}, nil
	}
	requeue := outcome.RequeueAfter
	if requeue == 0 || requeue > captureRequeue {
		requeue = captureRequeue
	}
	return ctrl.Result{RequeueAfter: requeue}, nil
}

// reconcileTerminal handles the little that changes after a capture ends: a
// retention edit moves the deadline, and a failed cleanup is retried until
// the bucket agrees. Expiry itself belongs to the retention controller.
func (r *CaptureJobReconciler) reconcileTerminal(ctx context.Context, job *trawlv1alpha1.CaptureJob) error {
	if job.Status.Phase == trawlv1alpha1.CapturePhaseFailed && cleanupPending(job) {
		if err := r.deleteArtifact(ctx, job); err != nil {
			return err
		}
	}
	if job.Status.ObservedGeneration == job.Generation || job.Status.Phase != trawlv1alpha1.CapturePhaseCompleted {
		return nil
	}
	if job.Status.CompletedAt == nil {
		return nil
	}
	deadline, err := capture.RetentionDeadline(job.Status.CompletedAt.Time, job.Spec.Retention)
	if err != nil {
		// The webhook keeps retention parseable; an unparseable one here is
		// a stored object nobody validated, and leaving the old deadline in
		// place is safer than guessing a new one.
		log.FromContext(ctx).Error(sanitize.Error(err), "retention on a completed capture is unparseable; deadline unchanged")
		return nil
	}
	job.Status.ObservedGeneration = job.Generation
	job.Status.RetentionDeadline = metaTime(deadline)
	r.setDownloadable(job)
	// The retention change itself is audited by the webhook that admitted it.
	return r.writeStatus(ctx, job, status.ReasonPending)
}

// cleanupPending reports whether a failed capture may still have objects in
// the bucket. The failure reasons that ask for cleanup are the ones where the
// runner stored something the controller could not accept.
func cleanupPending(job *trawlv1alpha1.CaptureJob) bool {
	f := job.Status.Failure
	if f == nil {
		return false
	}
	return f.Reason == trawlv1alpha1.FailureArtifactMismatch || f.Reason == trawlv1alpha1.FailureUploadFailed
}

func (r *CaptureJobReconciler) retentionCeiling() time.Duration {
	if r.Config == nil || r.Config.CaptureRetentionCeiling <= 0 {
		return config.DefaultCaptureRetentionCeiling
	}
	return r.Config.CaptureRetentionCeiling.Duration()
}

// observe gathers the facts Evaluate decides on. It consults only what the
// decision can use: the tap while no runner exists, storage once the runner
// says the capture ended or the Job has finished.
func (r *CaptureJobReconciler) observe(ctx context.Context, job *trawlv1alpha1.CaptureJob) (capture.Observation, *batchv1.Job, error) {
	obs := capture.Observation{Now: r.now()}

	runnerJob, err := r.observeJob(ctx, job, &obs)
	if err != nil {
		return obs, nil, err
	}

	if obs.Job.State == capture.JobAbsent && job.Status.RunnerJobRef == nil {
		if err := r.observeTarget(ctx, job, &obs); err != nil {
			return obs, nil, err
		}
	}

	terminal := obs.Job.State == capture.JobSucceeded || obs.Job.State == capture.JobFailed
	if terminal || job.Status.CaptureEndedAt != nil || job.Status.Phase == trawlv1alpha1.CapturePhaseStoring {
		r.observeArtifact(ctx, job, &obs)
	}
	return obs, runnerJob, nil
}

// observeJob finds the runner Job by its stable name and reads its state. A
// Job of that name owned by something else is reported as failed rather than
// adopted: the name derives from the capture's UID, so this cannot happen
// by accident, and creating over it would fail forever.
func (r *CaptureJobReconciler) observeJob(ctx context.Context, job *trawlv1alpha1.CaptureJob, obs *capture.Observation) (*batchv1.Job, error) {
	name, _, _ := CaptureNames(job)
	var runnerJob batchv1.Job
	err := r.Get(ctx, client.ObjectKey{Namespace: job.Namespace, Name: name}, &runnerJob)
	switch {
	case apierrors.IsNotFound(err):
		obs.Job.State = capture.JobAbsent
		return nil, nil
	case err != nil:
		return nil, sanitize.Errorf("reading the runner Job: %v", err)
	}
	if owner := metav1.GetControllerOf(&runnerJob); owner == nil || owner.UID != job.UID {
		obs.Job = capture.JobObservation{State: capture.JobFailed, Reason: "ForeignOwner"}
		return nil, nil
	}

	obs.Job.State = capture.JobActive
	for _, c := range runnerJob.Status.Conditions {
		if c.Status != corev1.ConditionTrue {
			continue
		}
		switch c.Type {
		case batchv1.JobComplete:
			obs.Job.State = capture.JobSucceeded
		case batchv1.JobFailed:
			obs.Job.State = capture.JobFailed
			obs.Job.Reason = c.Reason
		}
	}
	if obs.Job.State == capture.JobActive {
		return &runnerJob, nil
	}

	code, err := r.runnerExitCode(ctx, job.Namespace, name)
	if err != nil {
		return nil, err
	}
	obs.Job.ExitCode = code
	return &runnerJob, nil
}

// runnerExitCode reads the runner container's exit code from the Job's pod,
// when the pod still exists. Nil means it could not be learned, which
// Evaluate treats as "fall back to the Job's own reason".
func (r *CaptureJobReconciler) runnerExitCode(ctx context.Context, namespace, jobName string) (*int32, error) {
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(namespace), client.MatchingLabels{jobNameLabel: jobName}); err != nil {
		return nil, sanitize.Errorf("listing the runner's pods: %v", err)
	}
	for i := range pods.Items {
		for _, cs := range pods.Items[i].Status.ContainerStatuses {
			if cs.Name == runnerContainerName && cs.State.Terminated != nil {
				code := cs.State.Terminated.ExitCode
				return &code, nil
			}
		}
	}
	return nil, nil
}

// observeTarget decides whether the tap can host a runner on the target node
// right now. The bar is the same one the tap's own status uses to call a
// target healthy: the tap accepted its current spec, is Active or Degraded,
// and the node's sensor has reported within the heartbeat window.
func (r *CaptureJobReconciler) observeTarget(ctx context.Context, job *trawlv1alpha1.CaptureJob, obs *capture.Observation) error {
	var tap trawlv1alpha1.NetworkTap
	err := r.Get(ctx, client.ObjectKey{Namespace: job.Namespace, Name: job.Spec.TapRef.Name}, &tap)
	switch {
	case apierrors.IsNotFound(err):
		obs.Target.State = capture.TargetTapMissing
		return nil
	case err != nil:
		return sanitize.Errorf("reading the tap: %v", err)
	}
	if !tap.DeletionTimestamp.IsZero() {
		obs.Target.State = capture.TargetTapDeleting
		return nil
	}
	active := tap.Status.Phase == trawlv1alpha1.TapPhaseActive || tap.Status.Phase == trawlv1alpha1.TapPhaseDegraded
	if !active || !status.IsTrue(tap.Status.Conditions, status.TypeAccepted, tap.Generation) {
		obs.Target.State = capture.TargetTapInactive
		return nil
	}
	obs.Target.State = capture.TargetUnavailable
	for i := range tap.Status.Targets {
		t := &tap.Status.Targets[i]
		if t.NodeName != job.Spec.TargetNode {
			continue
		}
		if obs.Now.Sub(t.HeartbeatTime.Time) > staleHeartbeat {
			return nil
		}
		obs.Target = capture.TargetObservation{
			State:     capture.TargetEligible,
			TapUID:    tap.UID,
			Interface: t.Interface,
		}
		return nil
	}
	return nil
}

// observeArtifact checks the bucket for the capture's object and manifest and
// verifies them against each other. Storage errors become Unavailable, never
// Absent: "I could not look" and "there is nothing there" lead to opposite
// decisions.
func (r *CaptureJobReconciler) observeArtifact(ctx context.Context, job *trawlv1alpha1.CaptureJob, obs *capture.Observation) {
	uid := string(job.UID)
	objectKey := capture.ObjectKey(job.Namespace, uid)
	manifestKey := capture.ManifestKey(job.Namespace, uid)
	obs.Artifact.Key = objectKey

	state, manifest, info := r.lookupArtifact(ctx, uid, objectKey, manifestKey)
	obs.Artifact.State = state
	obs.Artifact.Manifest = manifest
	obs.Artifact.ETag = info.ETag

	if r.Metrics != nil {
		result := telemetry.ArtifactResultFailure
		switch state {
		case capture.ArtifactVerified, capture.ArtifactAbsent:
			result = telemetry.ArtifactResultSuccess
		case capture.ArtifactUnavailable:
			result = telemetry.ArtifactResultUnavailable
		}
		r.Metrics.ArtifactOperationsTotal.WithLabelValues(telemetry.ArtifactOpVerify, result).Inc()
	}
}

func (r *CaptureJobReconciler) lookupArtifact(ctx context.Context, uid, objectKey, manifestKey string) (
	capture.ArtifactState, *capture.Manifest, storage.ObjectInfo,
) {
	logger := log.FromContext(ctx)
	info, err := r.Store.Head(ctx, objectKey)
	switch {
	case errors.Is(err, storage.ErrNotFound):
		_, merr := r.Store.Head(ctx, manifestKey)
		switch {
		case errors.Is(merr, storage.ErrNotFound):
			return capture.ArtifactAbsent, nil, storage.ObjectInfo{}
		case merr != nil:
			logger.Error(sanitize.Error(merr), "artifact storage unavailable")
			return capture.ArtifactUnavailable, nil, storage.ObjectInfo{}
		}
		// A manifest without its object is nothing the runner writes; it is
		// unverifiable and gets cleaned up as such.
		return capture.ArtifactPresent, nil, storage.ObjectInfo{}
	case err != nil:
		logger.Error(sanitize.Error(err), "artifact storage unavailable")
		return capture.ArtifactUnavailable, nil, storage.ObjectInfo{}
	}

	raw, err := r.Store.Get(ctx, manifestKey)
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return capture.ArtifactPresent, nil, info
	case err != nil:
		logger.Error(sanitize.Error(err), "artifact storage unavailable")
		return capture.ArtifactUnavailable, nil, info
	}
	manifest, err := capture.ParseManifest(raw)
	if err != nil {
		logger.Info("artifact manifest is unreadable", "reason", sanitize.Error(err).Error())
		return capture.ArtifactPresent, nil, info
	}
	if err := capture.VerifyArtifact(manifest, uid, info.Size, info.Metadata); err != nil {
		logger.Info("artifact does not match its manifest", "reason", sanitize.Error(err).Error())
		return capture.ArtifactMismatch, manifest, info
	}
	return capture.ArtifactVerified, manifest, info
}

// createRunner renders and creates the capture's owned objects. The Job is
// created once and never updated: its spec is the capture's spec, which is
// immutable, and a changed Job would be a different capture.
//
// A nil Job with a nil error means the apiserver rejected the Job as
// invalid or forbidden - a configuration fault, not a transient one - and
// the capture should fail rather than retry.
func (r *CaptureJobReconciler) createRunner(ctx context.Context, job *trawlv1alpha1.CaptureJob, outcome capture.Outcome) (*batchv1.Job, error) {
	bounds, err := capture.ParseBounds(job.Spec)
	if err != nil {
		return nil, err
	}
	for _, obj := range []client.Object{
		r.Renderer.ServiceAccount(job),
		r.Renderer.StatusRole(job),
		r.Renderer.StatusRoleBinding(job),
	} {
		if err := r.applyOwned(ctx, job, obj); err != nil {
			return nil, err
		}
	}

	runnerJob := r.Renderer.Job(job, bounds, outcome.ResolvedInterface)
	if err := controllerutil.SetControllerReference(job, runnerJob, r.Scheme); err != nil {
		return nil, sanitize.Errorf("setting owner reference: %v", err)
	}
	err = r.Create(ctx, runnerJob)
	switch {
	case err == nil:
		return runnerJob, nil
	case apierrors.IsAlreadyExists(err):
		// Raced with a previous pass whose status write did not land. The
		// next observation adopts it by name.
		var existing batchv1.Job
		if err := r.Get(ctx, client.ObjectKeyFromObject(runnerJob), &existing); err != nil {
			return nil, sanitize.Errorf("reading the runner Job: %v", err)
		}
		return &existing, nil
	case apierrors.IsInvalid(err), apierrors.IsForbidden(err):
		log.FromContext(ctx).Error(sanitize.Error(err), "the runner Job was rejected")
		return nil, nil
	default:
		return nil, sanitize.Errorf("creating the runner Job: %v", err)
	}
}

// rejectedRunner is the outcome for a Job the apiserver would not accept.
func rejectedRunner(phase trawlv1alpha1.CapturePhase) capture.Outcome {
	if phase == "" {
		phase = trawlv1alpha1.CapturePhasePending
	}
	return capture.Outcome{
		Phase: trawlv1alpha1.CapturePhaseFailed,
		Failure: &trawlv1alpha1.CaptureFailure{
			Reason:      trawlv1alpha1.FailureRunnerCreateFailed,
			Message:     "the apiserver rejected the runner Job; check the installation's images, credentials Secret, and quotas",
			FailedPhase: phase,
			Attempts:    1,
		},
	}
}

// applyOwned creates or updates a supporting object under the capture's
// ownership. Only the identity objects go through here; the Job does not.
func (r *CaptureJobReconciler) applyOwned(ctx context.Context, job *trawlv1alpha1.CaptureJob, desired client.Object) error {
	if err := controllerutil.SetControllerReference(job, desired, r.Scheme); err != nil {
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
	desired.SetResourceVersion(existing.GetResourceVersion())
	if err := r.Update(ctx, desired); err != nil {
		return sanitize.Errorf("updating owned resource: %v", err)
	}
	return nil
}

// persist commits the transition's audit record, then writes the status the
// outcome describes. The order is the point: a phase the ledger does not
// know about is a phase that did not happen (ADR-0003), so when the ledger
// is unavailable the object keeps its previous phase and the pass is
// retried.
func (r *CaptureJobReconciler) persist(ctx context.Context, job *trawlv1alpha1.CaptureJob, obs capture.Observation,
	outcome capture.Outcome, runnerJob *batchv1.Job,
) error {
	before := job.Status.DeepCopy()
	from := job.Status.Phase

	if outcome.Phase != from {
		if !capture.CanTransition(from, outcome.Phase) {
			// Nothing an observation can say should move a capture backwards
			// or out of a terminal phase, so reaching here is a bug in the
			// derivation rather than a state the cluster got into. The pass is
			// dropped whole: an outcome whose phase is impossible is not one
			// to trust the rest of for conditions either, and dropping it
			// leaves the object as the ledger last described it.
			log.FromContext(ctx).Error(nil, "refusing an impossible capture phase transition",
				"from", from, "to", outcome.Phase)
			return nil
		}
		if err := r.auditTransition(ctx, job, outcome); err != nil {
			r.markAuditUnavailable(job, err)
			if werr := r.writeStatus(ctx, job, status.ReasonAuditUnavailable); werr != nil {
				log.FromContext(ctx).Error(werr, "recording an audit failure in status")
			}
			return err
		}
	}

	r.applyOutcome(job, obs, outcome, runnerJob)
	if equality.Semantic.DeepEqual(before, &job.Status) {
		return nil
	}
	if err := r.writeStatus(ctx, job, string(outcome.Phase)); err != nil {
		return err
	}
	r.observeTransition(job, from, outcome)
	return nil
}

// auditTransition commits the record for entering outcome.Phase. Its content
// is a function of the capture's identity and the outcome's fixed strings,
// so a retry after a failed status write commits byte-identical content and
// the sink reports it as the same record.
func (r *CaptureJobReconciler) auditTransition(ctx context.Context, job *trawlv1alpha1.CaptureJob, outcome capture.Outcome) error {
	if r.Audit == nil {
		return admission.ErrAuditUnavailable
	}
	rec := audit.Record{
		Action:      audit.ActionCaptureJobTransition,
		Decision:    audit.DecisionSucceeded,
		Reason:      string(outcome.Phase),
		Message:     "the capture entered " + string(outcome.Phase),
		Actor:       r.actor(),
		Resource:    resourceFor(job),
		StableKey:   audit.StableKeyForAutomatic(audit.ActionCaptureJobTransition, string(job.UID), capture.TransitionStep(outcome.Phase)),
		InitiatedBy: job.Annotations[trawlv1alpha1.AnnotationRequester],
	}
	if outcome.Failure != nil {
		rec.Decision = audit.DecisionFailed
		rec.Reason = string(outcome.Failure.Reason)
		rec.Message = outcome.Failure.Message
	}
	return r.commit(ctx, rec)
}

func (r *CaptureJobReconciler) commit(ctx context.Context, rec audit.Record) error {
	res, err := r.Audit.Commit(ctx, rec)
	if r.Metrics != nil {
		result := res.Result
		if result == "" {
			result = audit.ResultUnavailable
		}
		r.Metrics.AuditCommitTotal.WithLabelValues(rec.Decision, result).Inc()
		if result == audit.ResultConflict {
			r.Metrics.AuditConflictTotal.Inc()
		}
	}
	if err != nil {
		return fmt.Errorf("%w: %w", admission.ErrAuditUnavailable, sanitize.Error(err))
	}
	return nil
}

func (r *CaptureJobReconciler) actor() audit.Actor {
	return audit.Actor{Username: "system:serviceaccount:" + r.Config.SystemNamespace + ":trawl-controller-manager"}
}

func resourceFor(job *trawlv1alpha1.CaptureJob) audit.Resource {
	return audit.Resource{
		Group:     trawlv1alpha1.GroupVersion.Group,
		Kind:      kindCaptureJob,
		Namespace: job.Namespace,
		Name:      job.Name,
		UID:       string(job.UID),
	}
}

// applyOutcome writes the outcome into status. Reporter-owned fields are
// left alone except at Completed, where the verified manifest is the better
// source for all of them.
func (r *CaptureJobReconciler) applyOutcome(job *trawlv1alpha1.CaptureJob, obs capture.Observation,
	outcome capture.Outcome, runnerJob *batchv1.Job,
) {
	s := &job.Status
	gen := job.Generation
	s.ObservedGeneration = gen
	s.Phase = outcome.Phase
	if s.RequestedAt == nil {
		s.RequestedAt = &job.CreationTimestamp
	}
	if runnerJob != nil {
		s.RunnerJobRef = &corev1.LocalObjectReference{Name: runnerJob.Name}
	}
	if outcome.ResolvedTapUID != "" {
		s.ResolvedTapUID = outcome.ResolvedTapUID
	}

	status.Set(&s.Conditions, status.New(status.TypeAccepted, metav1.ConditionTrue, status.ReasonAccepted, "spec accepted", gen))
	r.setTargetReady(job, obs, outcome)
	r.setArtifactVerified(job, obs, outcome)

	if outcome.Failure != nil {
		if s.Failure != nil {
			outcome.Failure.Attempts = s.Failure.Attempts + 1
		}
		s.Failure = outcome.Failure
	}
	if c := outcome.Completion; c != nil {
		s.StartedAt = metaTime(c.StartedAt)
		s.CaptureEndedAt = metaTime(c.EndedAt)
		s.CompletedAt = metaTime(c.CompletedAt)
		s.PacketCount = &c.PacketCount
		s.SizeBytes = &c.SizeBytes
		s.SHA256 = c.SHA256
		s.ResolvedInterface = c.Interface
		artifact := c.Artifact
		artifact.Profile = artifactProfile
		s.Artifact = &artifact
		s.RetentionDeadline = metaTime(c.RetentionDeadline)
		s.Failure = nil
	}
	r.setDownloadable(job)
}

func (r *CaptureJobReconciler) setTargetReady(job *trawlv1alpha1.CaptureJob, obs capture.Observation, outcome capture.Outcome) {
	gen := job.Generation
	switch {
	case outcome.Action == capture.ActionCreateJob || obs.Job.State != capture.JobAbsent:
		status.Set(&job.Status.Conditions, status.New(status.TypeTargetReady, metav1.ConditionTrue,
			status.ReasonTargetReady, "the tap reports the target node with a fresh heartbeat", gen))
	case obs.Target.State == capture.TargetEligible || obs.Target.State == capture.TargetUnknown:
		// Nothing new was learned about the target on this pass.
	default:
		status.Set(&job.Status.Conditions, status.New(status.TypeTargetReady, metav1.ConditionFalse,
			status.ReasonTargetUnavailable, targetMessage(obs.Target.State), gen))
	}
}

func targetMessage(st capture.TargetState) string {
	switch st {
	case capture.TargetTapMissing:
		return "the referenced tap does not exist"
	case capture.TargetTapDeleting:
		return "the referenced tap is being deleted"
	case capture.TargetTapInactive:
		return "the referenced tap is not Active or Degraded for its current spec"
	default:
		return "the target node is not a target of the tap or its heartbeat is stale"
	}
}

func (r *CaptureJobReconciler) setArtifactVerified(job *trawlv1alpha1.CaptureJob, obs capture.Observation, outcome capture.Outcome) {
	gen := job.Generation
	conds := &job.Status.Conditions
	switch {
	case outcome.Completion != nil:
		status.Set(conds, status.New(status.TypeArtifactVerified, metav1.ConditionTrue,
			status.ReasonArtifactVerified, "the stored object matches its manifest", gen))
	case outcome.StorageUnavailable:
		status.Set(conds, status.New(status.TypeArtifactVerified, metav1.ConditionUnknown,
			status.ReasonStorageFailure, "artifact storage could not be reached; the capture's phase is unchanged until it can", gen))
	case obs.Artifact.State == capture.ArtifactMismatch:
		status.Set(conds, status.New(status.TypeArtifactVerified, metav1.ConditionFalse,
			status.ReasonChecksumMismatch, "the stored object does not match its manifest", gen))
	case outcome.Failure != nil && obs.Artifact.State == capture.ArtifactPresent:
		status.Set(conds, status.New(status.TypeArtifactVerified, metav1.ConditionFalse,
			status.ReasonStorageFailure, "the runner stored an object without a manifest", gen))
	case outcome.Failure != nil:
		status.Set(conds, status.New(status.TypeArtifactVerified, metav1.ConditionFalse,
			status.ReasonArtifactMissing, "no verified artifact exists for this capture", gen))
	}
}

// setDownloadable derives the Downloadable condition from everything else in
// status, using the same predicate the gateway will apply.
func (r *CaptureJobReconciler) setDownloadable(job *trawlv1alpha1.CaptureJob) {
	gen := job.Generation
	conds := &job.Status.Conditions
	switch {
	case capture.Downloadable(job, r.now()):
		status.Set(conds, status.New(status.TypeDownloadable, metav1.ConditionTrue,
			status.ReasonDownloadable, "the artifact is verified and within its retention period", gen))
	case job.Status.Phase == trawlv1alpha1.CapturePhaseCompleted:
		status.Set(conds, status.New(status.TypeDownloadable, metav1.ConditionFalse,
			status.ReasonExpired, "the artifact's retention period has ended", gen))
	case capture.IsTerminal(job.Status.Phase):
		status.Set(conds, status.New(status.TypeDownloadable, metav1.ConditionFalse,
			status.ReasonNotDownloadable, "the capture did not produce a verified artifact", gen))
	default:
		status.Set(conds, status.New(status.TypeDownloadable, metav1.ConditionFalse,
			status.ReasonPending, "the capture has not completed", gen))
	}
}

// observeTransition records the metrics a phase change carries.
func (r *CaptureJobReconciler) observeTransition(job *trawlv1alpha1.CaptureJob, from trawlv1alpha1.CapturePhase, outcome capture.Outcome) {
	if r.Metrics == nil || from == outcome.Phase {
		return
	}
	m := r.Metrics
	s := job.Status
	if from == "" {
		from = trawlv1alpha1.CapturePhasePending
	}
	m.CaptureTransitionsTotal.WithLabelValues(string(from), string(outcome.Phase)).Inc()
	rt := requestTypeLabel(job.Spec.RequestType)

	switch outcome.Phase {
	case trawlv1alpha1.CapturePhaseCapturing:
		m.CaptureRequestsTotal.WithLabelValues(rt, telemetry.RequestStarted).Inc()
		if s.StartedAt != nil && s.RequestedAt != nil {
			m.CaptureStartLatency.WithLabelValues(rt).Observe(s.StartedAt.Sub(s.RequestedAt.Time).Seconds())
		}
	case trawlv1alpha1.CapturePhaseCompleted:
		c := outcome.Completion
		m.CaptureStoreLatency.WithLabelValues(telemetry.ArtifactResultSuccess).Observe(c.CompletedAt.Sub(c.EndedAt).Seconds())
		m.CaptureSizeBytes.WithLabelValues(rt).Observe(float64(c.SizeBytes))
		m.CaptureBoundStopTotal.WithLabelValues(telemetry.BoundFor(string(c.StopReason))).Inc()
	case trawlv1alpha1.CapturePhaseFailed:
		m.CaptureRequestsTotal.WithLabelValues(rt, telemetry.RequestFailed).Inc()
		if s.CaptureEndedAt != nil {
			m.CaptureStoreLatency.WithLabelValues(telemetry.ArtifactResultFailure).Observe(r.now().Sub(s.CaptureEndedAt.Time).Seconds())
		}
	}
}

func requestTypeLabel(t trawlv1alpha1.CaptureRequestType) string {
	if t == trawlv1alpha1.CaptureRequestPolicy {
		return telemetry.RequestTypePolicy
	}
	return telemetry.RequestTypeManual
}

// reject fails a capture whose stored spec the controller will not act on.
func (r *CaptureJobReconciler) reject(ctx context.Context, job *trawlv1alpha1.CaptureJob, conditionReason string,
	failure trawlv1alpha1.FailureReason, message string,
) error {
	outcome := capture.Outcome{
		Phase: trawlv1alpha1.CapturePhaseFailed,
		Failure: &trawlv1alpha1.CaptureFailure{
			Reason:      failure,
			Message:     message,
			FailedPhase: trawlv1alpha1.CapturePhasePending,
			Attempts:    1,
		},
	}
	if job.Status.Phase != "" {
		outcome.Failure.FailedPhase = job.Status.Phase
	}
	if err := r.auditTransition(ctx, job, outcome); err != nil {
		r.markAuditUnavailable(job, err)
		if werr := r.writeStatus(ctx, job, status.ReasonAuditUnavailable); werr != nil {
			log.FromContext(ctx).Error(werr, "recording an audit failure in status")
		}
		return err
	}
	gen := job.Generation
	job.Status.ObservedGeneration = gen
	job.Status.Phase = trawlv1alpha1.CapturePhaseFailed
	job.Status.Failure = outcome.Failure
	status.Set(&job.Status.Conditions, status.New(status.TypeAccepted, metav1.ConditionFalse, conditionReason, message, gen))
	r.setDownloadable(job)
	return r.writeStatus(ctx, job, conditionReason)
}

// markAuditUnavailable says in status that a transition is waiting on the
// ledger. The phase is untouched: it has not happened yet.
func (r *CaptureJobReconciler) markAuditUnavailable(job *trawlv1alpha1.CaptureJob, cause error) {
	status.Set(&job.Status.Conditions, status.New(status.TypeAccepted, metav1.ConditionTrue,
		status.ReasonAuditUnavailable, "the transition is waiting for its audit record to commit: "+cause.Error(), job.Generation))
}

// reportUnavailable records a dependency failure and hands back the cause so
// the pass is retried with backoff.
func (r *CaptureJobReconciler) reportUnavailable(ctx context.Context, job *trawlv1alpha1.CaptureJob, doing string, cause error) error {
	job.Status.ObservedGeneration = job.Generation
	status.Set(&job.Status.Conditions, status.New(status.TypeAccepted, metav1.ConditionTrue,
		status.ReasonDependencyUnavailable, fmt.Sprintf("%s: %v", doing, cause), job.Generation))
	if err := r.writeStatus(ctx, job, status.ReasonDependencyUnavailable); err != nil {
		log.FromContext(ctx).Error(err, "recording a dependency failure in status", "while", doing)
	}
	return sanitize.Error(cause)
}

func (r *CaptureJobReconciler) writeStatus(ctx context.Context, job *trawlv1alpha1.CaptureJob, reason string) error {
	if err := r.Status().Update(ctx, job); err != nil {
		if r.Metrics != nil {
			r.Metrics.StatusUpdateFailures.WithLabelValues(kindCaptureJob, reason).Inc()
		}
		return sanitize.Error(err)
	}
	return nil
}

// deleteArtifact removes the capture's object and manifest. Both deletes are
// idempotent, so a pass that is interrupted between them finishes on the
// next one.
func (r *CaptureJobReconciler) deleteArtifact(ctx context.Context, job *trawlv1alpha1.CaptureJob) error {
	uid := string(job.UID)
	for _, key := range []string{capture.ObjectKey(job.Namespace, uid), capture.ManifestKey(job.Namespace, uid)} {
		err := r.Store.Delete(ctx, key)
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			if r.Metrics != nil {
				r.Metrics.ArtifactOperationsTotal.WithLabelValues(telemetry.ArtifactOpDelete, telemetry.ArtifactResultUnavailable).Inc()
			}
			return sanitize.Errorf("deleting artifact object: %v", err)
		}
	}
	if r.Metrics != nil {
		r.Metrics.ArtifactOperationsTotal.WithLabelValues(telemetry.ArtifactOpDelete, telemetry.ArtifactResultSuccess).Inc()
	}
	return nil
}

// finalize runs when the capture is deleted: stop the runner, remove the
// artifact, record that it was removed, and only then let the object go.
//
// The artifact is not touched until the runner's pod is gone - and the
// interface released; a runner still uploading into a key that was just
// deleted would leave an orphan. The pod, not the Job, is what is waited
// for, because it is the pod that holds the interface and the credentials.
func (r *CaptureJobReconciler) finalize(ctx context.Context, job *trawlv1alpha1.CaptureJob) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(job, captureFinalizer) {
		return ctrl.Result{}, nil
	}
	fail := func(reason string, err error) (ctrl.Result, error) {
		if r.Metrics != nil {
			r.Metrics.FinalizerFailures.WithLabelValues(kindCaptureJob, reason).Inc()
		}
		return ctrl.Result{}, sanitize.Error(err)
	}

	name, _, _ := CaptureNames(job)
	var runnerJob batchv1.Job
	err := r.Get(ctx, client.ObjectKey{Namespace: job.Namespace, Name: name}, &runnerJob)
	switch {
	case err == nil:
		if runnerJob.DeletionTimestamp.IsZero() {
			if err := r.Delete(ctx, &runnerJob, client.PropagationPolicy(metav1.DeletePropagationBackground)); err != nil &&
				!apierrors.IsNotFound(err) {
				return fail(status.ReasonDependencyUnavailable, err)
			}
		}
		return ctrl.Result{RequeueAfter: jobDeletionRequeue}, nil
	case !apierrors.IsNotFound(err):
		return fail(status.ReasonDependencyUnavailable, err)
	}
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(job.Namespace), client.MatchingLabels{jobNameLabel: name}); err != nil {
		return fail(status.ReasonDependencyUnavailable, err)
	}
	if len(pods.Items) > 0 {
		return ctrl.Result{RequeueAfter: jobDeletionRequeue}, nil
	}

	hadArtifact := job.Status.Artifact != nil
	if hadArtifact {
		if err := r.auditExpiry(ctx, job, audit.DecisionAllowed, "delete-allowed"); err != nil {
			return fail(status.ReasonAuditUnavailable, err)
		}
	}
	if err := r.deleteArtifact(ctx, job); err != nil {
		return fail(status.ReasonStorageFailure, err)
	}
	if hadArtifact {
		if err := r.auditExpiry(ctx, job, audit.DecisionSucceeded, "delete-succeeded"); err != nil {
			return fail(status.ReasonAuditUnavailable, err)
		}
	}

	controllerutil.RemoveFinalizer(job, captureFinalizer)
	if err := r.Update(ctx, job); err != nil {
		return fail(status.ReasonPending, err)
	}
	return ctrl.Result{}, nil
}

func (r *CaptureJobReconciler) auditExpiry(ctx context.Context, job *trawlv1alpha1.CaptureJob, decision, step string) error {
	if r.Audit == nil {
		return admission.ErrAuditUnavailable
	}
	return r.commit(ctx, audit.Record{
		Action:      audit.ActionArtifactExpire,
		Decision:    decision,
		Reason:      "CaptureJobDeleted",
		Message:     "the capture was deleted before its retention deadline; its artifact goes with it",
		Actor:       r.actor(),
		Resource:    resourceFor(job),
		StableKey:   audit.StableKeyForAutomatic(audit.ActionArtifactExpire, string(job.UID), step),
		InitiatedBy: job.Annotations[trawlv1alpha1.AnnotationRequester],
	})
}

func metaTime(t time.Time) *metav1.Time {
	if t.IsZero() {
		return nil
	}
	m := metav1.NewTime(t)
	return &m
}

// SetupWithManager registers the controller.
//
// There is deliberately no generation predicate on the CaptureJob watch: the
// reporter's status writes are what tell the controller a capture started
// or ended, and those never change the generation.
func (r *CaptureJobReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&trawlv1alpha1.CaptureJob{}).
		Owns(&batchv1.Job{}).
		Complete(r)
}
