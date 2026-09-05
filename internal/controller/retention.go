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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/audit"
	"trawl.cloud/trawl/internal/capture"
	"trawl.cloud/trawl/internal/config"
	"trawl.cloud/trawl/internal/sanitize"
	"trawl.cloud/trawl/internal/status"
	"trawl.cloud/trawl/internal/storage"
	"trawl.cloud/trawl/internal/telemetry"
)

const (
	// retentionSweepInterval is both the longest a capture waits between
	// retention passes and the retry interval after a failed deletion.
	//
	// It bounds how stale a deadline can be: a retention change is authorized
	// through the API, so the deadline can move at any time, and nothing else
	// wakes this controller for a capture that is simply sitting there.
	retentionSweepInterval = time.Hour

	// retentionOverdueAfter is how long past its deadline an artifact may go
	// without a verified deletion before the expiry counts as overdue. The
	// alert rule and the capture-management dashboard read the same bound.
	retentionOverdueAfter = 24 * time.Hour

	// expireStep names the retention step in the audit ledger's stable key, so
	// the intent and the outcome of one capture's expiry collapse onto one
	// entry per decision rather than accumulating on every retry.
	expireStep = "artifact:expire"
)

// RetentionReconciler deletes a capture's artifact once its retention deadline
// passes, and records that it did.
//
// It is a second controller over CaptureJob rather than part of
// CaptureJobReconciler because the two answer different questions on different
// clocks. The capture controller converges a request towards a stored artifact
// and is driven by the runner Job and the reporter; this one does nothing at
// all until a deadline that may be days away, and its only inputs are the
// clock and the retention field. Splitting them keeps a capture's progress
// from being blocked by a bucket that will not accept a delete, and keeps the
// deletion path small enough to read in one sitting.
type RetentionReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Config *config.Config
	// Store is the artifact bucket. Retention only ever deletes from it and
	// verifies those deletions.
	Store storage.Store
	// Audit commits the expiry record. The intent is durable before the
	// artifact is touched (ADR-0003), because the deletion cannot be undone.
	Audit   audit.Committer
	Metrics *telemetry.Metrics
	// Now is the clock; tests fix it.
	Now func() time.Time
}

// +kubebuilder:rbac:groups=trawl.cloud,resources=capturejobs,verbs=get;list;watch
// +kubebuilder:rbac:groups=trawl.cloud,resources=capturejobs/status,verbs=get;update;patch

func (r *RetentionReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// RetentionOverdue reports whether a capture's artifact is past the bound for
// having its deletion verified.
//
// It is exported because the same question is asked outside the reconciler:
// the alert rule and the dashboard describe an artifact that should be gone
// and demonstrably is not, and deriving that from one place stops the two
// definitions drifting apart.
func RetentionOverdue(job *trawlv1alpha1.CaptureJob, now time.Time) bool {
	if job == nil || job.Status.RetentionDeadline == nil {
		return false
	}
	if job.Status.Phase == trawlv1alpha1.CapturePhaseExpired {
		return false
	}
	return now.Sub(job.Status.RetentionDeadline.Time) > retentionOverdueAfter
}

// Reconcile enforces retention for one CaptureJob.
func (r *RetentionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	start := time.Now()
	result := telemetry.ReconcileSuccess
	defer func() {
		if r.Metrics != nil {
			r.Metrics.ReconcileTotal.WithLabelValues(telemetry.ControllerRetention, result).Inc()
			r.Metrics.ReconcileDurationSeconds.
				WithLabelValues(telemetry.ControllerRetention).
				Observe(time.Since(start).Seconds())
		}
	}()

	var job trawlv1alpha1.CaptureJob
	if err := r.Get(ctx, req.NamespacedName, &job); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		result = reconcileOutcome(err)
		return ctrl.Result{}, err
	}

	switch job.Status.Phase {
	case trawlv1alpha1.CapturePhaseExpired:
		// Terminal. The artifact is gone and the record of it stays.
		return ctrl.Result{}, nil

	case trawlv1alpha1.CapturePhaseFailed:
		// A capture that failed after its runner had already uploaded
		// something leaves objects no deadline covers and nothing will ever
		// serve. The capture controller cleans up on the way past; this is the
		// backstop for when that did not happen.
		return r.sweepOrphans(ctx, &job), nil

	case trawlv1alpha1.CapturePhaseCompleted:
		// The only phase with an artifact worth a deadline.

	default:
		// Pending, Capturing, Storing. There is no verified artifact yet, and
		// the runner may still be writing one: deleting here would race the
		// upload and could remove an object the reporter is about to record.
		// Nothing to wait for either - the capture controller will drive the
		// phase, and this controller watches the same object.
		return ctrl.Result{}, nil
	}

	deadline, err := r.observedDeadline(ctx, &job)
	if err != nil {
		result = reconcileOutcome(err)
		return ctrl.Result{}, err
	}

	now := r.now()
	if now.Before(deadline) {
		// The deadline is exclusive: at the instant itself the artifact is
		// already gone as far as every reader is concerned, so the wait ends
		// strictly before it.
		return ctrl.Result{RequeueAfter: nextSweep(deadline.Sub(now))}, nil
	}

	return r.expire(ctx, &job, deadline, now, &result)
}

// observedDeadline recomputes the retention deadline from the recorded
// completion time and the current spec, and persists it if an authorized
// change has moved it.
//
// It is always completedAt plus the period, never "now plus the period": that
// is what makes a shortening a shortening. Recomputing from the time the
// change was made would let a retention admin extend an artifact's life
// indefinitely by repeatedly shortening it.
func (r *RetentionReconciler) observedDeadline(ctx context.Context, job *trawlv1alpha1.CaptureJob) (time.Time, error) {
	if job.Status.CompletedAt == nil {
		return time.Time{}, errors.New("a completed capture has no completion time")
	}
	want, err := capture.RetentionDeadline(job.Status.CompletedAt.Time, job.Spec.Retention)
	if err != nil {
		return time.Time{}, sanitize.Error(err)
	}
	want = want.UTC().Truncate(time.Second)

	if job.Status.RetentionDeadline != nil && job.Status.RetentionDeadline.Time.Equal(want) {
		return want, nil
	}
	job.Status.RetentionDeadline = &metav1.Time{Time: want}
	if err := r.Status().Update(ctx, job); err != nil {
		return time.Time{}, err
	}
	return want, nil
}

// expire performs the irreversible half: refuse the download, record the
// intent, delete both keys, verify they are gone, then record the outcome.
//
// The order is the point. Refusing first means there is no window in which the
// object has been deleted but the status still advertises it, which is what
// would turn an expiry into a storage error in the analyst's hands. Recording
// the intent before the delete means an expiry that happens and then loses its
// acknowledgement is still in the ledger; the reverse would lose it entirely.
func (r *RetentionReconciler) expire(
	ctx context.Context, job *trawlv1alpha1.CaptureJob, deadline, now time.Time, result *string,
) (ctrl.Result, error) {
	if err := r.denyDownload(ctx, job, deadline); err != nil {
		*result = reconcileOutcome(err)
		return ctrl.Result{}, err
	}

	if err := r.auditExpiry(ctx, job, audit.DecisionAllowed, "the retention deadline passed"); err != nil {
		*result = reconcileOutcome(err)
		return ctrl.Result{}, err
	}

	if err := r.removeArtifact(ctx, job); err != nil {
		// The bytes are still there. Saying Expired here would record an
		// expiry that did not happen, and the artifact would stop being
		// mentioned by anything that could later prove it still exists.
		*result = telemetry.ReconcileError
		if failErr := r.markRetentionFailed(ctx, job, deadline, now, err); failErr != nil {
			return ctrl.Result{}, failErr
		}
		if auditErr := r.auditExpiry(ctx, job, audit.DecisionFailed, sanitize.Error(err).Error()); auditErr != nil {
			return ctrl.Result{}, auditErr
		}
		return ctrl.Result{RequeueAfter: retentionSweepInterval}, nil
	}

	if err := r.auditExpiry(ctx, job, audit.DecisionSucceeded, "the artifact was deleted and its absence verified"); err != nil {
		*result = reconcileOutcome(err)
		return ctrl.Result{}, err
	}

	job.Status.Phase = trawlv1alpha1.CapturePhaseExpired
	status.Set(&job.Status.Conditions, status.New(status.TypeRetentionEnforced, metav1.ConditionTrue,
		status.ReasonRetentionEnforced, "the artifact was deleted and its absence verified", job.Generation))
	status.Set(&job.Status.Conditions, status.New(status.TypeDownloadable, metav1.ConditionFalse,
		status.ReasonExpired, "the retention deadline passed and the artifact was deleted", job.Generation))
	if err := r.Status().Update(ctx, job); err != nil {
		*result = reconcileOutcome(err)
		return ctrl.Result{}, err
	}

	if r.Metrics != nil {
		r.Metrics.ArtifactExpiryLagSeconds.Observe(now.Sub(deadline).Seconds())
	}
	return ctrl.Result{}, nil
}

// denyDownload writes Downloadable=False before anything is deleted.
//
// Written as its own pass so that a failure to persist it stops the expiry:
// deleting an artifact the status still advertises is the one ordering this
// controller must never produce.
func (r *RetentionReconciler) denyDownload(ctx context.Context, job *trawlv1alpha1.CaptureJob, deadline time.Time) error {
	existing := status.Get(job.Status.Conditions, status.TypeDownloadable)
	if existing != nil && existing.Status == metav1.ConditionFalse &&
		existing.Reason == status.ReasonExpired && existing.ObservedGeneration == job.Generation {
		// Already refused on an earlier pass; this is a retry after a failed
		// deletion, and rewriting the condition would move its transition time
		// for no reason.
		return nil
	}
	status.Set(&job.Status.Conditions, status.New(status.TypeDownloadable, metav1.ConditionFalse,
		status.ReasonExpired, "the retention deadline passed at "+deadline.UTC().Format(time.RFC3339),
		job.Generation))
	return r.Status().Update(ctx, job)
}

// removeArtifact deletes both keys and proves they are gone.
//
// Delete reporting success is not proof: a backend can acknowledge a removal
// it has not performed, and an artifact that survives a "successful" expiry is
// exactly the failure retention exists to prevent. Head is the only statement
// about the object that comes from the store rather than from the request.
func (r *RetentionReconciler) removeArtifact(ctx context.Context, job *trawlv1alpha1.CaptureJob) error {
	if r.Store == nil {
		return errors.New("no artifact store configured")
	}
	uid := string(job.UID)
	for _, key := range []string{
		capture.ObjectKey(job.Namespace, uid),
		capture.ManifestKey(job.Namespace, uid),
	} {
		if err := r.Store.Delete(ctx, key); err != nil {
			r.observeDelete(telemetry.ArtifactResultFailure)
			return fmt.Errorf("deleting the artifact: %w", sanitize.Error(err))
		}
		if _, err := r.Store.Head(ctx, key); !errors.Is(err, storage.ErrNotFound) {
			r.observeDelete(telemetry.ArtifactResultFailure)
			if err != nil {
				return fmt.Errorf("verifying the deletion: %w", sanitize.Error(err))
			}
			return errors.New("the object is still present after a successful delete")
		}
		r.observeDelete(telemetry.ArtifactResultSuccess)
	}
	return nil
}

func (r *RetentionReconciler) observeDelete(result string) {
	if r.Metrics != nil {
		r.Metrics.ArtifactOperationsTotal.WithLabelValues(telemetry.ArtifactOpDelete, result).Inc()
	}
}

// markRetentionFailed records a deletion that did not happen, keeping the
// capture Completed-but-not-downloadable rather than pretending it expired.
func (r *RetentionReconciler) markRetentionFailed(
	ctx context.Context, job *trawlv1alpha1.CaptureJob, deadline, now time.Time, cause error,
) error {
	late := now.Sub(deadline).Truncate(time.Second)
	msg := fmt.Sprintf("the artifact is %s past its deadline and has not been deleted: %v",
		late, sanitize.Error(cause))
	if RetentionOverdue(job, now) {
		msg = fmt.Sprintf("the artifact is %s past its deadline, beyond the %s bound, and has not been deleted: %v",
			late, retentionOverdueAfter, sanitize.Error(cause))
	}
	status.Set(&job.Status.Conditions, status.New(status.TypeRetentionEnforced, metav1.ConditionFalse,
		status.ReasonRetentionFailed, msg, job.Generation))
	return r.Status().Update(ctx, job)
}

// sweepOrphans removes objects left by a capture that failed.
//
// No deadline covers them and nothing will ever serve them, so there is
// nothing to wait for and no download to refuse first. A failed capture that
// never uploaded anything makes this a pair of deletes of absent keys, which
// the store treats as success.
func (r *RetentionReconciler) sweepOrphans(ctx context.Context, job *trawlv1alpha1.CaptureJob) ctrl.Result {
	if err := r.removeArtifact(ctx, job); err != nil {
		// Retried on the chosen cadence rather than controller-runtime's
		// backoff, for the same reason a failed expiry is.
		return ctrl.Result{RequeueAfter: retentionSweepInterval}
	}
	return ctrl.Result{}
}

// auditExpiry commits one expiry record. The stable key carries the decision so
// the intent and the outcome are separate entries that each collapse on retry.
func (r *RetentionReconciler) auditExpiry(
	ctx context.Context, job *trawlv1alpha1.CaptureJob, decision, message string,
) error {
	if r.Audit == nil {
		return errors.New("no audit ledger configured")
	}
	rec := audit.Record{
		Action:      audit.ActionArtifactExpire,
		Decision:    decision,
		Reason:      status.ReasonExpired,
		Message:     message,
		Actor:       r.actor(),
		Resource:    resourceFor(job),
		StableKey:   audit.StableKeyForAutomatic(audit.ActionArtifactExpire, string(job.UID), expireStep+":"+decision),
		InitiatedBy: job.Annotations[trawlv1alpha1.AnnotationRequester],
	}
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
		return fmt.Errorf("committing the expiry record: %w", sanitize.Error(err))
	}
	return nil
}

func (r *RetentionReconciler) actor() audit.Actor {
	return audit.Actor{Username: "system:serviceaccount:" + r.Config.SystemNamespace + ":trawl-controller-manager"}
}

// nextSweep caps how long retention will sleep. A deadline further away than
// the interval is still revisited hourly, because the spec field it derives
// from can be changed while this controller is asleep.
func nextSweep(until time.Duration) time.Duration {
	if until > retentionSweepInterval {
		return retentionSweepInterval
	}
	return until
}

// SetupWithManager registers the controller.
//
// It needs an explicit name because CaptureJobReconciler already owns the
// default one derived from the watched type, and controller-runtime refuses
// two controllers with the same name.
func (r *RetentionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("capturejob-retention").
		For(&trawlv1alpha1.CaptureJob{}).
		Complete(r)
}
