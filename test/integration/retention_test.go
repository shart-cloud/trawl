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
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/audit"
	"trawl.cloud/trawl/internal/capture"
	"trawl.cloud/trawl/internal/controller"
	"trawl.cloud/trawl/internal/status"
	"trawl.cloud/trawl/internal/storage"
	"trawl.cloud/trawl/internal/telemetry"
)

// retentionHarness is a RetentionReconciler over a fake bucket and ledger, with
// a clock the test moves by hand.
type retentionHarness struct {
	r     *controller.RetentionReconciler
	store *storage.Fake
	audit *fakeCommitter
	now   time.Time
}

// at moves the harness clock and reconciles once.
func (h *retentionHarness) at(t *testing.T, when time.Time, job *trawlv1alpha1.CaptureJob) ctrl.Result {
	t.Helper()
	h.now = when
	res, err := h.r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(job)})
	if err != nil {
		t.Fatalf("Reconcile at %s: %v", when, err)
	}
	return res
}

// atFailing reconciles over a broken bucket and requires the hourly retry.
//
// A refused deletion is not returned as a reconcile error on purpose. An error
// gets controller-runtime's exponential backoff, which retries a broken bucket
// within milliseconds and then drifts to a cadence nothing has chosen; the
// requirement is a verified deletion within 24 hours of the deadline, so the
// retry is a flat hour and the failure is carried in the status and the
// metrics instead.
func (h *retentionHarness) atFailing(t *testing.T, when time.Time, job *trawlv1alpha1.CaptureJob) {
	t.Helper()
	res := h.at(t, when, job)
	if res.RequeueAfter != time.Hour {
		t.Fatalf("RequeueAfter = %v after a failed deletion, want an hourly retry", res.RequeueAfter)
	}
}

func retentionHarnessOver(t *testing.T, ns string, store *storage.Fake, ledger *fakeCommitter) *retentionHarness {
	t.Helper()
	h := &retentionHarness{store: store, audit: ledger}
	h.r = &controller.RetentionReconciler{
		Client:  Client(),
		Scheme:  Scheme(),
		Config:  captureConfig(ns),
		Store:   store,
		Audit:   ledger,
		Metrics: telemetry.NewMetrics(),
		Now:     func() time.Time { return h.now },
	}
	return h
}

// expirableCapture drives a capture all the way to Completed with its artifact
// and manifest in the bucket, then returns a retention harness sharing that
// bucket and ledger.
func expirableCapture(t *testing.T, ns, name string) (*retentionHarness, *trawlv1alpha1.CaptureJob) {
	t.Helper()
	ch, job, runner := startedCapture(t, ns, name)
	storeArtifact(t, ch.store, job, 0)
	finishRunner(t, runner, batchv1.JobComplete, "")
	reconcileCapture(t, ch.r, job)

	job = reloadCapture(t, job)
	if job.Status.Phase != trawlv1alpha1.CapturePhaseCompleted {
		t.Fatalf("setup: phase = %q, want Completed; failure=%+v", job.Status.Phase, job.Status.Failure)
	}
	if job.Status.RetentionDeadline == nil {
		t.Fatal("setup: no retention deadline on a completed capture")
	}
	h := retentionHarnessOver(t, ns, ch.store, ch.audit)
	return h, job
}

// expiryRecords returns the artifact.expire records for one capture, in the
// order they were committed.
func (c *fakeCommitter) expiryRecords(job *trawlv1alpha1.CaptureJob) []audit.Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []audit.Record
	for _, rec := range c.records {
		if rec.Action == audit.ActionArtifactExpire && rec.Resource.UID == string(job.UID) {
			out = append(out, rec)
		}
	}
	return out
}

func deadlineOf(t *testing.T, job *trawlv1alpha1.CaptureJob) time.Time {
	t.Helper()
	if job.Status.RetentionDeadline == nil {
		t.Fatal("no retention deadline")
	}
	return job.Status.RetentionDeadline.Time
}

func artifactKeys(ns string, job *trawlv1alpha1.CaptureJob) (string, string) {
	uid := string(job.UID)
	return capture.ObjectKey(ns, uid), capture.ManifestKey(ns, uid)
}

// TestRetentionWaitsAndRequeuesBeforeTheDeadline is the quiet path: nothing is
// deleted, and the controller asks to be woken no later than an hour away so a
// retention change made in the meantime is noticed.
func TestRetentionWaitsAndRequeuesBeforeTheDeadline(t *testing.T) {
	ns := NewNamespace(t)
	h, job := expirableCapture(t, ns, "waits")
	deadline := deadlineOf(t, job)
	object, manifest := artifactKeys(ns, job)

	res := h.at(t, deadline.Add(-48*time.Hour), job)

	if res.RequeueAfter != time.Hour {
		t.Errorf("RequeueAfter = %v, want 1h while the deadline is far away", res.RequeueAfter)
	}
	if h.store.ObjectCount() != 2 {
		t.Errorf("objects touched before the deadline: %d remain, want 2", h.store.ObjectCount())
	}
	if h.store.DeleteCount(object)+h.store.DeleteCount(manifest) != 0 {
		t.Error("retention deleted an artifact that had not expired")
	}
	after := reloadCapture(t, job)
	if after.Status.Phase != trawlv1alpha1.CapturePhaseCompleted {
		t.Errorf("phase = %q, want Completed before the deadline", after.Status.Phase)
	}
	if !capture.Downloadable(after, h.now) {
		t.Error("a capture inside its retention period is not downloadable")
	}
}

// TestRetentionRequeuesExactlyAtTheDeadline covers the near case of the same
// path: once the deadline is less than an hour away the wake-up is the
// remaining time, not a flat hour that would overshoot it.
func TestRetentionRequeuesExactlyAtTheDeadline(t *testing.T) {
	ns := NewNamespace(t)
	h, job := expirableCapture(t, ns, "requeues-near")
	deadline := deadlineOf(t, job)

	res := h.at(t, deadline.Add(-90*time.Second), job)

	if res.RequeueAfter != 90*time.Second {
		t.Errorf("RequeueAfter = %v, want the 90s remaining", res.RequeueAfter)
	}
}

// TestRetentionExpiresAtTheExactDeadline pins the boundary. The deadline is
// exclusive everywhere else in the system - capture.DecideDownload refuses at
// the instant itself - and retention has to agree, or there is a moment where
// the gateway refuses a download for an artifact retention still considers
// live.
func TestRetentionExpiresAtTheExactDeadline(t *testing.T) {
	ns := NewNamespace(t)
	h, job := expirableCapture(t, ns, "exact")
	deadline := deadlineOf(t, job)
	object, manifest := artifactKeys(ns, job)

	// One nanosecond before: still live.
	h.at(t, deadline.Add(-time.Nanosecond), job)
	if h.store.ObjectCount() != 2 {
		t.Fatalf("artifact removed before the deadline: %d objects remain", h.store.ObjectCount())
	}

	h.at(t, deadline, job)

	after := reloadCapture(t, job)
	if after.Status.Phase != trawlv1alpha1.CapturePhaseExpired {
		t.Errorf("phase = %q, want Expired at the deadline", after.Status.Phase)
	}
	if h.store.ObjectCount() != 0 {
		t.Errorf("%d objects survived expiry, want 0", h.store.ObjectCount())
	}
	if h.store.DeleteCount(object) == 0 || h.store.DeleteCount(manifest) == 0 {
		t.Errorf("both keys should be deleted: object=%d manifest=%d",
			h.store.DeleteCount(object), h.store.DeleteCount(manifest))
	}
	if c := condOf(after, status.TypeDownloadable); c == nil || c.Status != metav1.ConditionFalse {
		t.Errorf("Downloadable = %+v, want False", c)
	}
	if c := condOf(after, status.TypeRetentionEnforced); c == nil || c.Status != metav1.ConditionTrue {
		t.Errorf("RetentionEnforced = %+v, want True", c)
	}
}

// blockingStore fails every Delete, and records what the CaptureJob's
// Downloadable condition said at the moment the delete was attempted.
//
// The ordering is the whole point of the write-first rule, and it can only be
// observed from inside the delete: afterwards, a controller that wrote the
// condition first and one that wrote it in the same pass after a successful
// delete look identical. See principle 31 in the handoffs.
type blockingStore struct {
	storage.Store
	t              *testing.T
	job            client.ObjectKey
	err            error
	sawDeniedFirst bool
	observed       bool
}

func (s *blockingStore) Delete(ctx context.Context, key string) error {
	if !s.observed {
		s.observed = true
		var fresh trawlv1alpha1.CaptureJob
		if err := Client().Get(ctx, s.job, &fresh); err != nil {
			s.t.Fatalf("reading the capture from inside Delete: %v", err)
		}
		c := findCondition(fresh.Status.Conditions, status.TypeDownloadable)
		s.sawDeniedFirst = c != nil && c.Status == metav1.ConditionFalse
	}
	if s.err != nil {
		return s.err
	}
	return s.Store.Delete(ctx, key)
}

// TestTheArtifactIsDeniedBeforeItIsDeleted asserts the rule the whole reconciler
// is shaped around: the download is refused first, and only then are the bytes
// removed.
//
// Doing it the other way round leaves a window in which the object is gone but
// the status still advertises it, so the gateway presigns a URL for an object
// that no longer exists and the analyst gets a storage error instead of an
// expiry. The assertion runs from inside Delete because that is the only moment
// the ordering is visible.
func TestTheArtifactIsDeniedBeforeItIsDeleted(t *testing.T) {
	ns := NewNamespace(t)
	h, job := expirableCapture(t, ns, "denied-first")
	deadline := deadlineOf(t, job)

	blocking := &blockingStore{Store: h.store, t: t, job: client.ObjectKeyFromObject(job)}
	h.r.Store = blocking

	h.at(t, deadline, job)

	if !blocking.observed {
		t.Fatal("no delete was attempted, so the ordering was never exercised")
	}
	if !blocking.sawDeniedFirst {
		t.Error("the artifact was deleted while the capture still advertised it as downloadable")
	}
}

// TestRetentionFollowsAnAuthorizedShortening covers a retention admin cutting
// the period: the deadline is recomputed from the recorded completion time, not
// from when the change was made, so shortening cannot be used to extend.
func TestRetentionFollowsAnAuthorizedShortening(t *testing.T) {
	ns := NewNamespace(t)
	h, job := expirableCapture(t, ns, "shortened")
	completed := job.Status.CompletedAt.Time

	job.Spec.Retention = "1h"
	if err := Client().Update(t.Context(), job); err != nil {
		t.Fatalf("shortening retention: %v", err)
	}
	job = reloadCapture(t, job)

	// Still inside the new hour: nothing happens, but the deadline moves.
	h.at(t, completed.Add(30*time.Minute), job)
	after := reloadCapture(t, job)
	if got, want := deadlineOf(t, after), completed.Add(time.Hour); !got.Equal(want) {
		t.Errorf("deadline = %s, want %s (completedAt + the new period)", got, want)
	}
	if after.Status.Phase != trawlv1alpha1.CapturePhaseCompleted {
		t.Errorf("phase = %q, want Completed inside the shortened period", after.Status.Phase)
	}

	h.at(t, completed.Add(time.Hour), reloadCapture(t, job))

	final := reloadCapture(t, job)
	if final.Status.Phase != trawlv1alpha1.CapturePhaseExpired {
		t.Errorf("phase = %q, want Expired once the shortened deadline passed", final.Status.Phase)
	}
	if h.store.ObjectCount() != 0 {
		t.Errorf("%d objects survived a shortened retention", h.store.ObjectCount())
	}
}

// TestRetentionFollowsAnAuthorizedExtension is the other direction: an artifact
// already past its old deadline is kept once the period is extended, provided
// the extension is observed before the sweep.
func TestRetentionFollowsAnAuthorizedExtension(t *testing.T) {
	ns := NewNamespace(t)
	h, job := expirableCapture(t, ns, "extended")
	completed := job.Status.CompletedAt.Time

	job.Spec.Retention = "30d"
	if err := Client().Update(t.Context(), job); err != nil {
		t.Fatalf("extending retention: %v", err)
	}
	job = reloadCapture(t, job)

	// A moment that would have been past the original 7d deadline.
	h.at(t, completed.Add(8*24*time.Hour), job)

	after := reloadCapture(t, job)
	if after.Status.Phase != trawlv1alpha1.CapturePhaseCompleted {
		t.Errorf("phase = %q, want Completed after an extension", after.Status.Phase)
	}
	if h.store.ObjectCount() != 2 {
		t.Errorf("%d objects remain, want 2 after an extension", h.store.ObjectCount())
	}
	if got, want := deadlineOf(t, after), completed.Add(30*24*time.Hour); !got.Equal(want) {
		t.Errorf("deadline = %s, want %s", got, want)
	}
}

// TestRetentionLeavesAnUnfinishedCaptureAlone is the upload protection. A
// capture that has not completed has no verified artifact, and the runner may
// still be writing one; deleting underneath an upload in flight would race the
// writer and could remove an object the reporter is about to record.
func TestRetentionLeavesAnUnfinishedCaptureAlone(t *testing.T) {
	ns := NewNamespace(t)
	ch, job, _ := startedCapture(t, ns, "uploading")
	storeArtifact(t, ch.store, job, 0)
	h := retentionHarnessOver(t, ns, ch.store, ch.audit)

	stored := reloadCapture(t, job)
	if stored.Status.Phase == trawlv1alpha1.CapturePhaseCompleted {
		t.Fatal("setup: capture should not be complete")
	}

	res := h.at(t, time.Now().Add(365*24*time.Hour), stored)

	if h.store.ObjectCount() == 0 {
		t.Error("retention deleted the artifact of a capture that had not completed")
	}
	after := reloadCapture(t, job)
	if after.Status.Phase == trawlv1alpha1.CapturePhaseExpired {
		t.Error("an unfinished capture was expired")
	}
	if res.RequeueAfter != 0 {
		t.Errorf("RequeueAfter = %v, want 0: retention has nothing to wait for yet", res.RequeueAfter)
	}
}

// TestRetentionRetriesHourlyAfterAFailedDeletion keeps the artifact unreachable
// and the capture un-expired when the bucket refuses the delete. Reporting
// Expired here would record an expiry that did not happen.
func TestRetentionRetriesHourlyAfterAFailedDeletion(t *testing.T) {
	ns := NewNamespace(t)
	h, job := expirableCapture(t, ns, "delete-fails")
	deadline := deadlineOf(t, job)
	h.store.FailDelete(errors.New("bucket is unavailable"))

	h.atFailing(t, deadline, job)

	after := reloadCapture(t, job)
	if after.Status.Phase != trawlv1alpha1.CapturePhaseCompleted {
		t.Errorf("phase = %q, want Completed: the artifact is still there", after.Status.Phase)
	}
	if c := condOf(after, status.TypeDownloadable); c == nil || c.Status != metav1.ConditionFalse {
		t.Errorf("Downloadable = %+v, want False even though the delete failed", c)
	}
	if c := condOf(after, status.TypeRetentionEnforced); c == nil ||
		c.Status != metav1.ConditionFalse || c.Reason != status.ReasonRetentionFailed {
		t.Errorf("RetentionEnforced = %+v, want False/RetentionFailed", c)
	}
	if capture.Downloadable(after, deadline) {
		t.Error("an artifact past its deadline is still downloadable")
	}
}

// TestRetentionDoesNotReportAnExpiryTheBucketDidNotPerform is why the reconciler
// verifies absence with Head rather than trusting Delete. The fake is told to
// acknowledge deletes without performing them, which is the shape of an
// eventually-consistent or misconfigured backend.
func TestRetentionDoesNotReportAnExpiryTheBucketDidNotPerform(t *testing.T) {
	ns := NewNamespace(t)
	h, job := expirableCapture(t, ns, "swallowed")
	deadline := deadlineOf(t, job)
	h.store.SwallowDeletes(true)

	h.atFailing(t, deadline, job)

	after := reloadCapture(t, job)
	if after.Status.Phase == trawlv1alpha1.CapturePhaseExpired {
		t.Error("phase = Expired while both objects are still in the bucket")
	}
	if c := condOf(after, status.TypeRetentionEnforced); c == nil ||
		c.Status != metav1.ConditionFalse || c.Reason != status.ReasonRetentionFailed {
		t.Errorf("RetentionEnforced = %+v, want False/RetentionFailed", c)
	}
	if h.store.ObjectCount() != 2 {
		t.Fatalf("the fake did not keep the objects: %d remain", h.store.ObjectCount())
	}
}

// TestRetentionReportsHowLongAnExpiryIsOverdue is the 24-hour bound. The
// requirement is that a deletion is verified within a day of its deadline; the
// controller cannot force a broken bucket, so what it owes the operator is a
// status that says how far past the deadline it is, which is what the alert
// rule and the dashboard read.
func TestRetentionReportsHowLongAnExpiryIsOverdue(t *testing.T) {
	ns := NewNamespace(t)
	h, job := expirableCapture(t, ns, "overdue")
	deadline := deadlineOf(t, job)
	h.store.FailDelete(errors.New("bucket is unavailable"))

	h.atFailing(t, deadline, job)
	within := condOf(reloadCapture(t, job), status.TypeRetentionEnforced)
	if within == nil || within.Status != metav1.ConditionFalse {
		t.Fatalf("RetentionEnforced = %+v, want False", within)
	}
	if controller.RetentionOverdue(reloadCapture(t, job), deadline.Add(time.Hour)) {
		t.Error("an expiry one hour late should not yet be overdue")
	}

	h.atFailing(t, deadline.Add(25*time.Hour), job)

	after := reloadCapture(t, job)
	if !controller.RetentionOverdue(after, deadline.Add(25*time.Hour)) {
		t.Error("an expiry 25 hours late is past the 24-hour bound and should say so")
	}
	if c := condOf(after, status.TypeRetentionEnforced); c == nil || c.Message == "" {
		t.Errorf("RetentionEnforced carries no message saying how late it is: %+v", c)
	}
}

// TestExpiryPreservesTheCaptureRecord checks that expiry removes the evidence
// and keeps the record of it. What was captured, how big it was, when it ran
// and what it hashed to are the answers an investigation still needs after the
// packets are gone, and they are the only remaining proof of what was deleted.
func TestExpiryPreservesTheCaptureRecord(t *testing.T) {
	ns := NewNamespace(t)
	h, job := expirableCapture(t, ns, "preserves")
	deadline := deadlineOf(t, job)
	before := reloadCapture(t, job).Status

	h.at(t, deadline, job)

	after := reloadCapture(t, job).Status
	if after.Phase != trawlv1alpha1.CapturePhaseExpired {
		t.Fatalf("phase = %q, want Expired", after.Phase)
	}
	if after.SHA256 != before.SHA256 || after.SHA256 == "" {
		t.Errorf("sha256 = %q, want the recorded %q", after.SHA256, before.SHA256)
	}
	if after.SizeBytes == nil || before.SizeBytes == nil || *after.SizeBytes != *before.SizeBytes {
		t.Errorf("sizeBytes = %v, want %v", after.SizeBytes, before.SizeBytes)
	}
	if after.PacketCount == nil || before.PacketCount == nil || *after.PacketCount != *before.PacketCount {
		t.Errorf("packetCount = %v, want %v", after.PacketCount, before.PacketCount)
	}
	if after.StartedAt == nil || after.CaptureEndedAt == nil || after.CompletedAt == nil {
		t.Errorf("timestamps lost: started=%v ended=%v completed=%v",
			after.StartedAt, after.CaptureEndedAt, after.CompletedAt)
	}
	if after.RetentionDeadline == nil {
		t.Error("retention deadline lost, so nothing records when the artifact was due to go")
	}
}

// TestExpiryIsAuditedAsIntentThenOutcome mirrors the rest of the system: the
// intent is durable before the irreversible act, so a delete that happens and
// then loses its acknowledgement is still visible in the ledger.
func TestExpiryIsAuditedAsIntentThenOutcome(t *testing.T) {
	ns := NewNamespace(t)
	h, job := expirableCapture(t, ns, "audited")
	deadline := deadlineOf(t, job)

	h.at(t, deadline, job)

	records := h.audit.expiryRecords(job)
	if len(records) != 2 {
		t.Fatalf("got %d artifact.expire records, want 2 (intent then outcome): %+v", len(records), records)
	}
	if records[0].Decision != audit.DecisionAllowed {
		t.Errorf("first record decision = %q, want %q", records[0].Decision, audit.DecisionAllowed)
	}
	if records[1].Decision != audit.DecisionSucceeded {
		t.Errorf("second record decision = %q, want %q", records[1].Decision, audit.DecisionSucceeded)
	}
}

// TestExpiryIsNotRepeatedOnceEnforced keeps the reconciler convergent: an
// already-Expired capture is left entirely alone, with no further deletes and
// no further ledger records.
func TestExpiryIsNotRepeatedOnceEnforced(t *testing.T) {
	ns := NewNamespace(t)
	h, job := expirableCapture(t, ns, "converges")
	deadline := deadlineOf(t, job)
	object, _ := artifactKeys(ns, job)

	h.at(t, deadline, job)
	deletes := h.store.DeleteCount(object)
	records := len(h.audit.expiryRecords(job))

	res := h.at(t, deadline.Add(time.Hour), reloadCapture(t, job))

	if got := h.store.DeleteCount(object); got != deletes {
		t.Errorf("delete attempted again on an expired capture: %d, want %d", got, deletes)
	}
	if got := len(h.audit.expiryRecords(job)); got != records {
		t.Errorf("expiry audited again: %d records, want %d", got, records)
	}
	if res.RequeueAfter != 0 {
		t.Errorf("RequeueAfter = %v, want 0: an expired capture needs no further passes", res.RequeueAfter)
	}
}

// TestRetentionSweepsAFailedCapturesLeftovers covers the other source of
// orphaned bytes: a capture that failed after its runner had already uploaded
// something. Nothing will ever serve those objects, and no deadline covers
// them, so retention removes them on sight.
func TestRetentionSweepsAFailedCapturesLeftovers(t *testing.T) {
	ns := NewNamespace(t)
	ch, job, runner := startedCapture(t, ns, "failed-leftovers")
	finishRunner(t, runner, batchv1.JobFailed, "BackoffLimitExceeded")
	reconcileCapture(t, ch.r, job)

	// The objects are seeded after the capture controller has already run its
	// own cleanup, which is what this sweep exists to backstop: the case where
	// a runner uploaded something the controller never saw and so never
	// removed.
	storeArtifact(t, ch.store, job, 0)
	if ch.store.ObjectCount() == 0 {
		t.Fatal("setup: no orphaned objects to sweep")
	}

	failed := reloadCapture(t, job)
	if failed.Status.Phase != trawlv1alpha1.CapturePhaseFailed {
		t.Fatalf("setup: phase = %q, want Failed", failed.Status.Phase)
	}

	h := retentionHarnessOver(t, ns, ch.store, ch.audit)
	h.at(t, time.Now(), failed)

	if h.store.ObjectCount() != 0 {
		t.Errorf("%d objects left behind by a failed capture, want 0", h.store.ObjectCount())
	}
}
