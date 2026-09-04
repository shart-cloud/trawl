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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/audit"
	"trawl.cloud/trawl/internal/capture"
	"trawl.cloud/trawl/internal/capture/reporter"
	"trawl.cloud/trawl/internal/config"
	"trawl.cloud/trawl/internal/controller"
	"trawl.cloud/trawl/internal/status"
	"trawl.cloud/trawl/internal/storage"
	"trawl.cloud/trawl/internal/telemetry"
)

// The CaptureJob controller is exercised against a real apiserver for the
// same reasons the NetworkTap one is, plus one of its own: the reporter
// writes status with server-side apply under a different field manager, and
// whether those fields survive the controller's own writes is apiserver
// behaviour that no fake models.

const captureTestNode = "talos-sensor-01"

// fakeCommitter is an audit ledger that can be switched off. It counts
// commits by stable key so a test can say "exactly once".
type fakeCommitter struct {
	mu      sync.Mutex
	fail    error
	records []audit.Record
}

func (c *fakeCommitter) Commit(_ context.Context, rec audit.Record) (audit.CommitResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail != nil {
		return audit.CommitResult{Result: audit.ResultUnavailable}, c.fail
	}
	c.records = append(c.records, rec)
	return audit.CommitResult{Result: audit.ResultSuccess, LedgerKey: rec.StableKey, CommittedAt: time.Now()}, nil
}

func (c *fakeCommitter) setFailure(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fail = err
}

func (c *fakeCommitter) count(action string, job *trawlv1alpha1.CaptureJob, step string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	want := audit.StableKeyForAutomatic(action, string(job.UID), step)
	n := 0
	for _, r := range c.records {
		if r.Action == action && r.StableKey == want {
			n++
		}
	}
	return n
}

// transitions counts how often the transition into phase was audited.
func transitions(h *captureHarness, job *trawlv1alpha1.CaptureJob, phase trawlv1alpha1.CapturePhase) int {
	return h.audit.count(audit.ActionCaptureJobTransition, job, capture.TransitionStep(phase))
}

func condOf(job *trawlv1alpha1.CaptureJob, typ string) *metav1.Condition {
	return findCondition(job.Status.Conditions, typ)
}

func (c *fakeCommitter) last() audit.Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.records[len(c.records)-1]
}

// headFailingStore answers every Head with a transport error, which is the
// one storage failure the Fake cannot produce itself.
type headFailingStore struct {
	storage.Store
}

func (headFailingStore) Head(context.Context, string) (storage.ObjectInfo, error) {
	return storage.ObjectInfo{}, errors.New("dial tcp: connection refused")
}

type captureHarness struct {
	r     *controller.CaptureJobReconciler
	store *storage.Fake
	audit *fakeCommitter
}

// captureConfig is the installation the capture tests reconcile against.
//
// Shared with the gateway's end-to-end test, which drives the same reconciler
// against a real object store rather than the fake.
func captureConfig(namespace string) *config.Config {
	return &config.Config{
		ClusterID:       "homelab",
		SystemNamespace: namespace,
		Artifacts: config.BucketConfig{
			Endpoint: "minio.example:9000", Bucket: "trawl-artifacts", Region: "us-east-1",
		},
		Capture: config.CaptureConfig{
			CredentialsSecret: "trawl-artifact-credentials",
			StartupBudget:     config.Duration(5 * time.Minute),
			UploadBudget:      config.Duration(15 * time.Minute),
			RunnerResources: config.ResourceRequirements{
				RequestsCPU: "100m", RequestsMemory: "128Mi", LimitsCPU: "1", LimitsMemory: "512Mi",
			},
			ReporterResources: config.ResourceRequirements{
				RequestsCPU: "10m", RequestsMemory: "32Mi", LimitsCPU: "100m", LimitsMemory: "64Mi",
			},
		},
		Images: config.ImageConfig{
			Suricata:        "ghcr.io/t/s@sha256:" + strings.Repeat("a", 64),
			Zeek:            "ghcr.io/t/z@sha256:" + strings.Repeat("b", 64),
			SensorAgent:     "ghcr.io/t/a@sha256:" + strings.Repeat("c", 64),
			CaptureRunner:   "ghcr.io/t/r@sha256:" + strings.Repeat("d", 64),
			CaptureReporter: "ghcr.io/t/p@sha256:" + strings.Repeat("f", 64),
			ContentInit:     "ghcr.io/t/i@sha256:" + strings.Repeat("e", 64),
		},
	}
}

// captureReconcilerWith builds the reconciler over a caller-chosen store, so a
// test can supply MinIO where the fake will not do.
func captureReconcilerWith(
	t *testing.T, namespace string, store storage.Store, ledger audit.Committer,
) *controller.CaptureJobReconciler {
	t.Helper()
	cfg := captureConfig(namespace)
	return &controller.CaptureJobReconciler{
		Client:   Client(),
		Scheme:   Scheme(),
		Config:   cfg,
		Renderer: &controller.CaptureRenderer{Config: cfg},
		Store:    store,
		Audit:    ledger,
		Metrics:  telemetry.NewMetrics(),
	}
}

func captureReconcilerFor(t *testing.T, namespace string) *captureHarness {
	t.Helper()
	store := storage.NewFake()
	committer := &fakeCommitter{}
	return &captureHarness{
		r:     captureReconcilerWith(t, namespace, store, committer),
		store: store,
		audit: committer,
	}
}

func reconcileCapture(t *testing.T, r *controller.CaptureJobReconciler, job *trawlv1alpha1.CaptureJob) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(job)})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	return res
}

func reloadCapture(t *testing.T, job *trawlv1alpha1.CaptureJob) *trawlv1alpha1.CaptureJob {
	t.Helper()
	var fresh trawlv1alpha1.CaptureJob
	if err := Client().Get(t.Context(), client.ObjectKeyFromObject(job), &fresh); err != nil {
		t.Fatalf("reloading capture: %v", err)
	}
	return &fresh
}

// activeTap creates the tap a manualCapture refers to and reports the target
// node healthy on it, the way the tap controller would after a sensor
// heartbeat.
func activeTap(t *testing.T, ns string, heartbeat time.Time) *trawlv1alpha1.NetworkTap {
	t.Helper()
	tap := mirrorTap(ns, "north-south-mirror")
	if err := Client().Create(t.Context(), tap); err != nil {
		t.Fatalf("creating tap: %v", err)
	}
	stored := reload(t, tap)
	stored.Status.ObservedGeneration = stored.Generation
	stored.Status.Phase = trawlv1alpha1.TapPhaseActive
	stored.Status.Targets = []trawlv1alpha1.TargetStatus{{
		NodeName:      captureTestNode,
		Interface:     "enp5s0",
		HeartbeatTime: metav1.NewTime(heartbeat),
		Analyzers:     []trawlv1alpha1.AnalyzerStatus{{Name: trawlv1alpha1.AnalyzerSuricata, Healthy: true}},
	}}
	status.Set(&stored.Status.Conditions, status.New(status.TypeAccepted, metav1.ConditionTrue,
		status.ReasonAccepted, "spec accepted", stored.Generation))
	if err := Client().Status().Update(t.Context(), stored); err != nil {
		t.Fatalf("seeding tap status: %v", err)
	}
	return reload(t, tap)
}

func createCapture(t *testing.T, ns, name string) *trawlv1alpha1.CaptureJob {
	t.Helper()
	job := manualCapture(ns, name)
	if err := Client().Create(t.Context(), job); err != nil {
		t.Fatalf("creating capture: %v", err)
	}
	return reloadCapture(t, job)
}

// startedCapture drives a capture to the point where its runner Job exists.
func startedCapture(t *testing.T, ns, name string) (*captureHarness, *trawlv1alpha1.CaptureJob, *batchv1.Job) {
	t.Helper()
	activeTap(t, ns, time.Now())
	job := createCapture(t, ns, name)
	h := captureReconcilerFor(t, ns)
	reconcileCapture(t, h.r, job)
	job = reloadCapture(t, job)
	runner := runnerJobOf(t, job)
	return h, job, runner
}

func runnerJobOf(t *testing.T, job *trawlv1alpha1.CaptureJob) *batchv1.Job {
	t.Helper()
	name, _, _ := controller.CaptureNames(job)
	var runner batchv1.Job
	if err := Client().Get(t.Context(), client.ObjectKey{Namespace: job.Namespace, Name: name}, &runner); err != nil {
		t.Fatalf("reading the runner Job: %v", err)
	}
	return &runner
}

func finishRunner(t *testing.T, runner *batchv1.Job, condType batchv1.JobConditionType, reason string) {
	t.Helper()
	var fresh batchv1.Job
	if err := Client().Get(t.Context(), client.ObjectKeyFromObject(runner), &fresh); err != nil {
		t.Fatalf("reloading Job: %v", err)
	}
	now := metav1.Now()
	// The apiserver requires the interim condition before the terminal one,
	// as the Job controller itself sets them.
	gate := batchv1.JobSuccessCriteriaMet
	if condType == batchv1.JobFailed {
		gate = batchv1.JobFailureTarget
	}
	fresh.Status.Conditions = append(fresh.Status.Conditions,
		batchv1.JobCondition{Type: gate, Status: corev1.ConditionTrue, Reason: reason, LastTransitionTime: now},
		batchv1.JobCondition{Type: condType, Status: corev1.ConditionTrue, Reason: reason, LastTransitionTime: now},
	)
	if condType == batchv1.JobComplete {
		fresh.Status.Succeeded = 1
		fresh.Status.CompletionTime = &now
	} else {
		fresh.Status.Failed = 1
	}
	fresh.Status.StartTime = &now
	if err := Client().Status().Update(t.Context(), &fresh); err != nil {
		t.Fatalf("finishing Job: %v", err)
	}
}

// applyReporterPatch writes status the way the reporter sidecar does: a
// server-side apply under its own field manager.
func applyReporterPatch(t *testing.T, job *trawlv1alpha1.CaptureJob, p reporter.Patch) {
	t.Helper()
	ac, err := p.ApplyConfiguration(job.Namespace, job.Name)
	if err != nil {
		t.Fatalf("rendering reporter patch: %v", err)
	}
	err = Client().Status().Apply(t.Context(), ac, client.FieldOwner(reporter.FieldOwner), client.ForceOwnership)
	if err != nil {
		t.Fatalf("applying reporter patch: %v", err)
	}
}

// captureArtifactBody stands in for a pcapng. The controller never parses it -
// it verifies size and checksum - and neither does the gateway.
const captureArtifactBody = "not really a pcapng but the controller does not read it"

// storeArtifact writes a verifiable object and manifest for the capture.
// sizeSkew makes the manifest disagree with the object.
func storeArtifact(t *testing.T, store storage.Store, job *trawlv1alpha1.CaptureJob, sizeSkew int64) {
	t.Helper()
	body := []byte(captureArtifactBody)
	sum := sha256.Sum256(body)
	hexSum := hex.EncodeToString(sum[:])
	uid := string(job.UID)
	now := time.Now().UTC().Truncate(time.Second)
	m := capture.Manifest{
		SchemaVersion:     capture.ManifestSchemaVersion,
		CaptureJobUID:     uid,
		Namespace:         job.Namespace,
		Name:              job.Name,
		Interface:         "enp5s0",
		Filter:            job.Spec.Filter,
		RequestedDuration: job.Spec.Duration,
		RequestedMaxSize:  job.Spec.MaxSize.Value(),
		StartedAt:         now.Add(-2 * time.Minute),
		EndedAt:           now.Add(-time.Minute),
		StopReason:        trawlv1alpha1.CaptureStopDuration,
		PacketCount:       17,
		SizeBytes:         int64(len(body)) + sizeSkew,
		SHA256:            hexSum,
	}
	raw, err := m.Marshal()
	if err != nil {
		t.Fatalf("marshalling manifest: %v", err)
	}
	ctx := t.Context()
	_, err = store.Put(ctx, capture.ObjectKey(job.Namespace, uid), body, storage.PutOptions{
		IfNotExists: true,
		Metadata:    map[string]string{capture.MetadataSHA256: hexSum, capture.MetadataCaptureJobUID: uid},
	})
	if err != nil {
		t.Fatalf("storing object: %v", err)
	}
	_, err = store.Put(ctx, capture.ManifestKey(job.Namespace, uid), raw, storage.PutOptions{IfNotExists: true})
	if err != nil {
		t.Fatalf("storing manifest: %v", err)
	}
}

func TestCaptureWaitsWhileTheTargetIsNotReady(t *testing.T) {
	// A tap that has not reported the node is not yet a reason to fail: the
	// sensor may be seconds from its first heartbeat. The capture waits,
	// says why, and asks to be looked at again.
	ns := NewNamespace(t)
	tap := mirrorTap(ns, "north-south-mirror")
	if err := Client().Create(t.Context(), tap); err != nil {
		t.Fatalf("creating tap: %v", err)
	}
	job := createCapture(t, ns, "waiting")
	h := captureReconcilerFor(t, ns)

	res := reconcileCapture(t, h.r, job)
	if res.RequeueAfter <= 0 {
		t.Errorf("RequeueAfter = %v, want > 0 while waiting for the target", res.RequeueAfter)
	}
	after := reloadCapture(t, job)
	if after.Status.Phase != trawlv1alpha1.CapturePhasePending {
		t.Errorf("phase = %q, want Pending", after.Status.Phase)
	}
	if c := condOf(after, status.TypeTargetReady); c == nil || c.Status != metav1.ConditionFalse {
		t.Errorf("TargetReady = %+v, want False", c)
	}
	name, _, _ := controller.CaptureNames(after)
	var runner batchv1.Job
	if err := Client().Get(t.Context(), client.ObjectKey{Namespace: ns, Name: name}, &runner); !apierrors.IsNotFound(err) {
		t.Errorf("a runner Job exists for a capture whose target is not ready (err=%v)", err)
	}
	if got := transitions(h, job, trawlv1alpha1.CapturePhasePending); got != 1 {
		t.Errorf("Pending transition audited %d times, want 1", got)
	}
}

func TestCaptureCreatesARunnerOnAnEligibleTarget(t *testing.T) {
	ns := NewNamespace(t)
	h, job, runner := startedCapture(t, ns, "eligible")

	if owner := metav1.GetControllerOf(runner); owner == nil || owner.UID != job.UID {
		t.Errorf("runner Job controller owner = %+v, want the CaptureJob", owner)
	}
	if runner.Spec.Template.Spec.NodeSelector["kubernetes.io/hostname"] != captureTestNode {
		t.Errorf("runner is not pinned to %s: %v", captureTestNode, runner.Spec.Template.Spec.NodeSelector)
	}
	if job.Status.RunnerJobRef == nil || job.Status.RunnerJobRef.Name != runner.Name {
		t.Errorf("status.runnerJobRef = %+v, want %s", job.Status.RunnerJobRef, runner.Name)
	}
	if job.Status.ResolvedTapUID == "" {
		t.Error("status.resolvedTapUID is empty")
	}
	if job.Status.Phase != trawlv1alpha1.CapturePhasePending {
		t.Errorf("phase = %q, want Pending until the reporter says otherwise", job.Status.Phase)
	}
	if c := condOf(job, status.TypeTargetReady); c == nil || c.Status != metav1.ConditionTrue {
		t.Errorf("TargetReady = %+v, want True", c)
	}
	if c := condOf(job, status.TypeDownloadable); c == nil || c.Status != metav1.ConditionFalse {
		t.Errorf("Downloadable = %+v, want False", c)
	}

	_, saName, roleName := controller.CaptureNames(job)
	var role rbacv1.Role
	if err := Client().Get(t.Context(), client.ObjectKey{Namespace: ns, Name: roleName}, &role); err != nil {
		t.Fatalf("reading the status Role: %v", err)
	}
	if len(role.Rules) != 1 || len(role.Rules[0].ResourceNames) != 1 || role.Rules[0].ResourceNames[0] != job.Name {
		t.Errorf("status Role is not scoped to %s: %+v", job.Name, role.Rules)
	}
	var sa corev1.ServiceAccount
	if err := Client().Get(t.Context(), client.ObjectKey{Namespace: ns, Name: saName}, &sa); err != nil {
		t.Fatalf("reading the ServiceAccount: %v", err)
	}
	if runner.Spec.Template.Spec.ServiceAccountName != saName {
		t.Errorf("runner uses ServiceAccount %q, want %q", runner.Spec.Template.Spec.ServiceAccountName, saName)
	}
	if rec := h.audit.last(); rec.Actor.Username != "system:serviceaccount:"+ns+":trawl-controller-manager" {
		t.Errorf("audit actor = %q, want the controller's identity", rec.Actor.Username)
	}
}

func TestCaptureReconcileIsIdempotent(t *testing.T) {
	// A second pass over unchanged state writes nothing. The resource
	// versions are the proof: any write, even one that changed no field,
	// would bump them.
	ns := NewNamespace(t)
	h, job, runner := startedCapture(t, ns, "idempotent")

	reconcileCapture(t, h.r, job)

	if after := reloadCapture(t, job); after.ResourceVersion != job.ResourceVersion {
		t.Errorf("CaptureJob resourceVersion changed %s -> %s on an unchanged second pass",
			job.ResourceVersion, after.ResourceVersion)
	}
	if again := runnerJobOf(t, job); again.ResourceVersion != runner.ResourceVersion || again.UID != runner.UID {
		t.Error("the runner Job was replaced or rewritten on an unchanged second pass")
	}
	if got := transitions(h, job, trawlv1alpha1.CapturePhasePending); got != 1 {
		t.Errorf("Pending transition audited %d times across two passes, want 1", got)
	}
}

func TestCaptureAdoptsARunnerJobItAlreadyCreated(t *testing.T) {
	// The Job was created but the status write that recorded it was lost.
	// The next pass must find the Job by its stable name and carry on, not
	// try to create a second one.
	ns := NewNamespace(t)
	activeTap(t, ns, time.Now())
	job := createCapture(t, ns, "adopt")
	h := captureReconcilerFor(t, ns)

	bounds, err := capture.ParseBounds(job.Spec)
	if err != nil {
		t.Fatal(err)
	}
	orphan := h.r.Renderer.Job(job, bounds, "enp5s0")
	if err := controllerutil.SetControllerReference(job, orphan, Scheme()); err != nil {
		t.Fatal(err)
	}
	if err := Client().Create(t.Context(), orphan); err != nil {
		t.Fatalf("pre-creating runner: %v", err)
	}

	reconcileCapture(t, h.r, job)

	after := reloadCapture(t, job)
	if after.Status.RunnerJobRef == nil || after.Status.RunnerJobRef.Name != orphan.Name {
		t.Errorf("runnerJobRef = %+v, want the pre-existing Job %s", after.Status.RunnerJobRef, orphan.Name)
	}
	if again := runnerJobOf(t, job); again.UID != orphan.UID {
		t.Error("the pre-existing runner Job was replaced")
	}
}

func TestCaptureFailsWhenTheTargetStaysUnavailable(t *testing.T) {
	// Past the grace window a stale heartbeat is an answer, not a delay.
	ns := NewNamespace(t)
	activeTap(t, ns, time.Now().Add(-10*time.Minute))
	job := createCapture(t, ns, "stale")
	h := captureReconcilerFor(t, ns)
	h.r.Now = func() time.Time { return job.CreationTimestamp.Add(5 * time.Minute) }

	reconcileCapture(t, h.r, job)

	after := reloadCapture(t, job)
	if after.Status.Phase != trawlv1alpha1.CapturePhaseFailed {
		t.Fatalf("phase = %q, want Failed", after.Status.Phase)
	}
	if after.Status.Failure == nil || after.Status.Failure.Reason != trawlv1alpha1.FailureTargetUnavailable {
		t.Errorf("failure = %+v, want TargetUnavailable", after.Status.Failure)
	}
	rec := h.audit.last()
	if rec.Decision != audit.DecisionFailed || rec.Reason != string(trawlv1alpha1.FailureTargetUnavailable) {
		t.Errorf("audit record = %+v, want a Failed decision with the failure reason", rec)
	}
}

func TestCaptureFailsWhenTheTapIsNotActive(t *testing.T) {
	ns := NewNamespace(t)
	tap := activeTap(t, ns, time.Now())
	tap.Status.Phase = trawlv1alpha1.TapPhasePending
	if err := Client().Status().Update(t.Context(), tap); err != nil {
		t.Fatal(err)
	}
	job := createCapture(t, ns, "inactive")
	h := captureReconcilerFor(t, ns)
	h.r.Now = func() time.Time { return job.CreationTimestamp.Add(5 * time.Minute) }

	reconcileCapture(t, h.r, job)

	after := reloadCapture(t, job)
	if after.Status.Failure == nil || after.Status.Failure.Reason != trawlv1alpha1.FailureTapInactive {
		t.Errorf("failure = %+v, want TapInactive", after.Status.Failure)
	}
}

func TestReporterFieldsSurviveTheControllersWrites(t *testing.T) {
	// The reporter and the controller write the same status object under
	// different field managers. The controller's full-object update must
	// carry the reporter's fields forward, not blank them.
	ns := NewNamespace(t)
	h, job, _ := startedCapture(t, ns, "shared-status")

	started := metav1.NewTime(time.Now().Add(-30 * time.Second).Truncate(time.Second))
	applyReporterPatch(t, job, reporter.Patch{
		ResolvedInterface: "enp5s0",
		StartedAt:         &started,
		Conditions: []metav1.Condition{
			status.New(status.TypeFilterValid, metav1.ConditionTrue, "FilterCompiled", "ok", job.Generation),
			status.New(status.TypeCaptureStarted, metav1.ConditionTrue, "Started", "ok", job.Generation),
		},
	})

	reconcileCapture(t, h.r, reloadCapture(t, job))

	after := reloadCapture(t, job)
	if after.Status.Phase != trawlv1alpha1.CapturePhaseCapturing {
		t.Errorf("phase = %q, want Capturing once the reporter reports a start", after.Status.Phase)
	}
	if after.Status.StartedAt == nil || !after.Status.StartedAt.Equal(&started) {
		t.Errorf("startedAt = %v, want the reporter's %v", after.Status.StartedAt, started)
	}
	if after.Status.ResolvedInterface != "enp5s0" {
		t.Errorf("resolvedInterface = %q, want the reporter's", after.Status.ResolvedInterface)
	}
	for _, typ := range []string{status.TypeFilterValid, status.TypeCaptureStarted} {
		if c := condOf(after, typ); c == nil || c.Status != metav1.ConditionTrue {
			t.Errorf("%s = %+v after the controller wrote status, want True", typ, c)
		}
	}
	if c := condOf(after, status.TypeAccepted); c == nil || c.Status != metav1.ConditionTrue {
		t.Errorf("Accepted = %+v, want the controller's True", c)
	}
	if got := transitions(h, job, trawlv1alpha1.CapturePhaseCapturing); got != 1 {
		t.Errorf("Capturing transition audited %d times, want 1", got)
	}
}

func TestCaptureCompletesOnAVerifiedArtifact(t *testing.T) {
	ns := NewNamespace(t)
	h, job, runner := startedCapture(t, ns, "completes")
	storeArtifact(t, h.store, job, 0)
	finishRunner(t, runner, batchv1.JobComplete, "")

	res := reconcileCapture(t, h.r, job)

	after := reloadCapture(t, job)
	if after.Status.Phase != trawlv1alpha1.CapturePhaseCompleted {
		t.Fatalf("phase = %q, want Completed; failure=%+v", after.Status.Phase, after.Status.Failure)
	}
	if res.RequeueAfter != 0 {
		t.Errorf("a completed capture asked to be requeued: %+v", res)
	}
	s := after.Status
	if s.SHA256 == "" || s.SizeBytes == nil || s.PacketCount == nil || *s.PacketCount != 17 {
		t.Errorf("completion fields not filled from the manifest: sha=%q size=%v packets=%v",
			s.SHA256, s.SizeBytes, s.PacketCount)
	}
	if s.Artifact == nil || s.Artifact.Key != capture.ObjectKey(ns, string(job.UID)) {
		t.Errorf("artifact = %+v, want the object key", s.Artifact)
	}
	if s.StartedAt == nil || s.CaptureEndedAt == nil || s.CompletedAt == nil || s.RetentionDeadline == nil {
		t.Errorf("timestamps incomplete: started=%v ended=%v completed=%v deadline=%v",
			s.StartedAt, s.CaptureEndedAt, s.CompletedAt, s.RetentionDeadline)
	}
	if s.ResolvedInterface != "enp5s0" {
		t.Errorf("resolvedInterface = %q, want the manifest's", s.ResolvedInterface)
	}
	for _, typ := range []string{status.TypeArtifactVerified, status.TypeDownloadable} {
		if c := condOf(after, typ); c == nil || c.Status != metav1.ConditionTrue {
			t.Errorf("%s = %+v, want True", typ, c)
		}
	}
	if got := transitions(h, job, trawlv1alpha1.CapturePhaseCompleted); got != 1 {
		t.Errorf("Completed transition audited %d times, want 1", got)
	}
	if h.store.ObjectCount() != 2 {
		t.Errorf("a completed capture's objects were touched: %d objects remain, want 2", h.store.ObjectCount())
	}
}

func TestCaptureFailsWhenTheRunnerFailsWithoutAnArtifact(t *testing.T) {
	ns := NewNamespace(t)
	h, job, runner := startedCapture(t, ns, "runner-failed")
	finishRunner(t, runner, batchv1.JobFailed, "BackoffLimitExceeded")

	reconcileCapture(t, h.r, job)

	after := reloadCapture(t, job)
	if after.Status.Phase != trawlv1alpha1.CapturePhaseFailed {
		t.Fatalf("phase = %q, want Failed", after.Status.Phase)
	}
	if after.Status.Failure == nil {
		t.Fatal("no failure recorded")
	}
	if c := condOf(after, status.TypeArtifactVerified); c == nil || c.Status != metav1.ConditionFalse ||
		c.Reason != status.ReasonArtifactMissing {
		t.Errorf("ArtifactVerified = %+v, want False/ArtifactMissing", c)
	}
	if c := condOf(after, status.TypeDownloadable); c == nil || c.Status != metav1.ConditionFalse ||
		c.Reason != status.ReasonNotDownloadable {
		t.Errorf("Downloadable = %+v, want False/NotDownloadable", c)
	}
}

func TestCaptureFailsAndCleansUpOnAMismatchedArtifact(t *testing.T) {
	// An object the manifest does not describe is evidence of nothing. It
	// is removed so it can never be served, and the failure says why.
	ns := NewNamespace(t)
	h, job, runner := startedCapture(t, ns, "mismatch")
	storeArtifact(t, h.store, job, 4096)
	finishRunner(t, runner, batchv1.JobComplete, "")

	reconcileCapture(t, h.r, job)

	after := reloadCapture(t, job)
	if after.Status.Failure == nil || after.Status.Failure.Reason != trawlv1alpha1.FailureArtifactMismatch {
		t.Fatalf("failure = %+v, want ArtifactMismatch", after.Status.Failure)
	}
	if c := condOf(after, status.TypeArtifactVerified); c == nil || c.Reason != status.ReasonChecksumMismatch {
		t.Errorf("ArtifactVerified = %+v, want ChecksumMismatch", c)
	}
	if h.store.ObjectCount() != 0 {
		t.Errorf("%d objects remain after a mismatch, want 0", h.store.ObjectCount())
	}
}

func TestCaptureHoldsItsPhaseWhileStorageIsUnavailable(t *testing.T) {
	// "I could not look" must not become "there is nothing there". The
	// phase stays, the condition says storage is the problem, and the pass
	// asks to be repeated.
	ns := NewNamespace(t)
	h, job, runner := startedCapture(t, ns, "storage-down")
	storeArtifact(t, h.store, job, 0)
	finishRunner(t, runner, batchv1.JobComplete, "")
	h.r.Store = headFailingStore{Store: h.store}

	res := reconcileCapture(t, h.r, job)

	after := reloadCapture(t, job)
	if after.Status.Phase != trawlv1alpha1.CapturePhasePending {
		t.Errorf("phase = %q, want unchanged Pending while storage is unreachable", after.Status.Phase)
	}
	if c := condOf(after, status.TypeArtifactVerified); c == nil ||
		c.Status != metav1.ConditionUnknown || c.Reason != status.ReasonStorageFailure {
		t.Errorf("ArtifactVerified = %+v, want Unknown/StorageFailure", c)
	}
	if res.RequeueAfter <= 0 {
		t.Errorf("RequeueAfter = %v, want > 0", res.RequeueAfter)
	}

	h.r.Store = h.store
	reconcileCapture(t, h.r, reloadCapture(t, job))
	if after := reloadCapture(t, job); after.Status.Phase != trawlv1alpha1.CapturePhaseCompleted {
		t.Errorf("phase = %q after storage recovered, want Completed", after.Status.Phase)
	}
}

func TestATransitionWaitsForItsAuditRecord(t *testing.T) {
	// ADR-0003: no phase without a record. When the ledger is down the
	// phase does not move; when it recovers the record is committed once.
	ns := NewNamespace(t)
	activeTap(t, ns, time.Now())
	job := createCapture(t, ns, "audit-gate")
	h := captureReconcilerFor(t, ns)
	h.audit.setFailure(errors.New("ledger unavailable"))

	if _, err := h.r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(job)}); err == nil {
		t.Fatal("Reconcile succeeded with the ledger unavailable")
	}
	held := reloadCapture(t, job)
	if held.Status.Phase != "" {
		t.Errorf("phase = %q with the ledger unavailable, want none", held.Status.Phase)
	}
	if c := condOf(held, status.TypeAccepted); c == nil || c.Reason != status.ReasonAuditUnavailable {
		t.Errorf("Accepted = %+v, want reason AuditUnavailable", c)
	}

	h.audit.setFailure(nil)
	reconcileCapture(t, h.r, reloadCapture(t, job))
	after := reloadCapture(t, job)
	if after.Status.Phase != trawlv1alpha1.CapturePhasePending {
		t.Errorf("phase = %q after the ledger recovered, want Pending", after.Status.Phase)
	}
	if got := transitions(h, job, trawlv1alpha1.CapturePhasePending); got != 1 {
		t.Errorf("Pending transition audited %d times, want exactly 1", got)
	}
}

func TestARestartedControllerPicksUpWhereItLeftOff(t *testing.T) {
	// A new reconciler over the same objects has no memory. Everything it
	// needs is in the apiserver and the bucket.
	ns := NewNamespace(t)
	h1, job, runner := startedCapture(t, ns, "restart")
	storeArtifact(t, h1.store, job, 0)
	finishRunner(t, runner, batchv1.JobComplete, "")

	h2 := captureReconcilerFor(t, ns)
	h2.r.Store = h1.store
	reconcileCapture(t, h2.r, job)

	if after := reloadCapture(t, job); after.Status.Phase != trawlv1alpha1.CapturePhaseCompleted {
		t.Errorf("phase = %q from a fresh reconciler, want Completed", after.Status.Phase)
	}
}

func TestDeletingACaptureRemovesItsRunnerAndArtifact(t *testing.T) {
	ns := NewNamespace(t)
	h, job, runner := startedCapture(t, ns, "deleted")
	storeArtifact(t, h.store, job, 0)
	finishRunner(t, runner, batchv1.JobComplete, "")
	reconcileCapture(t, h.r, job)
	job = reloadCapture(t, job)
	if job.Status.Phase != trawlv1alpha1.CapturePhaseCompleted {
		t.Fatalf("phase = %q, want Completed before deletion", job.Status.Phase)
	}

	if err := Client().Delete(t.Context(), job); err != nil {
		t.Fatalf("deleting capture: %v", err)
	}

	// First pass: the runner Job goes and the pass waits for it.
	res := reconcileCapture(t, h.r, job)
	if res.RequeueAfter <= 0 {
		t.Errorf("RequeueAfter = %v while the Job is being deleted, want > 0", res.RequeueAfter)
	}
	if h.store.ObjectCount() != 2 {
		t.Errorf("artifact removed before the runner was gone: %d objects", h.store.ObjectCount())
	}
	var gone batchv1.Job
	if err := Client().Get(t.Context(), client.ObjectKeyFromObject(runner), &gone); !apierrors.IsNotFound(err) {
		t.Fatalf("runner Job still present after the finalizer ran (err=%v)", err)
	}

	// Second pass: artifact deleted, both expiry records written, object released.
	reconcileCapture(t, h.r, job)
	if h.store.ObjectCount() != 0 {
		t.Errorf("%d objects remain after deletion, want 0", h.store.ObjectCount())
	}
	for _, step := range []string{"delete-allowed", "delete-succeeded"} {
		if got := h.audit.count(audit.ActionArtifactExpire, job, step); got != 1 {
			t.Errorf("%s audited %d times, want 1", step, got)
		}
	}
	var fresh trawlv1alpha1.CaptureJob
	if err := Client().Get(t.Context(), client.ObjectKeyFromObject(job), &fresh); !apierrors.IsNotFound(err) {
		t.Errorf("CaptureJob still exists after its finalizer ran (err=%v, finalizers=%v)", err, fresh.Finalizers)
	}
}

func TestReconcileRejectsACaptureOutsideTheSystemNamespace(t *testing.T) {
	ns := NewNamespace(t)
	other := NewNamespace(t)
	job := createCapture(t, other, "elsewhere")
	h := captureReconcilerFor(t, ns)

	reconcileCapture(t, h.r, job)

	after := reloadCapture(t, job)
	if after.Status.Phase != trawlv1alpha1.CapturePhaseFailed {
		t.Errorf("phase = %q, want Failed", after.Status.Phase)
	}
	if c := condOf(after, status.TypeAccepted); c == nil || c.Reason != status.ReasonWrongNamespace {
		t.Errorf("Accepted = %+v, want reason WrongNamespace", c)
	}
	name, _, _ := controller.CaptureNames(after)
	var runner batchv1.Job
	err := Client().Get(t.Context(), client.ObjectKey{Namespace: other, Name: name}, &runner)
	if !apierrors.IsNotFound(err) {
		t.Errorf("a runner Job was rendered outside the system namespace (err=%v)", err)
	}
}

func TestACaptureStoredWithABadSpecFailsInsteadOfRunning(t *testing.T) {
	// The webhook's rules are re-checked before anything privileged is
	// rendered, for an object that reached etcd without passing them.
	ns := NewNamespace(t)
	activeTap(t, ns, time.Now().Add(-10*time.Minute))
	job := createCapture(t, ns, "bad-spec")
	h := captureReconcilerFor(t, ns)
	// The first pass adds the finalizer with a spec the apiserver accepts;
	// the second sees a spec it would not have.
	reconcileCapture(t, h.r, job)
	h.r.Client = &faultyClient{
		Client: Client(),
		afterGet: func(obj client.Object) {
			if cj, ok := obj.(*trawlv1alpha1.CaptureJob); ok {
				cj.Spec.Duration = "0s"
			}
		},
	}

	reconcileCapture(t, h.r, job)

	after := reloadCapture(t, job)
	if after.Status.Failure == nil || after.Status.Failure.Reason != trawlv1alpha1.FailureInvalidBounds {
		t.Errorf("failure = %+v, want InvalidBounds", after.Status.Failure)
	}
	if c := condOf(after, status.TypeAccepted); c == nil || c.Reason != status.ReasonInvalidSpec {
		t.Errorf("Accepted = %+v, want reason InvalidSpec", c)
	}
}
