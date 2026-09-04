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

package capture

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/status"
)

// The lifecycle is a pure function of the object and what the controller
// observed. Every row here is one situation the controller can find itself in,
// including the ones a restart produces, and each has exactly one answer.

var (
	t0        = time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	phases    = []trawlv1alpha1.CapturePhase{"", "Pending", "Capturing", "Storing", "Completed", "Failed", "Expired"}
	heartbeat = 90 * time.Second
)

func newJob(phase trawlv1alpha1.CapturePhase) *trawlv1alpha1.CaptureJob {
	job := &trawlv1alpha1.CaptureJob{
		ObjectMeta: metav1.ObjectMeta{
			Name: "manual-tls", Namespace: "trawl-system", UID: "11111111-2222-3333-4444-555555555555",
			Generation:        1,
			CreationTimestamp: metav1.Time{Time: t0},
		},
		Spec: trawlv1alpha1.CaptureJobSpec{
			RequestType: trawlv1alpha1.CaptureRequestManual,
			TapRef:      corev1.LocalObjectReference{Name: "north-south-mirror"},
			TargetNode:  "talos-sensor-01",
			Duration:    "2m",
			MaxSize:     resource.MustParse("50Mi"),
			Retention:   "7d",
		},
	}
	job.Status.Phase = phase
	job.Status.ObservedGeneration = 1
	if phase != "" && phase != trawlv1alpha1.CapturePhasePending {
		job.Status.RunnerJobRef = &corev1.LocalObjectReference{Name: "trawl-capture-" + string(job.UID)}
	}
	switch phase {
	case trawlv1alpha1.CapturePhaseCapturing:
		job.Status.StartedAt = &metav1.Time{Time: t0.Add(10 * time.Second)}
	case trawlv1alpha1.CapturePhaseStoring:
		job.Status.StartedAt = &metav1.Time{Time: t0.Add(10 * time.Second)}
		job.Status.CaptureEndedAt = &metav1.Time{Time: t0.Add(130 * time.Second)}
	}
	return job
}

func verifiedManifest() *Manifest {
	return &Manifest{
		SchemaVersion:  ManifestSchemaVersion,
		CaptureJobUID:  "11111111-2222-3333-4444-555555555555",
		Interface:      "enp5s0",
		StartedAt:      t0.Add(10 * time.Second),
		EndedAt:        t0.Add(130 * time.Second),
		StopReason:     trawlv1alpha1.CaptureStopDuration,
		PacketCount:    0,
		SizeBytes:      256,
		SHA256:         strings.Repeat("ab", 32),
		DumpcapVersion: "4.0.11",
	}
}

func eligible() TargetObservation {
	return TargetObservation{State: TargetEligible, TapUID: "tap-uid", Interface: "enp5s0"}
}

func TestIsTerminal(t *testing.T) {
	for _, p := range phases {
		want := p == trawlv1alpha1.CapturePhaseCompleted || p == trawlv1alpha1.CapturePhaseFailed || p == trawlv1alpha1.CapturePhaseExpired
		if got := IsTerminal(p); got != want {
			t.Errorf("IsTerminal(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestCanTransitionMatrix(t *testing.T) {
	// Forward moves may skip: the reconciler writes the phase the facts imply,
	// so a capture stored and verified inside one pass goes straight from
	// Capturing to Completed. Backwards moves and any move out of a terminal
	// phase other than Completed -> Expired are what the lifecycle forbids.
	legal := map[trawlv1alpha1.CapturePhase][]trawlv1alpha1.CapturePhase{
		"":          {"Pending", "Capturing", "Storing", "Completed", "Expired", "Failed"},
		"Pending":   {"Capturing", "Storing", "Completed", "Expired", "Failed"},
		"Capturing": {"Storing", "Completed", "Expired", "Failed"},
		"Storing":   {"Completed", "Expired", "Failed"},
		"Completed": {"Expired"},
		"Failed":    {},
		"Expired":   {},
	}
	for _, from := range phases {
		for _, to := range phases {
			want := false
			for _, ok := range legal[from] {
				if ok == to {
					want = true
				}
			}
			if got := CanTransition(from, to); got != want {
				t.Errorf("CanTransition(%q, %q) = %v, want %v", from, to, got, want)
			}
		}
	}
}

func TestEvaluateTerminalPhasesAreNoOps(t *testing.T) {
	for _, p := range []trawlv1alpha1.CapturePhase{"Completed", "Failed", "Expired"} {
		job := newJob(p)
		// Even contradicting observations must not move a terminal job.
		obs := Observation{Now: t0, Job: JobObservation{State: JobFailed}, Artifact: ArtifactObservation{State: ArtifactMismatch}}
		out, err := Evaluate(job, obs, heartbeat)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if out.Phase != p || out.Action != ActionNone {
			t.Errorf("%s: outcome %+v moved a terminal job", p, out)
		}
	}
}

func TestEvaluateCreatesJobWhenEligibleAndNoRunnerExists(t *testing.T) {
	job := newJob("")
	out, err := Evaluate(job, Observation{Now: t0, Target: eligible(), Job: JobObservation{State: JobAbsent}}, heartbeat)
	if err != nil {
		t.Fatal(err)
	}
	if out.Phase != trawlv1alpha1.CapturePhasePending || out.Action != ActionCreateJob {
		t.Fatalf("outcome %+v, want Pending + ActionCreateJob", out)
	}
	if out.ResolvedTapUID != "tap-uid" {
		t.Errorf("resolved tap UID %q not carried", out.ResolvedTapUID)
	}
}

func TestEvaluateWaitsThenFailsWhenTargetNotEligible(t *testing.T) {
	cases := map[TargetState]trawlv1alpha1.FailureReason{
		TargetTapMissing:  trawlv1alpha1.FailureTapInactive,
		TargetTapInactive: trawlv1alpha1.FailureTapInactive,
		TargetUnavailable: trawlv1alpha1.FailureTargetUnavailable,
		TargetTapDeleting: trawlv1alpha1.FailureTapInactive,
	}
	for state, reason := range cases {
		job := newJob(trawlv1alpha1.CapturePhasePending)
		job.Status.RunnerJobRef = nil
		obs := Observation{Now: t0.Add(heartbeat), Target: TargetObservation{State: state}, Job: JobObservation{State: JobAbsent}}
		out, err := Evaluate(job, obs, heartbeat)
		if err != nil {
			t.Fatal(err)
		}
		// Within the grace window the job waits: a tap that just restarted
		// will report a fresh heartbeat shortly.
		if out.Phase != trawlv1alpha1.CapturePhasePending || out.Action != ActionNone || out.RequeueAfter <= 0 {
			t.Errorf("%v within grace: %+v, want Pending with requeue", state, out)
		}

		obs.Now = t0.Add(2*heartbeat + time.Second)
		out, err = Evaluate(job, obs, heartbeat)
		if err != nil {
			t.Fatal(err)
		}
		if out.Phase != trawlv1alpha1.CapturePhaseFailed || out.Failure == nil || out.Failure.Reason != reason {
			t.Errorf("%v after grace: %+v, want Failed(%s)", state, out, reason)
		}
		if out.Failure != nil && out.Failure.FailedPhase != trawlv1alpha1.CapturePhasePending {
			t.Errorf("%v: failedPhase = %s, want Pending", state, out.Failure.FailedPhase)
		}
	}
}

func TestEvaluateFailsWhenRunnerJobDisappeared(t *testing.T) {
	job := newJob(trawlv1alpha1.CapturePhaseCapturing)
	obs := Observation{Now: t0, Target: eligible(), Job: JobObservation{State: JobAbsent}, Artifact: ArtifactObservation{State: ArtifactAbsent}}
	out, err := Evaluate(job, obs, heartbeat)
	if err != nil {
		t.Fatal(err)
	}
	if out.Phase != trawlv1alpha1.CapturePhaseFailed || out.Failure.Reason != trawlv1alpha1.FailureInternalError {
		t.Fatalf("outcome %+v, want Failed(InternalError)", out)
	}
	if out.Action == ActionCreateJob {
		t.Error("a second runner was requested for the same capture")
	}
}

func TestEvaluateDerivesLivePhaseFromReporterFacts(t *testing.T) {
	cases := []struct {
		name    string
		started bool
		ended   bool
		want    trawlv1alpha1.CapturePhase
	}{
		{"nothing reported", false, false, trawlv1alpha1.CapturePhasePending},
		{"started", true, false, trawlv1alpha1.CapturePhaseCapturing},
		{"ended", true, true, trawlv1alpha1.CapturePhaseStoring},
	}
	for _, tc := range cases {
		job := newJob(trawlv1alpha1.CapturePhasePending)
		if tc.started {
			job.Status.StartedAt = &metav1.Time{Time: t0}
		}
		if tc.ended {
			job.Status.CaptureEndedAt = &metav1.Time{Time: t0.Add(time.Minute)}
		}
		out, err := Evaluate(job, Observation{Now: t0.Add(2 * time.Minute), Job: JobObservation{State: JobActive}}, heartbeat)
		if err != nil {
			t.Fatal(err)
		}
		if out.Phase != tc.want {
			t.Errorf("%s: phase %s, want %s", tc.name, out.Phase, tc.want)
		}
	}
}

func TestEvaluateNeverRegressesTheLivePhase(t *testing.T) {
	// The reporter's fields are set once and never cleared, but a controller
	// must still not move Storing back to Capturing if it somehow observed
	// a stale object.
	job := newJob(trawlv1alpha1.CapturePhaseStoring)
	job.Status.CaptureEndedAt = nil
	out, err := Evaluate(job, Observation{Now: t0, Job: JobObservation{State: JobActive}}, heartbeat)
	if err != nil {
		t.Fatal(err)
	}
	if out.Phase != trawlv1alpha1.CapturePhaseStoring {
		t.Errorf("phase regressed to %s", out.Phase)
	}
}

func TestEvaluateVerifiedArtifactCompletesRegardlessOfJob(t *testing.T) {
	for _, js := range []JobState{JobActive, JobSucceeded, JobFailed, JobAbsent} {
		job := newJob(trawlv1alpha1.CapturePhaseStoring)
		obs := Observation{
			Now: t0.Add(3 * time.Minute),
			Job: JobObservation{State: js, ExitCode: exit(15)},
			Artifact: ArtifactObservation{
				State: ArtifactVerified, Manifest: verifiedManifest(),
				Key: "captures/trawl-system/uid/capture.pcapng", ETag: "etag-1", VersionID: "v1",
			},
		}
		out, err := Evaluate(job, obs, heartbeat)
		if err != nil {
			t.Fatalf("%v: %v", js, err)
		}
		if out.Phase != trawlv1alpha1.CapturePhaseCompleted || out.Completion == nil {
			t.Fatalf("%v: outcome %+v, want Completed with facts", js, out)
		}
		c := out.Completion
		if c.SizeBytes != 256 || c.SHA256 != strings.Repeat("ab", 32) || c.PacketCount != 0 {
			t.Errorf("%v: completion facts %+v do not match the manifest", js, c)
		}
		if c.Artifact.Key == "" || c.Artifact.ETag != "etag-1" || !c.Artifact.VerifiedAt.Time.Equal(obs.Now) {
			t.Errorf("%v: artifact reference %+v incomplete", js, c.Artifact)
		}
		want := obs.Now.Add(7 * 24 * time.Hour)
		if !c.RetentionDeadline.Equal(want) {
			t.Errorf("%v: retention deadline %v, want %v", js, c.RetentionDeadline, want)
		}
		if !c.StartedAt.Equal(t0.Add(10*time.Second)) || !c.EndedAt.Equal(t0.Add(130*time.Second)) {
			t.Errorf("%v: manifest times not carried: %+v", js, c)
		}
	}
}

func TestEvaluateZeroPacketArtifactCompletes(t *testing.T) {
	job := newJob(trawlv1alpha1.CapturePhaseStoring)
	m := verifiedManifest()
	m.PacketCount = 0
	obs := Observation{Now: t0, Job: JobObservation{State: JobSucceeded}, Artifact: ArtifactObservation{State: ArtifactVerified, Manifest: m}}
	out, err := Evaluate(job, obs, heartbeat)
	if err != nil || out.Phase != trawlv1alpha1.CapturePhaseCompleted {
		t.Fatalf("zero-packet capture did not complete: %+v %v", out, err)
	}
}

func TestEvaluateArtifactMismatchFailsAndCleansUp(t *testing.T) {
	job := newJob(trawlv1alpha1.CapturePhaseStoring)
	obs := Observation{Now: t0, Job: JobObservation{State: JobSucceeded}, Artifact: ArtifactObservation{State: ArtifactMismatch}}
	out, err := Evaluate(job, obs, heartbeat)
	if err != nil {
		t.Fatal(err)
	}
	if out.Phase != trawlv1alpha1.CapturePhaseFailed || out.Failure.Reason != trawlv1alpha1.FailureArtifactMismatch {
		t.Fatalf("outcome %+v, want Failed(ArtifactMismatch)", out)
	}
	if out.Action != ActionCleanupArtifact {
		t.Error("a mismatching object was left in the bucket")
	}
}

func TestEvaluateStorageUnavailableHoldsPhase(t *testing.T) {
	for _, phase := range []trawlv1alpha1.CapturePhase{"Capturing", "Storing"} {
		job := newJob(phase)
		obs := Observation{Now: t0, Job: JobObservation{State: JobSucceeded}, Artifact: ArtifactObservation{State: ArtifactUnavailable}}
		out, err := Evaluate(job, obs, heartbeat)
		if err != nil {
			t.Fatal(err)
		}
		if out.Phase != phase || out.Failure != nil || !out.StorageUnavailable || out.RequeueAfter <= 0 {
			t.Errorf("%s: outcome %+v, want phase held with storage flagged and a retry", phase, out)
		}
	}
}

func exit(code int32) *int32 { return &code }

func TestEvaluateTerminalJobWithoutArtifactFails(t *testing.T) {
	cases := []struct {
		name   string
		job    JobObservation
		result *trawlv1alpha1.RunnerResult
		art    ArtifactState
		want   trawlv1alpha1.FailureReason
		phase  trawlv1alpha1.CapturePhase
		clean  bool
	}{
		{"reporter reason wins", JobObservation{State: JobFailed, ExitCode: exit(13)},
			&trawlv1alpha1.RunnerResult{Outcome: trawlv1alpha1.RunnerOutcomeFailed, Reason: trawlv1alpha1.FailureInvalidFilter, ExitCode: 12},
			ArtifactAbsent, trawlv1alpha1.FailureInvalidFilter, "Pending", false},
		{"exit code when no reporter result", JobObservation{State: JobFailed, ExitCode: exit(11)}, nil,
			ArtifactAbsent, trawlv1alpha1.FailureInterfaceUnavailable, "Pending", false},
		{"size exceeded", JobObservation{State: JobFailed, ExitCode: exit(14)}, nil,
			ArtifactAbsent, trawlv1alpha1.FailureSizeExceeded, "Capturing", false},
		{"upload failed by exit code", JobObservation{State: JobFailed, ExitCode: exit(15)}, nil,
			ArtifactAbsent, trawlv1alpha1.FailureUploadFailed, "Storing", false},
		{"job deadline after start", JobObservation{State: JobFailed, Reason: "DeadlineExceeded"}, nil,
			ArtifactAbsent, trawlv1alpha1.FailureCaptureFailed, "Capturing", false},
		{"job deadline before start", JobObservation{State: JobFailed, Reason: "DeadlineExceeded"}, nil,
			ArtifactAbsent, trawlv1alpha1.FailureInternalError, "Pending", false},
		{"unknown failure", JobObservation{State: JobFailed}, nil,
			ArtifactAbsent, trawlv1alpha1.FailureInternalError, "Capturing", false},
		{"succeeded but nothing stored", JobObservation{State: JobSucceeded, ExitCode: exit(0)}, nil,
			ArtifactAbsent, trawlv1alpha1.FailureArtifactMissing, "Storing", false},
		{"object without manifest", JobObservation{State: JobSucceeded, ExitCode: exit(0)}, nil,
			ArtifactPresent, trawlv1alpha1.FailureUploadFailed, "Storing", true},
		{"unknown exit code", JobObservation{State: JobFailed, ExitCode: exit(137)}, nil,
			ArtifactAbsent, trawlv1alpha1.FailureCaptureFailed, "Capturing", false},
	}
	for _, tc := range cases {
		job := newJob(tc.phase)
		job.Status.RunnerResult = tc.result
		obs := Observation{Now: t0, Job: tc.job, Artifact: ArtifactObservation{State: tc.art}}
		out, err := Evaluate(job, obs, heartbeat)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if out.Phase != trawlv1alpha1.CapturePhaseFailed || out.Failure == nil || out.Failure.Reason != tc.want {
			t.Errorf("%s: outcome %+v, want Failed(%s)", tc.name, out, tc.want)
			continue
		}
		if out.Failure.FailedPhase != tc.phase {
			t.Errorf("%s: failedPhase %s, want %s", tc.name, out.Failure.FailedPhase, tc.phase)
		}
		if (out.Action == ActionCleanupArtifact) != tc.clean {
			t.Errorf("%s: cleanup = %v, want %v", tc.name, out.Action == ActionCleanupArtifact, tc.clean)
		}
		if out.Failure.Message == "" || len(out.Failure.Message) > 512 {
			t.Errorf("%s: message %q not bounded and present", tc.name, out.Failure.Message)
		}
	}
}

func TestEvaluateRejectsTerminalJobWithoutArtifactObservation(t *testing.T) {
	// The controller must look before it decides. A terminal Job with the
	// artifact unobserved is a caller bug, not a capture failure.
	job := newJob(trawlv1alpha1.CapturePhaseStoring)
	_, err := Evaluate(job, Observation{Now: t0, Job: JobObservation{State: JobSucceeded}, Artifact: ArtifactObservation{State: ArtifactUnknown}}, heartbeat)
	if err == nil {
		t.Fatal("terminal Job with unobserved artifact evaluated")
	}
}

func TestEvaluateActiveJobWithRunnerFailureWaitsForJob(t *testing.T) {
	// The reporter can publish the result before the pod is torn down. The
	// Job is the arbiter of "over"; the phase holds until it says so.
	job := newJob(trawlv1alpha1.CapturePhaseCapturing)
	job.Status.RunnerResult = &trawlv1alpha1.RunnerResult{Outcome: trawlv1alpha1.RunnerOutcomeFailed, Reason: trawlv1alpha1.FailureCaptureFailed}
	out, err := Evaluate(job, Observation{Now: t0, Job: JobObservation{State: JobActive}, Artifact: ArtifactObservation{State: ArtifactAbsent}}, heartbeat)
	if err != nil {
		t.Fatal(err)
	}
	if out.Phase != trawlv1alpha1.CapturePhaseCapturing || out.Failure != nil {
		t.Errorf("outcome %+v, want Capturing held", out)
	}
}

func TestEvaluateOutcomeIsDeterministic(t *testing.T) {
	job := newJob(trawlv1alpha1.CapturePhaseCapturing)
	obs := Observation{Now: t0, Job: JobObservation{State: JobFailed, ExitCode: exit(13)}, Artifact: ArtifactObservation{State: ArtifactAbsent}}
	a, _ := Evaluate(job, obs, heartbeat)
	b, _ := Evaluate(job, obs, heartbeat)
	if a.Failure.Message != b.Failure.Message || a.Phase != b.Phase {
		t.Errorf("two evaluations of the same facts differ: %+v vs %+v", a, b)
	}
}

func TestDownloadableAtTheDeadline(t *testing.T) {
	deadline := t0.Add(time.Hour)
	job := newJob(trawlv1alpha1.CapturePhaseCompleted)
	job.Status.SHA256 = strings.Repeat("ab", 32)
	job.Status.Artifact = &trawlv1alpha1.ArtifactReference{Key: "k", VerifiedAt: metav1.Time{Time: t0}}
	job.Status.RetentionDeadline = &metav1.Time{Time: deadline}
	status.Set(&job.Status.Conditions, status.New(status.TypeArtifactVerified, metav1.ConditionTrue, status.ReasonArtifactVerified, "", 1))

	if !Downloadable(job, deadline.Add(-time.Nanosecond)) {
		t.Error("not downloadable one nanosecond before the deadline")
	}
	if Downloadable(job, deadline) {
		t.Error("downloadable at the deadline instant")
	}
	if Downloadable(job, deadline.Add(time.Nanosecond)) {
		t.Error("downloadable after the deadline")
	}

	// Every other precondition is independently sufficient to deny.
	deny := map[string]func(*trawlv1alpha1.CaptureJob){
		"failed":                   func(j *trawlv1alpha1.CaptureJob) { j.Status.Phase = trawlv1alpha1.CapturePhaseFailed },
		"expired":                  func(j *trawlv1alpha1.CaptureJob) { j.Status.Phase = trawlv1alpha1.CapturePhaseExpired },
		"failure recorded":         func(j *trawlv1alpha1.CaptureJob) { j.Status.Failure = &trawlv1alpha1.CaptureFailure{} },
		"no artifact":              func(j *trawlv1alpha1.CaptureJob) { j.Status.Artifact = nil },
		"no checksum":              func(j *trawlv1alpha1.CaptureJob) { j.Status.SHA256 = "" },
		"no deadline":              func(j *trawlv1alpha1.CaptureJob) { j.Status.RetentionDeadline = nil },
		"unverified":               func(j *trawlv1alpha1.CaptureJob) { j.Status.Conditions = nil },
		"retention not reconciled": func(j *trawlv1alpha1.CaptureJob) { j.Generation = 2 },
	}
	for name, mutate := range deny {
		j := job.DeepCopy()
		mutate(j)
		if Downloadable(j, t0) {
			t.Errorf("%s: downloadable", name)
		}
	}
}

func TestRetentionDeadline(t *testing.T) {
	got, err := RetentionDeadline(t0, "7d")
	if err != nil || !got.Equal(t0.Add(7*24*time.Hour)) {
		t.Errorf("7d: %v %v", got, err)
	}
	got, err = RetentionDeadline(t0, "12h")
	if err != nil || !got.Equal(t0.Add(12*time.Hour)) {
		t.Errorf("12h: %v %v", got, err)
	}
	if _, err := RetentionDeadline(t0, "soon"); err == nil {
		t.Error("garbage retention accepted")
	}
}

func TestExitCodesRoundTrip(t *testing.T) {
	for _, reason := range []trawlv1alpha1.FailureReason{
		trawlv1alpha1.FailureInvalidBounds, trawlv1alpha1.FailureInterfaceUnavailable,
		trawlv1alpha1.FailureInvalidFilter, trawlv1alpha1.FailureCaptureFailed,
		trawlv1alpha1.FailureSizeExceeded, trawlv1alpha1.FailureUploadFailed,
		trawlv1alpha1.FailureInternalError,
	} {
		code := ExitCodeFor(reason)
		if code == 0 {
			t.Errorf("%s has no exit code", reason)
		}
		if got := FailureReasonForExitCode(code); got != reason {
			t.Errorf("exit %d → %s, want %s", code, got, reason)
		}
	}
	if FailureReasonForExitCode(0) != "" {
		t.Error("exit 0 mapped to a failure")
	}
	if got := FailureReasonForExitCode(137); got != trawlv1alpha1.FailureCaptureFailed {
		t.Errorf("unrecognised exit code → %s, want CaptureFailed", got)
	}
}

func TestTransitionStepIsStablePerPhase(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range phases[1:] {
		step := TransitionStep(p)
		if step == "" || seen[step] {
			t.Errorf("phase %s: step %q empty or reused", p, step)
		}
		seen[step] = true
	}
}

func TestDownloadDecisionSeparatesExpiryFromUnreadiness(t *testing.T) {
	deadline := t0.Add(time.Hour)
	ready := func() *trawlv1alpha1.CaptureJob {
		j := newJob(trawlv1alpha1.CapturePhaseCompleted)
		j.Status.SHA256 = strings.Repeat("ab", 32)
		j.Status.Artifact = &trawlv1alpha1.ArtifactReference{Key: "k", VerifiedAt: metav1.Time{Time: t0}}
		j.Status.RetentionDeadline = &metav1.Time{Time: deadline}
		status.Set(&j.Status.Conditions, status.New(status.TypeArtifactVerified, metav1.ConditionTrue, status.ReasonArtifactVerified, "", 1))
		return j
	}

	cases := []struct {
		name   string
		mutate func(*trawlv1alpha1.CaptureJob)
		now    time.Time
		want   DownloadDecision
	}{
		{"ready", func(*trawlv1alpha1.CaptureJob) {}, t0, DownloadAllowed},
		{"at the deadline", func(*trawlv1alpha1.CaptureJob) {}, deadline, DownloadExpired},
		{"past the deadline", func(*trawlv1alpha1.CaptureJob) {}, deadline.Add(time.Hour), DownloadExpired},
		{"phase Expired", func(j *trawlv1alpha1.CaptureJob) {
			j.Status.Phase = trawlv1alpha1.CapturePhaseExpired
		}, t0, DownloadExpired},
		{"still capturing", func(j *trawlv1alpha1.CaptureJob) {
			j.Status.Phase = trawlv1alpha1.CapturePhaseCapturing
		}, t0, DownloadNotReady},
		{"failed", func(j *trawlv1alpha1.CaptureJob) {
			j.Status.Phase = trawlv1alpha1.CapturePhaseFailed
		}, t0, DownloadNotReady},
		{"no verified artifact", func(j *trawlv1alpha1.CaptureJob) { j.Status.Conditions = nil }, t0, DownloadNotReady},
		{"retention change not yet reconciled", func(j *trawlv1alpha1.CaptureJob) { j.Generation = 2 }, t0, DownloadNotReady},
	}

	for _, tc := range cases {
		j := ready()
		tc.mutate(j)
		got := DecideDownload(j, tc.now)
		if got != tc.want {
			t.Errorf("%s: DecideDownload = %q, want %q", tc.name, got, tc.want)
		}
		// Downloadable must stay the single-bool view of the same decision, so
		// the two can never disagree about whether to serve an artifact.
		if want := tc.want == DownloadAllowed; Downloadable(j, tc.now) != want {
			t.Errorf("%s: Downloadable = %v, disagrees with DecideDownload = %q", tc.name, !want, got)
		}
	}
}
