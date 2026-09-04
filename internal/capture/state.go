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

// Package capture holds the CaptureJob domain: bounds, filter handling, the
// artifact manifest, the runner/reporter progress protocol, and the lifecycle
// state machine.
//
// Nothing here talks to the API server or object storage. The controller
// gathers what it can observe into an Observation and Evaluate returns the
// one outcome those facts support, so the lifecycle can be tested as a table
// and a restart re-evaluates rather than remembers.
package capture

import (
	"errors"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/types"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/config"
	"trawl.cloud/trawl/internal/status"
)

// Runner exit codes. The reporter's result record carries the reason directly;
// the exit code is the fallback the controller reads from the pod when the
// reporter never got to write one.
const (
	ExitOK                   = 0
	ExitInvalidBounds        = 10
	ExitInterfaceUnavailable = 11
	ExitInvalidFilter        = 12
	ExitCaptureFailed        = 13
	ExitSizeExceeded         = 14
	ExitUploadFailed         = 15
	ExitInternalError        = 16
)

var exitCodes = map[trawlv1alpha1.FailureReason]int32{
	trawlv1alpha1.FailureInvalidBounds:        ExitInvalidBounds,
	trawlv1alpha1.FailureInterfaceUnavailable: ExitInterfaceUnavailable,
	trawlv1alpha1.FailureInvalidFilter:        ExitInvalidFilter,
	trawlv1alpha1.FailureCaptureFailed:        ExitCaptureFailed,
	trawlv1alpha1.FailureSizeExceeded:         ExitSizeExceeded,
	trawlv1alpha1.FailureUploadFailed:         ExitUploadFailed,
	trawlv1alpha1.FailureInternalError:        ExitInternalError,
}

// ExitCodeFor returns the runner exit code for a failure reason, or 0 for a
// reason the runner never produces.
func ExitCodeFor(reason trawlv1alpha1.FailureReason) int32 {
	return exitCodes[reason]
}

// FailureReasonForExitCode maps a runner exit code back to its reason. Zero is
// success and maps to nothing; an unrecognised code (a signal, an OOM kill)
// is a capture that failed for a reason the runner did not get to say.
func FailureReasonForExitCode(code int32) trawlv1alpha1.FailureReason {
	if code == ExitOK {
		return ""
	}
	for reason, c := range exitCodes {
		if c == code {
			return reason
		}
	}
	return trawlv1alpha1.FailureCaptureFailed
}

// IsTerminal reports whether a phase admits no further transition.
func IsTerminal(p trawlv1alpha1.CapturePhase) bool {
	switch p {
	case trawlv1alpha1.CapturePhaseCompleted, trawlv1alpha1.CapturePhaseFailed, trawlv1alpha1.CapturePhaseExpired:
		return true
	}
	return false
}

// CanTransition reports whether the lifecycle permits moving from one phase
// to another. The empty phase is a freshly created object.
//
// Progress may skip phases, and describing the lifecycle as a chain of single
// steps does not survive contact with the cluster: the reconciler is
// level-triggered and writes the phase the facts it observed imply, so a
// capture whose artifact is already verified when the next pass looks moves
// Capturing -> Completed and Storing is never written. What the lifecycle
// actually forbids is moving backwards and leaving a terminal phase, and that
// is what this reports on.
func CanTransition(from, to trawlv1alpha1.CapturePhase) bool {
	if to == trawlv1alpha1.CapturePhaseFailed {
		return !IsTerminal(from)
	}
	if IsTerminal(from) {
		// Expiry is the one move out of a terminal phase: the artifact of a
		// completed capture outlives the capture, until retention ends it.
		return from == trawlv1alpha1.CapturePhaseCompleted && to == trawlv1alpha1.CapturePhaseExpired
	}
	return phaseOrder(to) > phaseOrder(from)
}

// phaseOrder is the lifecycle's forward ordering, which is what "backwards"
// is measured against. Failed is absent on purpose: it is reachable from
// every non-terminal phase and so is ordered against none of them.
func phaseOrder(p trawlv1alpha1.CapturePhase) int {
	switch p {
	case trawlv1alpha1.CapturePhasePending:
		return 1
	case trawlv1alpha1.CapturePhaseCapturing:
		return 2
	case trawlv1alpha1.CapturePhaseStoring:
		return 3
	case trawlv1alpha1.CapturePhaseCompleted:
		return 4
	case trawlv1alpha1.CapturePhaseExpired:
		return 5
	}
	// The empty phase of an object whose status has never been written.
	return 0
}

// TransitionStep names a phase for the audit record's stable key, so the same
// transition re-evaluated after a restart converges on one record.
func TransitionStep(p trawlv1alpha1.CapturePhase) string {
	return "phase:" + string(p)
}

// JobState is what the controller found when it looked for the runner Job.
type JobState int

const (
	// JobAbsent means no Job with the capture's stable name exists.
	JobAbsent JobState = iota
	// JobActive means the Job exists and has not reached a terminal condition.
	JobActive
	// JobSucceeded means the Job reports Complete.
	JobSucceeded
	// JobFailed means the Job reports Failed.
	JobFailed
)

// JobObservation carries the Job's state plus what the controller could learn
// about why it ended.
type JobObservation struct {
	State JobState
	// Reason is the Job's terminal condition reason, when it has one:
	// DeadlineExceeded, BackoffLimitExceeded.
	Reason string
	// ExitCode is the runner container's exit code, when the pod still exists
	// to be asked.
	ExitCode *int32
}

// ArtifactState is what the controller found in object storage.
type ArtifactState int

const (
	// ArtifactUnknown means storage was not consulted. It is only acceptable
	// while the runner is still active.
	ArtifactUnknown ArtifactState = iota
	// ArtifactAbsent means neither the object nor the manifest exists.
	ArtifactAbsent
	// ArtifactPresent means the object exists but could not be verified: the
	// manifest is missing or unreadable.
	ArtifactPresent
	// ArtifactVerified means object and manifest agree on size and checksum.
	ArtifactVerified
	// ArtifactMismatch means they exist and disagree.
	ArtifactMismatch
	// ArtifactUnavailable means storage could not be consulted.
	ArtifactUnavailable
)

// ArtifactObservation carries the verified manifest and the object identity
// storage reported, for the status the controller writes at Completed.
type ArtifactObservation struct {
	State     ArtifactState
	Manifest  *Manifest
	Key       string
	ETag      string
	VersionID string
}

// TargetState is whether the capture's tap and node can host a runner now.
type TargetState int

const (
	// TargetUnknown means the tap was not consulted; only acceptable once a
	// runner exists, since the Job then answers for itself.
	TargetUnknown TargetState = iota
	// TargetEligible means the tap is Active or Degraded and the node reported
	// a fresh heartbeat.
	TargetEligible
	// TargetTapMissing means no tap of that name exists.
	TargetTapMissing
	// TargetTapDeleting means the tap has a deletion timestamp.
	TargetTapDeleting
	// TargetTapInactive means the tap exists but is not Active or Degraded for
	// its current generation.
	TargetTapInactive
	// TargetUnavailable means the tap is fine but the node is not one of its
	// targets, or its heartbeat is stale.
	TargetUnavailable
)

// TargetObservation carries the resolved identity the runner will use.
type TargetObservation struct {
	State     TargetState
	TapUID    types.UID
	Interface string
}

// Observation is everything Evaluate needs, gathered by the controller.
type Observation struct {
	Now      time.Time
	Target   TargetObservation
	Job      JobObservation
	Artifact ArtifactObservation
}

// Action is the side effect an outcome asks the controller to perform.
type Action int

const (
	ActionNone Action = iota
	// ActionCreateJob renders and creates the runner Job.
	ActionCreateJob
	// ActionCleanupArtifact deletes the object and manifest after a failure.
	ActionCleanupArtifact
)

// Completion carries the facts the controller persists when a capture reaches
// Completed. They come from the verified manifest, never from the runner's
// unverified claim.
type Completion struct {
	StartedAt         time.Time
	EndedAt           time.Time
	CompletedAt       time.Time
	PacketCount       int64
	SizeBytes         int64
	SHA256            string
	Interface         string
	StopReason        trawlv1alpha1.CaptureStopReason
	Artifact          trawlv1alpha1.ArtifactReference
	RetentionDeadline time.Time
}

// Outcome is the phase and side effects the observed facts support.
type Outcome struct {
	Phase trawlv1alpha1.CapturePhase
	// Failure is set when Phase is Failed.
	Failure *trawlv1alpha1.CaptureFailure
	// Completion is set when Phase is Completed.
	Completion *Completion
	// ResolvedTapUID and ResolvedInterface are set with ActionCreateJob.
	ResolvedTapUID    types.UID
	ResolvedInterface string
	Action            Action
	// StorageUnavailable asks the controller to record that verification is
	// pending on storage, without failing the capture.
	StorageUnavailable bool
	// RequeueAfter is a hint for when to look again while waiting.
	RequeueAfter time.Duration
}

// storageRetry is how long to wait before asking storage again.
const storageRetry = 30 * time.Second

// jobReasonDeadlineExceeded is the batch Job condition reason for a Job that
// outlived its activeDeadlineSeconds.
const jobReasonDeadlineExceeded = "DeadlineExceeded"

// Evaluate returns the outcome the facts support for a CaptureJob.
//
// Precedence is object truth first: a verified artifact completes the capture
// whatever the Job says, because the artifact is the evidence and the Job is
// only how it was made. Then the Job's terminal state, then live progress
// from the reporter, then whether a runner should be created at all.
//
// staleHeartbeat is the tap heartbeat interval the eligibility grace window
// is derived from; a target is given twice that to report before the capture
// fails for want of one.
func Evaluate(job *trawlv1alpha1.CaptureJob, obs Observation, staleHeartbeat time.Duration) (Outcome, error) {
	current := job.Status.Phase
	if IsTerminal(current) {
		return Outcome{Phase: current}, nil
	}

	switch obs.Artifact.State {
	case ArtifactVerified:
		return complete(job, obs)
	case ArtifactMismatch:
		return fail(current, trawlv1alpha1.FailureArtifactMismatch,
			"the stored object does not match its manifest; it was removed", ActionCleanupArtifact), nil
	case ArtifactUnavailable:
		return Outcome{Phase: livePhase(job), StorageUnavailable: true, RequeueAfter: storageRetry}, nil
	}

	switch obs.Job.State {
	case JobSucceeded, JobFailed:
		return finishWithoutArtifact(job, obs)
	case JobActive:
		return Outcome{Phase: livePhase(job)}, nil
	}

	// No runner exists.
	if job.Status.RunnerJobRef != nil {
		return fail(current, trawlv1alpha1.FailureInternalError,
			"the runner Job disappeared before it finished; the capture cannot be resumed", ActionNone), nil
	}
	switch obs.Target.State {
	case TargetEligible:
		return Outcome{
			Phase:             trawlv1alpha1.CapturePhasePending,
			Action:            ActionCreateJob,
			ResolvedTapUID:    obs.Target.TapUID,
			ResolvedInterface: obs.Target.Interface,
		}, nil
	case TargetUnknown:
		return Outcome{}, errors.New("no runner exists and the target was not observed")
	}

	grace := 2 * staleHeartbeat
	waited := obs.Now.Sub(job.CreationTimestamp.Time)
	if waited < grace {
		return Outcome{Phase: trawlv1alpha1.CapturePhasePending, RequeueAfter: grace - waited}, nil
	}
	switch obs.Target.State {
	case TargetUnavailable:
		return fail(trawlv1alpha1.CapturePhasePending, trawlv1alpha1.FailureTargetUnavailable,
			"the target node is not an active target of the tap; check the tap's targets and the node's heartbeat", ActionNone), nil
	default:
		return fail(trawlv1alpha1.CapturePhasePending, trawlv1alpha1.FailureTapInactive,
			"the tap is not active; a capture needs an Active or Degraded tap with the target node reporting", ActionNone), nil
	}
}

// livePhase derives the non-terminal phase from the reporter's facts, never
// moving backwards from what status already says.
func livePhase(job *trawlv1alpha1.CaptureJob) trawlv1alpha1.CapturePhase {
	derived := trawlv1alpha1.CapturePhasePending
	switch {
	case job.Status.CaptureEndedAt != nil:
		derived = trawlv1alpha1.CapturePhaseStoring
	case job.Status.StartedAt != nil:
		derived = trawlv1alpha1.CapturePhaseCapturing
	}
	if rank(job.Status.Phase) > rank(derived) {
		return job.Status.Phase
	}
	return derived
}

func rank(p trawlv1alpha1.CapturePhase) int {
	switch p {
	case trawlv1alpha1.CapturePhasePending:
		return 1
	case trawlv1alpha1.CapturePhaseCapturing:
		return 2
	case trawlv1alpha1.CapturePhaseStoring:
		return 3
	}
	return 0
}

func complete(job *trawlv1alpha1.CaptureJob, obs Observation) (Outcome, error) {
	m := obs.Artifact.Manifest
	if m == nil {
		return Outcome{}, errors.New("artifact reported verified without a manifest")
	}
	deadline, err := RetentionDeadline(obs.Now, job.Spec.Retention)
	if err != nil {
		return Outcome{}, err
	}
	return Outcome{
		Phase: trawlv1alpha1.CapturePhaseCompleted,
		Completion: &Completion{
			StartedAt:   m.StartedAt,
			EndedAt:     m.EndedAt,
			CompletedAt: obs.Now,
			PacketCount: m.PacketCount,
			SizeBytes:   m.SizeBytes,
			SHA256:      m.SHA256,
			Interface:   m.Interface,
			StopReason:  m.StopReason,
			Artifact: trawlv1alpha1.ArtifactReference{
				Key:        obs.Artifact.Key,
				ETag:       obs.Artifact.ETag,
				VersionID:  obs.Artifact.VersionID,
				VerifiedAt: metaTime(obs.Now),
			},
			RetentionDeadline: deadline,
		},
	}, nil
}

// finishWithoutArtifact decides the failure for a Job that ended with nothing
// verifiable in storage. The reason comes from the most specific source that
// exists: the reporter's result, then the runner's exit code, then the Job's
// own condition.
func finishWithoutArtifact(job *trawlv1alpha1.CaptureJob, obs Observation) (Outcome, error) {
	phase := livePhase(job)
	switch obs.Artifact.State {
	case ArtifactUnknown:
		return Outcome{}, errors.New("the runner Job ended but the artifact was not observed")
	case ArtifactPresent:
		return fail(phase, trawlv1alpha1.FailureUploadFailed,
			"the runner stored an object without a manifest; it was removed", ActionCleanupArtifact), nil
	}

	if r := job.Status.RunnerResult; r != nil && r.Outcome == trawlv1alpha1.RunnerOutcomeFailed && r.Reason != "" {
		return fail(phase, r.Reason, "the runner reported "+string(r.Reason)+"; "+remedy(r.Reason), ActionNone), nil
	}
	if obs.Job.ExitCode != nil && *obs.Job.ExitCode != ExitOK {
		reason := FailureReasonForExitCode(*obs.Job.ExitCode)
		return fail(phase, reason, fmt.Sprintf("the runner exited with code %d (%s); %s", *obs.Job.ExitCode, reason, remedy(reason)), ActionNone), nil
	}
	if obs.Job.State == JobSucceeded {
		return fail(phase, trawlv1alpha1.FailureArtifactMissing,
			"the runner exited successfully but no artifact exists in storage", ActionNone), nil
	}
	if obs.Job.Reason == jobReasonDeadlineExceeded {
		if job.Status.StartedAt == nil {
			return fail(phase, trawlv1alpha1.FailureInternalError,
				"the runner did not start capturing within the startup budget; check image pulls and node scheduling", ActionNone), nil
		}
		return fail(phase, trawlv1alpha1.FailureCaptureFailed,
			"the runner exceeded its active deadline before storing the artifact", ActionNone), nil
	}
	return fail(phase, trawlv1alpha1.FailureInternalError,
		"the runner Job failed without a reported reason; inspect the Job's conditions", ActionNone), nil
}

func fail(phase trawlv1alpha1.CapturePhase, reason trawlv1alpha1.FailureReason, message string, action Action) Outcome {
	if phase == "" {
		phase = trawlv1alpha1.CapturePhasePending
	}
	return Outcome{
		Phase: trawlv1alpha1.CapturePhaseFailed,
		Failure: &trawlv1alpha1.CaptureFailure{
			Reason:      reason,
			Message:     message,
			FailedPhase: phase,
			Attempts:    1,
		},
		Action: action,
	}
}

// remedy is the operator action a failure reason points to. Messages are
// fixed strings so they can never carry tool output.
func remedy(reason trawlv1alpha1.FailureReason) string {
	switch reason {
	case trawlv1alpha1.FailureInvalidFilter:
		return "correct the BPF filter and create a new capture"
	case trawlv1alpha1.FailureInvalidBounds:
		return "the bounds could not be applied; create a new capture"
	case trawlv1alpha1.FailureInterfaceUnavailable:
		return "the interface could not be opened on the target node; check the tap's targets"
	case trawlv1alpha1.FailureSizeExceeded:
		return "the capture overshot its size bound and was discarded; lower the filter's scope"
	case trawlv1alpha1.FailureUploadFailed:
		return "the artifact could not be stored; check the artifact bucket and credentials"
	case trawlv1alpha1.FailureCaptureFailed:
		return "dumpcap ended abnormally; check the runner pod's termination state"
	default:
		return "inspect the runner pod's termination state"
	}
}

// Downloadable reports whether a capture may be served now.
//
// The retention deadline is exclusive: at the instant itself the answer is
// no. observedGeneration must match so a retention change the controller has
// not yet applied cannot be read as either an extension or a shortening.
func Downloadable(job *trawlv1alpha1.CaptureJob, now time.Time) bool {
	s := job.Status
	if s.Phase != trawlv1alpha1.CapturePhaseCompleted || s.Failure != nil {
		return false
	}
	if s.Artifact == nil || s.SHA256 == "" || s.RetentionDeadline == nil {
		return false
	}
	if !now.Before(s.RetentionDeadline.Time) {
		return false
	}
	if s.ObservedGeneration != job.Generation {
		return false
	}
	return status.IsTrue(s.Conditions, status.TypeArtifactVerified, job.Generation)
}

// RetentionDeadline is completedAt plus the retention period.
func RetentionDeadline(completedAt time.Time, retention string) (time.Time, error) {
	d, err := config.ParseDuration(retention)
	if err != nil {
		return time.Time{}, fmt.Errorf("retention: %w", err)
	}
	return completedAt.Add(d), nil
}
