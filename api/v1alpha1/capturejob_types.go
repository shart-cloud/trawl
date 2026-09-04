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

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// AnnotationRequester carries the authenticated username that created the
// CaptureJob. The admission webhook stamps it from the API server's user info
// and refuses later changes, so it is provenance rather than a claim.
const AnnotationRequester = "trawl.cloud/requester"

// CaptureRequestType says who asked for a capture.
//
// Policy is accepted only from the event worker's identity: a user who could
// mark a manual request as policy-originated could make evidence look like it
// was collected automatically under a reviewed policy when it was not.
// +kubebuilder:validation:Enum=Manual;Policy
type CaptureRequestType string

const (
	// CaptureRequestManual is a capture an analyst asked for directly.
	CaptureRequestManual CaptureRequestType = "Manual"

	// CaptureRequestPolicy is a capture the event worker created because a
	// CapturePolicy trigger matched.
	CaptureRequestPolicy CaptureRequestType = "Policy"
)

// CapturePhase is the lifecycle position of a CaptureJob.
//
// Completed is deliberately unreachable until the stored artifact has been
// verified by size and checksum; an analyst downloading a "Completed" capture
// must get exactly the bytes the runner hashed.
// +kubebuilder:validation:Enum=Pending;Capturing;Storing;Completed;Failed;Expired
type CapturePhase string

const (
	// CapturePhasePending means the request is accepted and a runner has not
	// yet opened the capture socket.
	CapturePhasePending CapturePhase = "Pending"

	// CapturePhaseCapturing means packets are being written on the target node.
	CapturePhaseCapturing CapturePhase = "Capturing"

	// CapturePhaseStoring means capture ended and the artifact is being
	// uploaded or verified.
	CapturePhaseStoring CapturePhase = "Storing"

	// CapturePhaseCompleted means a verified artifact exists and is
	// downloadable until its retention deadline.
	CapturePhaseCompleted CapturePhase = "Completed"

	// CapturePhaseFailed is terminal. A failed capture is never downloadable.
	CapturePhaseFailed CapturePhase = "Failed"

	// CapturePhaseExpired means the retention deadline passed and deletion of
	// the artifact was verified.
	CapturePhaseExpired CapturePhase = "Expired"
)

// FailureReason is the closed enum of why a capture failed.
//
// Dashboards and the audit ledger group by this value, so a free-form reason
// would be a cardinality bug. The sanitized detail goes in the message.
// +kubebuilder:validation:Enum=InvalidFilter;InvalidBounds;TapInactive;TargetUnavailable;InterfaceUnavailable;RunnerCreateFailed;CaptureFailed;SizeExceeded;UploadFailed;ArtifactMissing;ArtifactMismatch;RetentionDeleteFailed;InternalError
type FailureReason string

const (
	FailureInvalidFilter         FailureReason = "InvalidFilter"
	FailureInvalidBounds         FailureReason = "InvalidBounds"
	FailureTapInactive           FailureReason = "TapInactive"
	FailureTargetUnavailable     FailureReason = "TargetUnavailable"
	FailureInterfaceUnavailable  FailureReason = "InterfaceUnavailable"
	FailureRunnerCreateFailed    FailureReason = "RunnerCreateFailed"
	FailureCaptureFailed         FailureReason = "CaptureFailed"
	FailureSizeExceeded          FailureReason = "SizeExceeded"
	FailureUploadFailed          FailureReason = "UploadFailed"
	FailureArtifactMissing       FailureReason = "ArtifactMissing"
	FailureArtifactMismatch      FailureReason = "ArtifactMismatch"
	FailureRetentionDeleteFailed FailureReason = "RetentionDeleteFailed"
	FailureInternalError         FailureReason = "InternalError"
)

// CaptureStopReason says which bound ended a capture.
//
// dumpcap does not report which autostop condition fired, so the runner infers
// it from the output size and elapsed time. Error covers an exit that matched
// neither, which is worth distinguishing from a bound that did its job.
// +kubebuilder:validation:Enum=Duration;Size;Cancelled;Error
type CaptureStopReason string

const (
	CaptureStopDuration  CaptureStopReason = "Duration"
	CaptureStopSize      CaptureStopReason = "Size"
	CaptureStopCancelled CaptureStopReason = "Cancelled"
	CaptureStopError     CaptureStopReason = "Error"
)

// RunnerOutcome is the runner's own verdict on its execution.
// +kubebuilder:validation:Enum=Succeeded;Failed
type RunnerOutcome string

const (
	RunnerOutcomeSucceeded RunnerOutcome = "Succeeded"
	RunnerOutcomeFailed    RunnerOutcome = "Failed"
)

// TriggerSource names the event stream that fired a policy.
// +kubebuilder:validation:Enum=SuricataAlert;HubbleDrop
type TriggerSource string

const (
	TriggerSourceSuricataAlert TriggerSource = "SuricataAlert"
	TriggerSourceHubbleDrop    TriggerSource = "HubbleDrop"
)

// ImmutablePolicyReference pins the exact policy generation that created a
// job, so a later policy edit cannot rewrite why evidence was collected.
type ImmutablePolicyReference struct {
	// Name is the CapturePolicy name in the same namespace.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// UID is the policy's UID at trigger time.
	UID types.UID `json:"uid"`

	// Generation is the policy spec generation that was armed.
	// +kubebuilder:validation:Minimum=1
	Generation int64 `json:"generation"`
}

// FlowSnapshot is the 5-tuple the trigger matched on, copied at trigger time.
type FlowSnapshot struct {
	// +kubebuilder:validation:MaxLength=45
	// +optional
	SourceIP string `json:"sourceIP,omitempty"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	// +optional
	SourcePort int32 `json:"sourcePort,omitempty"`
	// +kubebuilder:validation:MaxLength=45
	// +optional
	DestinationIP string `json:"destinationIP,omitempty"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	// +optional
	DestinationPort int32 `json:"destinationPort,omitempty"`
	// +kubebuilder:validation:MaxLength=16
	// +optional
	Protocol string `json:"protocol,omitempty"`
	// +kubebuilder:validation:MaxLength=128
	// +optional
	CommunityID string `json:"communityID,omitempty"`
}

// SuricataTriggerContext is the alert that fired, minus any payload.
type SuricataTriggerContext struct {
	// +kubebuilder:validation:Minimum=0
	RuleID int64 `json:"ruleID"`
	// +kubebuilder:validation:Minimum=0
	// +optional
	Revision int32 `json:"revision,omitempty"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=4
	Severity int32 `json:"severity"`
	// +kubebuilder:validation:MaxLength=128
	// +optional
	Category string `json:"category,omitempty"`
	// +kubebuilder:validation:MaxLength=512
	// +optional
	Message string `json:"message,omitempty"`
}

// HubbleTriggerContext is the drop verdict that fired.
type HubbleTriggerContext struct {
	// +kubebuilder:validation:MaxLength=64
	Reason string `json:"reason"`
	// +kubebuilder:validation:MaxLength=253
	// +optional
	SourceNamespace string `json:"sourceNamespace,omitempty"`
	// +kubebuilder:validation:MaxLength=253
	// +optional
	DestinationNamespace string `json:"destinationNamespace,omitempty"`
	// +kubebuilder:validation:Minimum=1
	// +optional
	Count int32 `json:"count,omitempty"`
}

// TriggerSnapshot records what fired a policy, copied at trigger time so the
// job explains itself after the source event has aged out of Loki.
// +kubebuilder:validation:XValidation:rule="self.source != 'SuricataAlert' || has(self.suricata)",message="source SuricataAlert requires suricata"
// +kubebuilder:validation:XValidation:rule="self.source != 'HubbleDrop' || has(self.hubble)",message="source HubbleDrop requires hubble"
type TriggerSnapshot struct {
	// Source is which event stream produced the trigger.
	Source TriggerSource `json:"source"`

	// Fingerprint is the deduplication fingerprint of the triggering event.
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	Fingerprint string `json:"fingerprint"`

	// EventTime is when the source says the event happened.
	EventTime metav1.Time `json:"eventTime"`

	// ObservedAt is when the event worker saw it.
	ObservedAt metav1.Time `json:"observedAt"`

	// Flow is the matched 5-tuple.
	// +optional
	Flow *FlowSnapshot `json:"flow,omitempty"`

	// Suricata carries alert context when Source is SuricataAlert.
	// +optional
	Suricata *SuricataTriggerContext `json:"suricata,omitempty"`

	// Hubble carries drop context when Source is HubbleDrop.
	// +optional
	Hubble *HubbleTriggerContext `json:"hubble,omitempty"`
}

// CaptureJobSpec asks for one bounded packet capture.
//
// Every execution field is immutable: a capture whose filter or bounds changed
// after it ran would be evidence of something other than what the status
// describes. The rules are CEL so the API server enforces them even if the
// webhook is down. Retention is the single exception and is gated by the
// webhook on caller identity and deadline.
//
// Durations are Go duration strings; retention additionally accepts whole
// days (`30d`). CEL's duration() does not know `d`, so the day form is
// range-checked on its integer prefix.
// +kubebuilder:validation:XValidation:rule="self.requestType == oldSelf.requestType",message="requestType is immutable"
// +kubebuilder:validation:XValidation:rule="self.tapRef == oldSelf.tapRef",message="tapRef is immutable"
// +kubebuilder:validation:XValidation:rule="has(self.targetNode) == has(oldSelf.targetNode) && (!has(self.targetNode) || self.targetNode == oldSelf.targetNode)",message="targetNode is immutable"
// +kubebuilder:validation:XValidation:rule="has(self.filter) == has(oldSelf.filter) && (!has(self.filter) || self.filter == oldSelf.filter)",message="filter is immutable"
// +kubebuilder:validation:XValidation:rule="self.duration == oldSelf.duration",message="duration is immutable"
// +kubebuilder:validation:XValidation:rule="self.snaplen == oldSelf.snaplen",message="snaplen is immutable"
// +kubebuilder:validation:XValidation:rule="string(self.maxSize) == string(oldSelf.maxSize)",message="maxSize is immutable"
// +kubebuilder:validation:XValidation:rule="has(self.policyRef) == has(oldSelf.policyRef) && (!has(self.policyRef) || self.policyRef == oldSelf.policyRef)",message="policyRef is immutable"
// +kubebuilder:validation:XValidation:rule="has(self.trigger) == has(oldSelf.trigger) && (!has(self.trigger) || self.trigger == oldSelf.trigger)",message="trigger is immutable"
// +kubebuilder:validation:XValidation:rule="has(self.deduplicationKey) == has(oldSelf.deduplicationKey) && (!has(self.deduplicationKey) || self.deduplicationKey == oldSelf.deduplicationKey)",message="deduplicationKey is immutable"
// +kubebuilder:validation:XValidation:rule="self.requestType != 'Manual' || has(self.targetNode)",message="requestType Manual requires targetNode"
// +kubebuilder:validation:XValidation:rule="self.requestType != 'Manual' || (!has(self.policyRef) && !has(self.trigger) && !has(self.deduplicationKey))",message="requestType Manual forbids policyRef, trigger, and deduplicationKey"
// +kubebuilder:validation:XValidation:rule="self.requestType != 'Policy' || (has(self.policyRef) && has(self.trigger) && has(self.deduplicationKey))",message="requestType Policy requires policyRef, trigger, and deduplicationKey"
// +kubebuilder:validation:XValidation:rule="duration(self.duration) >= duration('1s') && duration(self.duration) <= duration('1h')",message="duration must be between 1s and 1h"
// +kubebuilder:validation:XValidation:rule="self.snaplen == 0 || (self.snaplen >= 64 && self.snaplen <= 262144)",message="snaplen must be 0 or between 64 and 262144"
// +kubebuilder:validation:XValidation:rule="quantity(string(self.maxSize)).compareTo(quantity('1Mi')) >= 0 && quantity(string(self.maxSize)).compareTo(quantity('1Gi')) <= 0",message="maxSize must be between 1Mi and 1Gi"
// +kubebuilder:validation:XValidation:rule="self.retention.endsWith('d') ? (int(self.retention.substring(0, size(self.retention) - 1)) >= 1 && int(self.retention.substring(0, size(self.retention) - 1)) <= 30) : (duration(self.retention) >= duration('1h') && duration(self.retention) <= duration('720h'))",message="retention must be between 1h and 30d"
type CaptureJobSpec struct {
	// RequestType says whether an analyst or a policy asked for this capture.
	// +kubebuilder:default=Manual
	// +optional
	RequestType CaptureRequestType `json:"requestType,omitempty"`

	// TapRef names the NetworkTap whose interface is captured. The tap must
	// be observing on the target node when the job is scheduled; afterwards
	// the tap's fate does not affect the capture.
	// +kubebuilder:validation:Required
	TapRef corev1.LocalObjectReference `json:"tapRef"`

	// TargetNode is the node to capture on. Required for Manual requests; a
	// Policy request may omit it only to record that target resolution failed.
	// +kubebuilder:validation:MaxLength=253
	// +optional
	TargetNode string `json:"targetNode,omitempty"`

	// Filter is a BPF expression. Its syntax is checked structurally here and
	// compiled by the runner before any packet is read; an empty filter
	// captures everything the bounds allow.
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	Filter string `json:"filter,omitempty"`

	// Duration bounds wall-clock capture time, 1s to 1h.
	// +kubebuilder:validation:Pattern=`^([0-9]+(ms|s|m|h))+$`
	Duration string `json:"duration"`

	// Snaplen bounds bytes kept per packet; 0 means whole packets.
	// +kubebuilder:default=0
	// +optional
	Snaplen int32 `json:"snaplen,omitempty"`

	// MaxSize bounds the artifact, 1Mi to 1Gi. Whichever of Duration and
	// MaxSize is reached first ends the capture.
	MaxSize resource.Quantity `json:"maxSize"`

	// Retention is how long the artifact is kept after completion, 1h to
	// 30d, further capped by the installation's captureRetentionCeiling.
	// +kubebuilder:default="30d"
	// +kubebuilder:validation:Pattern=`^([0-9]+(ms|s|m|h))+$|^[0-9]+d$`
	// +optional
	Retention string `json:"retention,omitempty"`

	// PolicyRef pins the policy generation that created a Policy request.
	// +optional
	PolicyRef *ImmutablePolicyReference `json:"policyRef,omitempty"`

	// Trigger records what fired the policy.
	// +optional
	Trigger *TriggerSnapshot `json:"trigger,omitempty"`

	// DeduplicationKey identifies the trigger window this job answers, so a
	// repeated event does not produce a second capture.
	// +kubebuilder:validation:Pattern=`^sha256:[0-9a-f]{64}$`
	// +optional
	DeduplicationKey string `json:"deduplicationKey,omitempty"`
}

// ArtifactReference locates the verified artifact. The key is opaque and
// controller-derived; a client never composes it.
type ArtifactReference struct {
	// Profile is the installation storage profile the artifact lives in.
	Profile string `json:"profile"`

	// Key is the object key inside the profile's bucket.
	Key string `json:"key"`

	// ETag is the object's ETag when the store returned one.
	// +optional
	ETag string `json:"etag,omitempty"`

	// VersionID is the object version when the bucket is versioned.
	// +optional
	VersionID string `json:"versionID,omitempty"`

	// VerifiedAt is when the controller last confirmed size and checksum
	// against the stored object.
	VerifiedAt metav1.Time `json:"verifiedAt"`
}

// CaptureFailure explains a terminal failure.
type CaptureFailure struct {
	// Reason is the closed-enum cause.
	Reason FailureReason `json:"reason"`

	// Message is sanitized detail, bounded so a tool's stderr cannot become
	// an unbounded status field.
	// +kubebuilder:validation:MaxLength=512
	// +optional
	Message string `json:"message,omitempty"`

	// FailedPhase is the phase the job was in when it failed.
	// +kubebuilder:validation:Enum=Pending;Capturing;Storing
	FailedPhase CapturePhase `json:"failedPhase"`

	// Attempts counts runner executions. It is 1 in this release; the field
	// exists so a retry policy later is additive.
	// +kubebuilder:validation:Minimum=0
	// +optional
	Attempts int32 `json:"attempts,omitempty"`
}

// RunnerResult is the runner's terminal outcome, relayed by the reporter.
//
// The controller owns failure and phase, but once the runner pod is gone the
// only durable record of why it stopped is what the reporter relayed here.
// The controller treats these as claims to verify against the stored object,
// never as verification itself.
type RunnerResult struct {
	// Outcome is the runner's own verdict.
	Outcome RunnerOutcome `json:"outcome"`

	// Reason is set when Outcome is Failed.
	// +optional
	Reason FailureReason `json:"reason,omitempty"`

	// StopReason is which bound ended capture.
	// +optional
	StopReason CaptureStopReason `json:"stopReason,omitempty"`

	// PacketCount is the number of packets the runner counted in the file.
	// +optional
	PacketCount *int64 `json:"packetCount,omitempty"`

	// SizeBytes is the artifact size the runner uploaded.
	// +optional
	SizeBytes *int64 `json:"sizeBytes,omitempty"`

	// SHA256 is the hex digest the runner computed.
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
	// +optional
	SHA256 string `json:"sha256,omitempty"`

	// ExitCode is the runner process exit code.
	// +optional
	ExitCode int32 `json:"exitCode,omitempty"`

	// Message is sanitized detail.
	// +kubebuilder:validation:MaxLength=512
	// +optional
	Message string `json:"message,omitempty"`
}

// CaptureJobStatus is the observed state.
//
// Field ownership is split between two writers and enforced by server-side
// apply field management: the reporter sidecar owns resolvedInterface,
// startedAt, captureEndedAt, runnerResult, and the FilterValid and
// CaptureStarted conditions; the controller owns everything else.
type CaptureJobStatus struct {
	// ObservedGeneration is the spec generation this status describes.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Phase is the lifecycle position.
	// +optional
	Phase CapturePhase `json:"phase,omitempty"`

	// ResolvedTapUID is the UID of the tap at scheduling time, so a tap
	// recreated under the same name is not mistaken for the one captured.
	// +optional
	ResolvedTapUID types.UID `json:"resolvedTapUID,omitempty"`

	// ResolvedInterface is the interface the runner opened.
	// +optional
	ResolvedInterface string `json:"resolvedInterface,omitempty"`

	// RunnerJobRef names the batch Job executing the capture.
	// +optional
	RunnerJobRef *corev1.LocalObjectReference `json:"runnerJobRef,omitempty"`

	// RequestedAt is when the request was accepted.
	// +optional
	RequestedAt *metav1.Time `json:"requestedAt,omitempty"`

	// StartedAt is when the capture socket opened (node clock).
	// +optional
	StartedAt *metav1.Time `json:"startedAt,omitempty"`

	// CaptureEndedAt is when the capture stopped (node clock).
	// +optional
	CaptureEndedAt *metav1.Time `json:"captureEndedAt,omitempty"`

	// CompletedAt is when the artifact was verified (controller clock). The
	// retention deadline is computed from it.
	// +optional
	CompletedAt *metav1.Time `json:"completedAt,omitempty"`

	// PacketCount is the verified packet count. Zero is a real answer and is
	// distinguishable from unknown.
	// +optional
	PacketCount *int64 `json:"packetCount,omitempty"`

	// SizeBytes is the verified artifact size.
	// +optional
	SizeBytes *int64 `json:"sizeBytes,omitempty"`

	// SHA256 is the verified hex digest of the artifact.
	// +kubebuilder:validation:Pattern=`^[0-9a-f]{64}$`
	// +optional
	SHA256 string `json:"sha256,omitempty"`

	// Artifact locates the verified object.
	// +optional
	Artifact *ArtifactReference `json:"artifact,omitempty"`

	// RetentionDeadline is completedAt + spec.retention. Downloads are denied
	// from this instant.
	// +optional
	RetentionDeadline *metav1.Time `json:"retentionDeadline,omitempty"`

	// Failure explains a Failed phase.
	// +optional
	Failure *CaptureFailure `json:"failure,omitempty"`

	// RunnerResult is the runner's relayed terminal outcome.
	// +optional
	RunnerResult *RunnerResult `json:"runnerResult,omitempty"`

	// Conditions carry the detailed reasons behind Phase.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=capture;captures
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.requestType`
// +kubebuilder:printcolumn:name="Tap",type=string,JSONPath=`.spec.tapRef.name`
// +kubebuilder:printcolumn:name="Node",type=string,JSONPath=`.spec.targetNode`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Size",type=integer,JSONPath=`.status.sizeBytes`
// +kubebuilder:printcolumn:name="Expires",type=date,JSONPath=`.status.retentionDeadline`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// CaptureJob requests one bounded packet capture and records its evidence.
type CaptureJob struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CaptureJobSpec   `json:"spec,omitempty"`
	Status CaptureJobStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// CaptureJobList contains a list of CaptureJob.
type CaptureJobList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CaptureJob `json:"items"`
}
