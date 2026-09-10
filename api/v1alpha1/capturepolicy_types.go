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

// This file holds the parts of CapturePolicy that the pure logic in
// internal/policy is written against: the trigger union and the rate limit. The
// rest of the type - the CapturePolicy object itself, spec.tapRef, spec.armed,
// spec.capture, spec.retention, status, phases, conditions, print columns,
// defaults and the CEL validation markers - is T104, and belongs with the
// webhook that enforces it (T105).
//
// The split is deliberate rather than incidental. Matching and limit accounting
// are pure functions of a spec and some evidence, and they are testable long
// before there is a CRD to install or an API server to admit against. Defining
// the whole type first would have made those tests wait on validation machinery
// they do not exercise.

// CaptureTriggerType names the event source a policy evaluates.
//
// A closed enum with no default: a policy that matched "everything the worker
// happens to receive" would arm silently against sources the operator never
// reviewed. The union below carries exactly one body, named by this field.
// +kubebuilder:validation:Enum=SuricataAlert;HubbleDrop
type CaptureTriggerType string

const (
	// CaptureTriggerSuricataAlert evaluates Suricata signature observations
	// read from the sensor's log stream.
	CaptureTriggerSuricataAlert CaptureTriggerType = "SuricataAlert"

	// CaptureTriggerHubbleDrop evaluates denied cluster flows read from the
	// Hubble relay stream.
	CaptureTriggerHubbleDrop CaptureTriggerType = "HubbleDrop"
)

// CapturePolicyTrigger is the closed union of supported trigger types.
//
// Exactly one body is populated and it must be the one Type names. Both halves
// are enforced: without the presence rule a policy can name a type and supply
// nothing, which arms an object that can never match; without the exclusivity
// rule it can carry a second body that is silently ignored, so an operator who
// edits the wrong one sees no error and no change in behavior.
// +kubebuilder:validation:XValidation:rule="self.type != 'SuricataAlert' || has(self.suricataAlert)",message="trigger type SuricataAlert requires suricataAlert"
// +kubebuilder:validation:XValidation:rule="self.type != 'HubbleDrop' || has(self.hubbleDrop)",message="trigger type HubbleDrop requires hubbleDrop"
// +kubebuilder:validation:XValidation:rule="self.type == 'SuricataAlert' || !has(self.suricataAlert)",message="suricataAlert is only allowed when trigger type is SuricataAlert"
// +kubebuilder:validation:XValidation:rule="self.type == 'HubbleDrop' || !has(self.hubbleDrop)",message="hubbleDrop is only allowed when trigger type is HubbleDrop"
type CapturePolicyTrigger struct {
	// Type selects which body below is evaluated.
	// +kubebuilder:validation:Required
	Type CaptureTriggerType `json:"type"`

	// SuricataAlert is required when Type is SuricataAlert.
	// +optional
	SuricataAlert *SuricataAlertTrigger `json:"suricataAlert,omitempty"`

	// HubbleDrop is required when Type is HubbleDrop.
	// +optional
	HubbleDrop *HubbleDropTrigger `json:"hubbleDrop,omitempty"`
}

// SuricataAlertTrigger selects Suricata signature observations.
//
// Severities is required and the optional fields only narrow: a trigger with no
// rule IDs and no categories matches every alert at the listed severities. That
// direction matters. An empty list read as "match nothing" would silently
// disarm a policy an operator believed was armed, and the reverse - an omitted
// field widening the match - is the behavior an operator writing a severity
// filter expects.
type SuricataAlertTrigger struct {
	// Severities are the Suricata alert severities to match.
	//
	// Suricata's scale runs 1 (most severe) to 4, which is the reverse of what
	// most people assume, so the bound is enforced rather than documented.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=4
	// +kubebuilder:validation:items:Minimum=1
	// +kubebuilder:validation:items:Maximum=4
	// +listType=set
	Severities []int32 `json:"severities"`

	// RuleIDs optionally narrows to specific signature IDs.
	// +optional
	// +kubebuilder:validation:MaxItems=1000
	// +kubebuilder:validation:items:Minimum=0
	// +listType=set
	RuleIDs []int64 `json:"ruleIDs,omitempty"`

	// Categories optionally narrows to specific signature categories.
	// +optional
	// +kubebuilder:validation:MaxItems=100
	// +kubebuilder:validation:items:MaxLength=128
	// +listType=set
	Categories []string `json:"categories,omitempty"`
}

// HubbleDropTrigger selects denied cluster flows.
//
// Reasons is required for the same reason Severities is: a drop policy with no
// reasons would match every denied flow in the cluster, which on a busy cluster
// is a capture storm rather than a policy.
type HubbleDropTrigger struct {
	// Reasons are the Hubble drop reasons to match.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=100
	// +kubebuilder:validation:items:MaxLength=64
	// +listType=set
	Reasons []string `json:"reasons"`

	// SourceNamespaces optionally narrows to flows leaving these namespaces.
	// +optional
	// +kubebuilder:validation:MaxItems=100
	// +kubebuilder:validation:items:MaxLength=253
	// +listType=set
	SourceNamespaces []string `json:"sourceNamespaces,omitempty"`

	// Threshold optionally requires a sustained rate rather than a single flow.
	//
	// Absent means one matching flow triggers. Present means the policy waits
	// for Count flows within Window before it does.
	// +optional
	Threshold *DropThreshold `json:"threshold,omitempty"`
}

// DropThreshold is a count of matching flows within a rolling window.
//
// The window's bounds are a CEL rule rather than a pattern, because the pattern
// that shapes the string cannot express a range over what it denotes: it admits
// both "0s" and "600m". Neither is a wrong-looking value that fails loudly. A
// zero window expires every event that is not simultaneous with the newest, so
// a count of five can never be reached and the policy silently never fires; a
// window past the reconnect replay bound cannot be rebuilt after a disconnect,
// so it under-counts with nothing to say it did.
// +kubebuilder:validation:XValidation:rule="duration(self.window) >= duration('1s') && duration(self.window) <= duration('15m')",message="window must be between 1s and 15m"
type DropThreshold struct {
	// Count is how many matching flows must fall inside Window.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=10000
	Count int32 `json:"count"`

	// Window is the rolling period the count is measured over.
	//
	// Bounded at both ends: a window below a second cannot be measured
	// meaningfully against event timestamps that arrive with skew, and one
	// above fifteen minutes holds more flow state than the worker should carry
	// per policy.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:Pattern=`^([0-9]+(s|m))+$`
	Window metav1.Duration `json:"window"`
}

// CaptureRateLimit bounds how often a policy may capture.
//
// Both fields are required and both are bounded, because this is the only thing
// standing between a noisy signature and a capture storm that fills the
// artifact bucket. An unbounded policy is not a useful default even for a
// careful operator: the traffic decides how often it fires, and the traffic is
// not under the operator's control.
type CaptureRateLimit struct {
	// MaxCapturesPerHour is how many captures this policy may request in any
	// trailing hour.
	//
	// Counted from the CaptureJobs the policy created rather than from a
	// running total, so the bound survives a restart or a leader handoff.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=100
	MaxCapturesPerHour int32 `json:"maxCapturesPerHour"`

	// Cooldown is the window within which equivalent traffic collapses to one
	// capture.
	//
	// It shapes the deduplication bucket rather than gating the policy as a
	// whole: FR-031 scopes it to "the equivalent source and traffic", so two
	// unrelated flows matching the same policy are not held back by each other.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:Pattern=`^([0-9]+(s|m|h))+$`
	Cooldown metav1.Duration `json:"cooldown"`
}

// PolicyCaptureBounds is the capture a policy requests when it fires.
//
// The same bounds a manual request carries, minus the target: a policy does not
// name a node, because the node is whichever one observed the traffic and is
// only known at trigger time.
type PolicyCaptureBounds struct {
	// Duration bounds wall-clock capture time, 1s to 1h.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^([0-9]+(ms|s|m|h))+$`
	Duration string `json:"duration"`

	// FilterTemplate is a BPF expression that may carry the documented typed
	// placeholders, which are substituted from the triggering event.
	//
	// Not a Go template. The rendered string becomes the expression the capture
	// runner executes, and the values substituted into it describe traffic an
	// attacker sends, so the placeholder set is closed and each value is
	// validated as the type it claims to be (internal/policy/template.go).
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	FilterTemplate string `json:"filterTemplate,omitempty"`

	// Snaplen bounds bytes kept per packet; 0 means whole packets.
	// +kubebuilder:default=0
	// +optional
	Snaplen int32 `json:"snaplen,omitempty"`

	// MaxSize bounds the artifact, 1Mi to 1Gi. Whichever of Duration and
	// MaxSize is reached first ends the capture.
	// +kubebuilder:validation:Required
	MaxSize resource.Quantity `json:"maxSize"`
}

// CapturePolicySpec is an operator's rule mapping one trigger to bounded
// capture behavior.
type CapturePolicySpec struct {
	// TapRef names the NetworkTap whose traffic this policy watches, in the
	// same namespace.
	// +kubebuilder:validation:Required
	TapRef corev1.LocalObjectReference `json:"tapRef"`

	// Armed says whether the policy evaluates events at all.
	//
	// Defaults false so that creating a policy is never the same act as
	// switching it on. An operator writing a trigger for the first time gets to
	// read it back before it can start collecting packets.
	// +kubebuilder:default=false
	// +optional
	Armed bool `json:"armed,omitempty"`

	// Trigger is the event condition that fires this policy.
	// +kubebuilder:validation:Required
	Trigger CapturePolicyTrigger `json:"trigger"`

	// Capture is the bounded capture requested when the trigger fires.
	// +kubebuilder:validation:Required
	Capture PolicyCaptureBounds `json:"capture"`

	// Retention is how long each artifact is kept after completion, 1h to 30d,
	// further capped by the installation's captureRetentionCeiling.
	// +kubebuilder:default="30d"
	// +kubebuilder:validation:Pattern=`^([0-9]+(ms|s|m|h))+$|^[0-9]+d$`
	// +optional
	Retention string `json:"retention,omitempty"`

	// RateLimit bounds how often this policy may capture.
	// +kubebuilder:validation:Required
	RateLimit CaptureRateLimit `json:"rateLimit"`
}

// CapturePolicyPhase is the operational position of a policy.
// +kubebuilder:validation:Enum=Disarmed;Armed;Degraded;RateLimited
type CapturePolicyPhase string

const (
	// CapturePolicyDisarmed means the policy evaluates no events.
	CapturePolicyDisarmed CapturePolicyPhase = "Disarmed"

	// CapturePolicyArmed means the policy is evaluating events normally.
	CapturePolicyArmed CapturePolicyPhase = "Armed"

	// CapturePolicyDegraded means the policy is armed but its event source is
	// not delivering, so absence of captures is not evidence of absence of
	// traffic.
	CapturePolicyDegraded CapturePolicyPhase = "Degraded"

	// CapturePolicyRateLimited means the hourly ceiling is reached. The policy
	// recovers on its own as captures age out of the trailing hour.
	CapturePolicyRateLimited CapturePolicyPhase = "RateLimited"
)

// PolicyDecisionCounters count what the policy decided, by outcome.
//
// Monotonic for a policy UID and rebuildable from the CaptureJobs it created
// plus its checkpoints, so a restart does not reset the record of what the
// policy has been doing.
type PolicyDecisionCounters struct {
	// Matched is qualifying events that produced a capture request.
	// +optional
	Matched int64 `json:"matched,omitempty"`

	// NotMatched is events evaluated and declined.
	// +optional
	NotMatched int64 `json:"notMatched,omitempty"`

	// Duplicate is qualifying events collapsed into an existing capture.
	// +optional
	Duplicate int64 `json:"duplicate,omitempty"`

	// RateLimited is qualifying events refused by the hourly ceiling.
	// +optional
	RateLimited int64 `json:"rateLimited,omitempty"`

	// Failed is qualifying events whose capture could not be requested.
	// +optional
	Failed int64 `json:"failed,omitempty"`
}

// CapturePolicyStatus is what the event worker observed about a policy.
type CapturePolicyStatus struct {
	// ObservedGeneration is the spec generation being evaluated.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Phase is the policy's operational position.
	// +optional
	Phase CapturePolicyPhase `json:"phase,omitempty"`

	// ResolvedTapUID is the tap identity bound for the current generation. A
	// tap deleted and recreated under the same name is a different tap, and
	// the UID is what makes that visible.
	// +optional
	ResolvedTapUID types.UID `json:"resolvedTapUID,omitempty"`

	// TotalCaptures is how many unique captures this policy has requested.
	// +optional
	TotalCaptures int64 `json:"totalCaptures,omitempty"`

	// ActiveCaptures is how many of its captures have not reached a terminal
	// phase.
	// +optional
	ActiveCaptures int32 `json:"activeCaptures,omitempty"`

	// LastTriggerTime is the last matching event, including one whose capture
	// was suppressed. A policy that is matching but suppressing is working;
	// one that is not matching at all is a different problem, and the two
	// would otherwise look identical.
	// +optional
	LastTriggerTime *metav1.Time `json:"lastTriggerTime,omitempty"`

	// LastCaptureRef is the most recent capture created or deduplicated into.
	// +optional
	LastCaptureRef *corev1.LocalObjectReference `json:"lastCaptureRef,omitempty"`

	// Decisions counts outcomes by kind.
	// +optional
	Decisions PolicyDecisionCounters `json:"decisions,omitempty"`

	// Conditions carry the detailed reasons behind Phase.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=cpolicy;cpolicies
// +kubebuilder:printcolumn:name="Armed",type=boolean,JSONPath=`.spec.armed`
// +kubebuilder:printcolumn:name="Trigger",type=string,JSONPath=`.spec.trigger.type`
// +kubebuilder:printcolumn:name="Tap",type=string,JSONPath=`.spec.tapRef.name`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Captures",type=integer,JSONPath=`.status.totalCaptures`
// +kubebuilder:printcolumn:name="Active",type=integer,JSONPath=`.status.activeCaptures`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// CapturePolicy arms one trigger against one tap with bounded capture behavior.
type CapturePolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CapturePolicySpec   `json:"spec,omitempty"`
	Status CapturePolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// CapturePolicyList contains a list of CapturePolicy.
type CapturePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CapturePolicy `json:"items"`
}
