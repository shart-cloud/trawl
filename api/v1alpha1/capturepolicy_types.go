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

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
// Exactly one body is populated, and it must be the one Type names. Enforcing
// that pairing is the webhook's job (T105); nothing here can express it, and a
// matcher handed a mismatched union treats it as no trigger at all rather than
// guessing which body was meant.
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
	// +listType=set
	Severities []int32 `json:"severities"`

	// RuleIDs optionally narrows to specific signature IDs.
	// +optional
	// +kubebuilder:validation:MaxItems=1000
	// +listType=set
	RuleIDs []int64 `json:"ruleIDs,omitempty"`

	// Categories optionally narrows to specific signature categories.
	// +optional
	// +kubebuilder:validation:MaxItems=100
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
	// +listType=set
	Reasons []string `json:"reasons"`

	// SourceNamespaces optionally narrows to flows leaving these namespaces.
	// +optional
	// +kubebuilder:validation:MaxItems=100
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
