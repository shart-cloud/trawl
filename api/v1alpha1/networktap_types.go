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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TapMode is the observation mode of a NetworkTap.
//
// Passive is the only member in this release, and the field exists rather than
// being implied so that adding an inline mode later is a visible API change
// requiring the separate approved specification the constitution demands
// (FR-003). A tap that silently became inline would be the exact failure
// Principle I is written to prevent.
// +kubebuilder:validation:Enum=Passive
type TapMode string

// TapModePassive observes traffic without modifying, blocking, delaying, or
// redirecting it.
const TapModePassive TapMode = "Passive"

// TapSourceType selects which source branch of the spec applies.
// +kubebuilder:validation:Enum=MirrorInterface;NodeInterface
type TapSourceType string

const (
	// TapSourceMirrorInterface observes a physical mirror (SPAN) interface on
	// exactly one node.
	TapSourceMirrorInterface TapSourceType = "MirrorInterface"

	// TapSourceNodeInterface observes a node interface on one or more nodes.
	TapSourceNodeInterface TapSourceType = "NodeInterface"
)

// TapPhase is the aggregate state of a NetworkTap.
// +kubebuilder:validation:Enum=Pending;Active;Degraded;Error
type TapPhase string

const (
	// TapPhasePending means the tap is validated but not yet observing.
	TapPhasePending TapPhase = "Pending"

	// TapPhaseActive means every selected target and requested analyzer is
	// healthy. It is deliberately the strictest phase: a partially working tap
	// reports Degraded, because an analyst reading "Active" must be able to
	// trust that the evidence is complete.
	TapPhaseActive TapPhase = "Active"

	// TapPhaseDegraded means monitoring is running but incomplete.
	TapPhaseDegraded TapPhase = "Degraded"

	// TapPhaseError means the tap is invalid or its dependencies are wholly
	// unavailable.
	TapPhaseError TapPhase = "Error"
)

// DuplicationState reports whether duplicate observations are suspected on a
// target.
//
// Unknown is a real answer, not a placeholder: mirrored and overlay traffic can
// legitimately duplicate packets, and the fingerprint window is bounded, so an
// evicted or incomplete fingerprint must not be reported as NotDetected.
// Claiming the absence of duplicates we did not actually establish would
// mislead an analyst counting observations.
// +kubebuilder:validation:Enum=Unknown;NotDetected;Suspected
type DuplicationState string

const (
	DuplicationUnknown     DuplicationState = "Unknown"
	DuplicationNotDetected DuplicationState = "NotDetected"
	DuplicationSuspected   DuplicationState = "Suspected"
)

// AnalyzerName identifies an analyzer.
// +kubebuilder:validation:Enum=Suricata;Zeek
type AnalyzerName string

const (
	AnalyzerSuricata AnalyzerName = "Suricata"
	AnalyzerZeek     AnalyzerName = "Zeek"
)

// InterfaceSource describes where packets are observed.
type InterfaceSource struct {
	// Interface is the Linux interface name to observe.
	//
	// Bounded to 15 bytes by IFNAMSIZ, and pattern-checked because this value
	// reaches a capture process argument. Validating it here means a malformed
	// name is rejected at admission rather than becoming a pod that crash-loops.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=15
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9][A-Za-z0-9_.-]*$`
	Interface string `json:"interface"`

	// Promiscuous enables promiscuous mode on the interface.
	//
	// Required for a mirror port, which receives frames addressed elsewhere.
	// +kubebuilder:default=false
	// +optional
	Promiscuous bool `json:"promiscuous,omitempty"`

	// NodeSelector chooses eligible nodes.
	//
	// Required and non-empty. An empty selector matches every node, which for a
	// mirror source would mean opening a capture socket cluster-wide instead of
	// on the one node wired to the SPAN port.
	// +kubebuilder:validation:Required
	NodeSelector metav1.LabelSelector `json:"nodeSelector"`
}

// CustomContentRef points at a site-specific detection content artifact.
//
// Digest-pinned (FR-042): a tag can be repointed after the rule review that
// approved its content, so it cannot identify what a sensor is running.
type CustomContentRef struct {
	// Reference is an OCI artifact reference in repository@sha256:... form.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=512
	// +kubebuilder:validation:Pattern=`^[^@\s]+@sha256:[0-9a-f]{64}$`
	Reference string `json:"reference"`
}

// AnalyzerConfig enables one analyzer and bounds its resources.
type AnalyzerConfig struct {
	// Enabled turns this analyzer on for the tap.
	// +kubebuilder:default=false
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// Resources are the requests and limits for the analyzer container.
	//
	// Required when enabled, and validated so requests do not exceed limits.
	// An unbounded analyzer on a sensor node competes with the workloads it is
	// meant to observe.
	// +optional
	Resources *corev1.ResourceRequirements `json:"resources,omitempty"`

	// CustomContent optionally overlays site-specific rules or scripts on top
	// of the upstream content fetched at startup (ADR-0005).
	//
	// Absent means upstream-only, which is the normal case.
	// +optional
	CustomContent *CustomContentRef `json:"customContent,omitempty"`
}

// AnalyzerSelection chooses which analyzers run.
type AnalyzerSelection struct {
	// Suricata provides signature-based detection.
	// +optional
	Suricata AnalyzerConfig `json:"suricata,omitempty"`

	// Zeek provides protocol metadata.
	// +optional
	Zeek AnalyzerConfig `json:"zeek,omitempty"`
}

// NetworkTapSpec is the desired observation state.
//
// The cross-field rules are expressed as CEL so the API server enforces them.
// Leaving them to the webhook alone would let a direct etcd restore or a webhook
// outage admit a tap whose source branch does not match its type.
// +kubebuilder:validation:XValidation:rule="self.type != 'MirrorInterface' || has(self.mirrorInterface)",message="type MirrorInterface requires mirrorInterface"
// +kubebuilder:validation:XValidation:rule="self.type != 'MirrorInterface' || !has(self.nodeInterface)",message="type MirrorInterface forbids nodeInterface"
// +kubebuilder:validation:XValidation:rule="self.type != 'NodeInterface' || has(self.nodeInterface)",message="type NodeInterface requires nodeInterface"
// +kubebuilder:validation:XValidation:rule="self.type != 'NodeInterface' || !has(self.mirrorInterface)",message="type NodeInterface forbids mirrorInterface"
// +kubebuilder:validation:XValidation:rule="(has(self.analyzers.suricata) && self.analyzers.suricata.enabled) || (has(self.analyzers.zeek) && self.analyzers.zeek.enabled)",message="at least one analyzer must be enabled"
// +kubebuilder:validation:XValidation:rule="!(has(self.analyzers.suricata) && self.analyzers.suricata.enabled) || has(self.analyzers.suricata.resources)",message="enabled suricata requires resources"
// +kubebuilder:validation:XValidation:rule="!(has(self.analyzers.zeek) && self.analyzers.zeek.enabled) || has(self.analyzers.zeek.resources)",message="enabled zeek requires resources"
type NetworkTapSpec struct {
	// Mode is the observation mode. Passive is the only accepted value.
	// +kubebuilder:default=Passive
	// +optional
	Mode TapMode `json:"mode,omitempty"`

	// Type selects which source branch applies.
	// +kubebuilder:validation:Required
	Type TapSourceType `json:"type"`

	// MirrorInterface observes a physical mirror port on exactly one node.
	// +optional
	MirrorInterface *InterfaceSource `json:"mirrorInterface,omitempty"`

	// NodeInterface observes a node interface on one or more nodes.
	// +optional
	NodeInterface *InterfaceSource `json:"nodeInterface,omitempty"`

	// Analyzers selects which analysis runs on the observed traffic.
	// +kubebuilder:validation:Required
	Analyzers AnalyzerSelection `json:"analyzers"`
}

// AnalyzerStatus reports one analyzer's health on one target.
type AnalyzerStatus struct {
	// Name identifies the analyzer.
	Name AnalyzerName `json:"name"`

	// Healthy reflects observed liveness, not desired state.
	Healthy bool `json:"healthy"`

	// Version is the analyzer's reported version.
	// +optional
	Version string `json:"version,omitempty"`

	// LastRecordTime is when this analyzer last produced a record.
	// +optional
	LastRecordTime *metav1.Time `json:"lastRecordTime,omitempty"`

	// UpstreamFetchedAt is when this analyzer's upstream detection content was
	// retrieved, so operators can see content currency without exec'ing into a
	// pod (FR-045).
	// +optional
	UpstreamFetchedAt *metav1.Time `json:"upstreamFetchedAt,omitempty"`

	// CustomContentDigest is the digest of the applied custom content artifact,
	// empty when the analyzer is running upstream-only.
	// +optional
	CustomContentDigest string `json:"customContentDigest,omitempty"`

	// Reason is a sanitized explanation when unhealthy.
	// +kubebuilder:validation:MaxLength=256
	// +optional
	Reason string `json:"reason,omitempty"`
}

// TargetStatus reports observation health on one node.
type TargetStatus struct {
	// NodeName is the node this target runs on.
	NodeName string `json:"nodeName"`

	// Interface is the interface being observed.
	Interface string `json:"interface"`

	// PodRef references the analyzer pod.
	// +optional
	PodRef *corev1.LocalObjectReference `json:"podRef,omitempty"`

	// ReporterInstance identifies the sensor process that wrote this status.
	//
	// It distinguishes a restarted sensor from a stalled one: counters reset on
	// restart, and without knowing the instance changed, that reset looks like
	// traffic stopping.
	// +optional
	ReporterInstance string `json:"reporterInstance,omitempty"`

	// HeartbeatTime is when the sensor last reported.
	HeartbeatTime metav1.Time `json:"heartbeatTime"`

	// LastPacketTime is when a packet was last observed.
	// +optional
	LastPacketTime *metav1.Time `json:"lastPacketTime,omitempty"`

	// PacketsObserved counts packets at the capture boundary.
	// +optional
	PacketsObserved int64 `json:"packetsObserved,omitempty"`

	// KernelDrops counts packets the kernel dropped before the analyzer saw
	// them. Absent when the analyzer does not report it; zero and unknown are
	// different answers for packet-loss reporting (FR-039).
	// +optional
	KernelDrops *int64 `json:"kernelDrops,omitempty"`

	// Duplication reports whether duplicate observations are suspected.
	// +kubebuilder:default=Unknown
	// +optional
	Duplication DuplicationState `json:"duplication,omitempty"`

	// RejectedRecords counts malformed or unsupported analyzer records. Raw
	// rejected content is never stored here, only the count (FR-016).
	// +optional
	RejectedRecords int64 `json:"rejectedRecords,omitempty"`

	// Analyzers reports per-analyzer health on this target.
	// +listType=map
	// +listMapKey=name
	// +optional
	Analyzers []AnalyzerStatus `json:"analyzers,omitempty"`
}

// NetworkTapStatus is the observed state.
type NetworkTapStatus struct {
	// ObservedGeneration is the spec generation this status describes. Status is
	// stale whenever it lags metadata.generation, and consumers must treat a
	// stale status as unknown rather than current truth.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Phase is the aggregate state.
	// +optional
	Phase TapPhase `json:"phase,omitempty"`

	// MatchedTargets is how many nodes the selector resolved to.
	// +optional
	MatchedTargets int32 `json:"matchedTargets,omitempty"`

	// ReadyTargets is how many are observing with healthy analyzers.
	// +optional
	ReadyTargets int32 `json:"readyTargets,omitempty"`

	// LastPacketTime is the most recent packet across all targets.
	// +optional
	LastPacketTime *metav1.Time `json:"lastPacketTime,omitempty"`

	// Targets reports per-node observation health.
	// +listType=map
	// +listMapKey=nodeName
	// +optional
	Targets []TargetStatus `json:"targets,omitempty"`

	// Conditions carry the detailed reasons behind Phase.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=tap;taps
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Targets",type=string,JSONPath=`.status.readyTargets`
// +kubebuilder:printcolumn:name="Matched",type=string,JSONPath=`.status.matchedTargets`
// +kubebuilder:printcolumn:name="Last Packet",type=date,JSONPath=`.status.lastPacketTime`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// NetworkTap declares one passive observation point.
type NetworkTap struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NetworkTapSpec   `json:"spec,omitempty"`
	Status NetworkTapStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NetworkTapList contains a list of NetworkTap.
type NetworkTapList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkTap `json:"items"`
}
