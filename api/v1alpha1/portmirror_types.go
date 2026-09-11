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

// MirrorProvider names the driver that speaks to a device.
//
// An enum rather than free text: the provider decides what credentials are
// used and what commands are sent to hardware, and a typo that silently
// selected a different driver would send one vendor's configuration to
// another's switch.
// +kubebuilder:validation:Enum=MikroTikRouterOS7
type MirrorProvider string

const (
	// MirrorProviderMikroTikRouterOS7 drives RouterOS 7.x switches through
	// their REST API.
	MirrorProviderMikroTikRouterOS7 MirrorProvider = "MikroTikRouterOS7"
)

// MirrorDirection selects which of a source port's traffic is copied.
// +kubebuilder:validation:Enum=Both;Ingress;Egress
type MirrorDirection string

const (
	MirrorDirectionBoth    MirrorDirection = "Both"
	MirrorDirectionIngress MirrorDirection = "Ingress"
	MirrorDirectionEgress  MirrorDirection = "Egress"
)

// PortMirrorPhase is the mirror's operational position.
// +kubebuilder:validation:Enum=Pending;Active;Degraded;Error
type PortMirrorPhase string

const (
	// PortMirrorPending means the device has not yet confirmed the mirror.
	PortMirrorPending PortMirrorPhase = "Pending"

	// PortMirrorActive means the device was read back and reports the mirror
	// this resource asked for. It is never set from a successful write alone.
	PortMirrorActive PortMirrorPhase = "Active"

	// PortMirrorDegraded means the device is reachable and its configuration
	// does not match. Someone may have changed it by hand.
	PortMirrorDegraded PortMirrorPhase = "Degraded"

	// PortMirrorError means the device could not be reached or refused the
	// configuration.
	PortMirrorError PortMirrorPhase = "Error"
)

// PortMirrorSpec asks a network device to copy traffic from one or more ports
// to another.
//
// This is the only Trawl resource that writes to hardware outside the cluster,
// and it is deliberately its own kind rather than a NetworkTap source type.
// Three reasons, in order of how much they matter:
//
//  1. **It is separately authorizable.** An analyst who may create taps and
//     request captures does not thereby gain the ability to reconfigure switch
//     hardware; granting `portmirrors` is its own decision. Device credentials
//     are coarse - RouterOS group policies do not offer "may only set a mirror"
//     - so the Kubernetes side is where least privilege is actually available,
//     and collapsing this into NetworkTap would give it away.
//
//  2. **NetworkTap stays passive.** Nothing about the existing tap path
//     changes, and the resource that writes to the fabric is visibly a
//     different thing with a different blast radius.
//
//  3. **The failure domains separate.** A device that refuses configuration
//     does not make a tap lie about what it is observing. The tap reports on
//     packets it can see; the mirror reports on what the device says.
//
// Mirroring copies traffic and leaves the forwarding path alone, so the
// observed traffic is not modified, blocked, delayed or redirected. What is new
// is that Trawl holds a credential that can change network hardware. See
// ADR-0007.
//
// +kubebuilder:validation:XValidation:rule="!(self.target in self.sources)",message="target must not also be a source"
type PortMirrorSpec struct {
	// Provider selects the driver used to talk to the device.
	// +kubebuilder:validation:Required
	Provider MirrorProvider `json:"provider"`

	// DeviceRef names a Secret in the same namespace holding the device
	// address and credentials.
	//
	// A Secret rather than inline fields, and in-namespace rather than
	// cluster-wide: the credential is the whole security story of this
	// resource, and a device address in a spec with the password somewhere
	// else invites the two to drift apart.
	// +kubebuilder:validation:Required
	DeviceRef corev1.LocalObjectReference `json:"deviceRef"`

	// Sources are the device ports whose traffic is copied.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=48
	// +kubebuilder:validation:items:MaxLength=64
	// +kubebuilder:validation:items:Pattern=`^[A-Za-z0-9._/-]+$`
	// +listType=set
	Sources []string `json:"sources"`

	// Target is the device port the copies are sent to.
	//
	// It must not also be a source. A port mirroring itself is a loop the
	// switch will happily configure and nobody wants, so the union is checked
	// rather than documented.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxLength=64
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9._/-]+$`
	Target string `json:"target"`

	// Direction selects which of the sources' traffic is copied.
	// +kubebuilder:default=Both
	// +optional
	Direction MirrorDirection `json:"direction,omitempty"`
}

// PortMirrorStatus is what the device reports, not what was asked for.
type PortMirrorStatus struct {
	// ObservedGeneration is the spec generation last reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Phase is the mirror's operational position.
	// +optional
	Phase PortMirrorPhase `json:"phase,omitempty"`

	// ObservedSources and ObservedTarget are what the device says its mirror
	// is set to, read back after configuring.
	//
	// Recorded separately from the spec so a drifted device is visible as a
	// difference rather than as a bare Degraded phase: an operator needs to
	// know what it drifted *to*, because that is usually somebody else's
	// change and the interesting question is whose.
	// +optional
	// +listType=set
	ObservedSources []string `json:"observedSources,omitempty"`

	// +optional
	ObservedTarget string `json:"observedTarget,omitempty"`

	// DeviceIdentity is what the device said it is: model and firmware.
	//
	// Kept because a mirror that works on one RouterOS release can fail on the
	// next, and an incident six months from now needs to know which it was.
	// +optional
	DeviceIdentity string `json:"deviceIdentity,omitempty"`

	// LastVerifiedTime is when the device was last read back successfully.
	// +optional
	LastVerifiedTime *metav1.Time `json:"lastVerifiedTime,omitempty"`

	// Conditions carry the detail behind Phase.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=mirror;mirrors
// +kubebuilder:printcolumn:name="Provider",type=string,JSONPath=`.spec.provider`
// +kubebuilder:printcolumn:name="Target",type=string,JSONPath=`.spec.target`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Verified",type=date,JSONPath=`.status.lastVerifiedTime`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PortMirror configures traffic mirroring on a network device so a NetworkTap
// has something to observe.
type PortMirror struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PortMirrorSpec   `json:"spec,omitempty"`
	Status PortMirrorStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PortMirrorList contains a list of PortMirror.
type PortMirrorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PortMirror `json:"items"`
}
