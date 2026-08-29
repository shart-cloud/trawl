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

package admission

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
)

// The rules tested here are the ones a CRD schema cannot express. The schema
// checks shape; these check meaning.

func validSpec() *trawlv1alpha1.NetworkTapSpec {
	return &trawlv1alpha1.NetworkTapSpec{
		Mode: trawlv1alpha1.TapModePassive,
		Type: trawlv1alpha1.TapSourceMirrorInterface,
		MirrorInterface: &trawlv1alpha1.InterfaceSource{
			Interface:   "enp5s0",
			Promiscuous: true,
			NodeSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"kubernetes.io/hostname": "sensor-01"},
			},
		},
		Analyzers: trawlv1alpha1.AnalyzerSelection{
			Suricata: trawlv1alpha1.AnalyzerConfig{
				Enabled: true,
				Resources: &corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("500m"),
						corev1.ResourceMemory: resource.MustParse("512Mi"),
					},
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("1"),
						corev1.ResourceMemory: resource.MustParse("1Gi"),
					},
				},
			},
		},
	}
}

func TestValidateAcceptsReferenceSpec(t *testing.T) {
	if errs := ValidateNetworkTapSpec(validSpec()); len(errs) > 0 {
		t.Fatalf("reference spec rejected: %v", errs)
	}
}

func TestValidateRejectsEmptyNodeSelector(t *testing.T) {
	// The schema cannot express "non-empty LabelSelector". An empty selector
	// matches every node, so a mirror tap would open capture sockets
	// cluster-wide rather than on the node wired to the SPAN port.
	spec := validSpec()
	spec.MirrorInterface.NodeSelector = metav1.LabelSelector{}

	errs := ValidateNetworkTapSpec(spec)
	if len(errs) == 0 {
		t.Fatal("empty node selector accepted")
	}
	if !strings.Contains(errs.ToAggregate().Error(), "nodeSelector") {
		t.Errorf("error does not name the field: %v", errs)
	}
}

func TestValidateAcceptsMatchExpressionsOnlySelector(t *testing.T) {
	// matchExpressions alone is a legitimately non-empty selector.
	spec := validSpec()
	spec.MirrorInterface.NodeSelector = metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key:      "trawl.cloud/sensor",
			Operator: metav1.LabelSelectorOpExists,
		}},
	}
	if errs := ValidateNetworkTapSpec(spec); len(errs) > 0 {
		t.Errorf("matchExpressions-only selector rejected: %v", errs)
	}
}

func TestValidateRejectsRequestAboveLimit(t *testing.T) {
	// A request above its limit is unschedulable. Rejecting it turns a pod that
	// silently never schedules into an immediate, explicable error.
	spec := validSpec()
	spec.Analyzers.Suricata.Resources.Requests[corev1.ResourceCPU] = resource.MustParse("2")

	errs := ValidateNetworkTapSpec(spec)
	if len(errs) == 0 {
		t.Fatal("cpu request above limit accepted")
	}
	if !strings.Contains(errs.ToAggregate().Error(), "request must not exceed limit") {
		t.Errorf("unexpected error: %v", errs)
	}
}

func TestValidateRequiresBothCPUAndMemoryBounds(t *testing.T) {
	spec := validSpec()
	delete(spec.Analyzers.Suricata.Resources.Limits, corev1.ResourceMemory)

	errs := ValidateNetworkTapSpec(spec)
	if len(errs) == 0 {
		t.Fatal("missing memory limit accepted")
	}
}

func TestValidateIgnoresDisabledAnalyzerConfiguration(t *testing.T) {
	// A disabled analyzer's configuration is inert. Validating it would reject
	// specs that are harmless, and would punish an operator for leaving a
	// stanza in place while turning it off.
	spec := validSpec()
	spec.Analyzers.Zeek = trawlv1alpha1.AnalyzerConfig{
		Enabled:       false,
		CustomContent: &trawlv1alpha1.CustomContentRef{Reference: "not-a-digest"},
	}
	if errs := ValidateNetworkTapSpec(spec); len(errs) > 0 {
		t.Errorf("disabled analyzer configuration was validated: %v", errs)
	}
}

func TestValidateRejectsNonDigestCustomContent(t *testing.T) {
	spec := validSpec()
	spec.Analyzers.Suricata.CustomContent = &trawlv1alpha1.CustomContentRef{
		Reference: "registry.example/custom:v1",
	}
	errs := ValidateNetworkTapSpec(spec)
	if len(errs) == 0 {
		t.Fatal("tag-based custom content reference accepted")
	}
}

func TestValidateAcceptsDigestCustomContent(t *testing.T) {
	spec := validSpec()
	spec.Analyzers.Suricata.CustomContent = &trawlv1alpha1.CustomContentRef{
		Reference: "registry.example/custom@sha256:" + strings.Repeat("a", 64),
	}
	if errs := ValidateNetworkTapSpec(spec); len(errs) > 0 {
		t.Errorf("digest-pinned custom content rejected: %v", errs)
	}
}

func TestValidateRejectsNonPassiveMode(t *testing.T) {
	// Defence in depth: the CRD enum rejects this too, but a stored object
	// restored directly into etcd never passed through the enum.
	spec := validSpec()
	spec.Mode = "Inline"
	if errs := ValidateNetworkTapSpec(spec); len(errs) == 0 {
		t.Fatal("non-passive mode accepted")
	}
}

func TestDefaultSetsPassiveMode(t *testing.T) {
	w := &NetworkTapWebhook{Gate: &Gate{SystemNamespace: "trawl-system"}}
	tap := &trawlv1alpha1.NetworkTap{Spec: *validSpec()}
	tap.Spec.Mode = ""

	if err := w.Default(t.Context(), tap); err != nil {
		t.Fatalf("Default: %v", err)
	}
	if tap.Spec.Mode != trawlv1alpha1.TapModePassive {
		t.Errorf("mode = %q, want Passive", tap.Spec.Mode)
	}
}

func TestDefaultForcesPromiscuousOnMirrorSource(t *testing.T) {
	// A mirror port carries frames addressed to other hosts. Without
	// promiscuous mode the NIC drops exactly the traffic the tap exists to
	// observe, and the only symptom is an empty dashboard.
	w := &NetworkTapWebhook{Gate: &Gate{SystemNamespace: "trawl-system"}}
	tap := &trawlv1alpha1.NetworkTap{Spec: *validSpec()}
	tap.Spec.MirrorInterface.Promiscuous = false

	if err := w.Default(t.Context(), tap); err != nil {
		t.Fatalf("Default: %v", err)
	}
	if !tap.Spec.MirrorInterface.Promiscuous {
		t.Error("promiscuous was not defaulted on for a mirror source")
	}
}

func TestDefaultLeavesNodeInterfacePromiscuousAlone(t *testing.T) {
	// A node interface sees its own traffic without promiscuous mode, and
	// enabling it would capture neighbouring traffic the operator did not ask
	// for. Scope creep in a capture path is a privacy problem, not a feature.
	w := &NetworkTapWebhook{Gate: &Gate{SystemNamespace: "trawl-system"}}
	tap := &trawlv1alpha1.NetworkTap{Spec: trawlv1alpha1.NetworkTapSpec{
		Type: trawlv1alpha1.TapSourceNodeInterface,
		NodeInterface: &trawlv1alpha1.InterfaceSource{
			Interface:    "eth0",
			NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
		},
		Analyzers: validSpec().Analyzers,
	}}

	if err := w.Default(t.Context(), tap); err != nil {
		t.Fatalf("Default: %v", err)
	}
	if tap.Spec.NodeInterface.Promiscuous {
		t.Error("promiscuous was enabled on a node interface without being asked")
	}
}

func TestCheckNamespaceRejectsOtherNamespaces(t *testing.T) {
	// FR-001. Cluster-wide CRD discovery must not imply cluster-wide
	// reconciliation: without this, a user with create rights in their own
	// namespace could have Trawl render privileged workloads there.
	g := &Gate{SystemNamespace: "trawl-system"}

	if err := g.CheckNamespace("trawl-system"); err != nil {
		t.Errorf("configured namespace rejected: %v", err)
	}
	for _, ns := range []string{"default", "kube-system", "", "trawl-system2"} {
		if err := g.CheckNamespace(ns); err == nil {
			t.Errorf("namespace %q accepted", ns)
		}
	}
}

func TestValidateImmutableFieldsRejectsRepointing(t *testing.T) {
	// Changing the interface or source type in place would keep the object's
	// identity and history while observing entirely different traffic, so
	// stored observations would be attributed to a tap that no longer
	// describes them.
	old := &trawlv1alpha1.NetworkTap{Spec: *validSpec()}

	changedIface := &trawlv1alpha1.NetworkTap{Spec: *validSpec()}
	changedIface.Spec.MirrorInterface.Interface = "eth9"
	if errs := validateImmutableFields(old, changedIface); len(errs) == 0 {
		t.Error("interface change accepted")
	}

	changedType := &trawlv1alpha1.NetworkTap{Spec: *validSpec()}
	changedType.Spec.Type = trawlv1alpha1.TapSourceNodeInterface
	changedType.Spec.MirrorInterface = nil
	changedType.Spec.NodeInterface = &trawlv1alpha1.InterfaceSource{
		Interface:    "enp5s0",
		NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
	}
	if errs := validateImmutableFields(old, changedType); len(errs) == 0 {
		t.Error("source type change accepted")
	}
}

func TestValidateImmutableFieldsAllowsAnalyzerChanges(t *testing.T) {
	// FR-004 requires analyzer selection and bounds to be changeable; only the
	// observation point is fixed.
	old := &trawlv1alpha1.NetworkTap{Spec: *validSpec()}
	updated := &trawlv1alpha1.NetworkTap{Spec: *validSpec()}
	updated.Spec.Analyzers.Zeek = trawlv1alpha1.AnalyzerConfig{
		Enabled:   true,
		Resources: validSpec().Analyzers.Suricata.Resources,
	}

	if errs := validateImmutableFields(old, updated); len(errs) > 0 {
		t.Errorf("analyzer change rejected: %v", errs)
	}
}
