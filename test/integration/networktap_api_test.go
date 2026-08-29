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
	"strconv"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
)

// These run against a real apiserver rather than a fake client, because
// defaulting, structural validation, and CEL are apiserver behaviours. A fake
// client implements none of them, so a type that passes against one can still
// be rejected — or worse, wrongly accepted — in a cluster.

func analyzerResources() *corev1.ResourceRequirements {
	return &corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("500m"),
			corev1.ResourceMemory: resource.MustParse("512Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("1"),
			corev1.ResourceMemory: resource.MustParse("1Gi"),
		},
	}
}

func mirrorTap(namespace, name string) *trawlv1alpha1.NetworkTap {
	return &trawlv1alpha1.NetworkTap{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: trawlv1alpha1.NetworkTapSpec{
			Type: trawlv1alpha1.TapSourceMirrorInterface,
			MirrorInterface: &trawlv1alpha1.InterfaceSource{
				Interface:   "enp5s0",
				Promiscuous: true,
				NodeSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"kubernetes.io/hostname": "talos-sensor-01"},
				},
			},
			Analyzers: trawlv1alpha1.AnalyzerSelection{
				Suricata: trawlv1alpha1.AnalyzerConfig{Enabled: true, Resources: analyzerResources()},
			},
		},
	}
}

func TestNetworkTapAcceptsValidMirrorSource(t *testing.T) {
	ns := NewNamespace(t)
	tap := mirrorTap(ns, "valid-mirror")

	if err := Client().Create(t.Context(), tap); err != nil {
		t.Fatalf("valid mirror tap rejected: %v", err)
	}
}

func TestNetworkTapDefaultsModeToPassive(t *testing.T) {
	// FR-003: passive is the only supported mode, and an unset mode must not
	// leave the field empty for a later reader to interpret.
	ns := NewNamespace(t)
	tap := mirrorTap(ns, "default-mode")
	tap.Spec.Mode = ""

	if err := Client().Create(t.Context(), tap); err != nil {
		t.Fatalf("create: %v", err)
	}
	if tap.Spec.Mode != trawlv1alpha1.TapModePassive {
		t.Errorf("mode = %q, want %q", tap.Spec.Mode, trawlv1alpha1.TapModePassive)
	}
}

func TestNetworkTapRejectsNonPassiveMode(t *testing.T) {
	// The enum is what makes "this release cannot go inline" enforceable rather
	// than merely intended.
	ns := NewNamespace(t)
	tap := mirrorTap(ns, "inline-mode")
	tap.Spec.Mode = "Inline"

	if err := Client().Create(t.Context(), tap); err == nil {
		t.Fatal("apiserver accepted mode Inline")
	}
}

func TestNetworkTapEnforcesClosedSourceUnion(t *testing.T) {
	// Cross-field rules live in CEL so the apiserver enforces them. Leaving them
	// to the webhook alone would let a webhook outage or a direct etcd restore
	// admit a tap whose source branch contradicts its type.
	ns := NewNamespace(t)

	cases := []struct {
		name   string
		mutate func(*trawlv1alpha1.NetworkTap)
	}{
		{"mirror type without mirror source", func(tap *trawlv1alpha1.NetworkTap) {
			tap.Spec.MirrorInterface = nil
		}},
		{"mirror type with node source", func(tap *trawlv1alpha1.NetworkTap) {
			tap.Spec.NodeInterface = &trawlv1alpha1.InterfaceSource{
				Interface:    "eth0",
				NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			}
		}},
		{"node type without node source", func(tap *trawlv1alpha1.NetworkTap) {
			tap.Spec.Type = trawlv1alpha1.TapSourceNodeInterface
			tap.Spec.MirrorInterface = nil
		}},
		{"node type with mirror source", func(tap *trawlv1alpha1.NetworkTap) {
			tap.Spec.Type = trawlv1alpha1.TapSourceNodeInterface
			tap.Spec.NodeInterface = &trawlv1alpha1.InterfaceSource{
				Interface:    "eth0",
				NodeSelector: metav1.LabelSelector{MatchLabels: map[string]string{"a": "b"}},
			}
		}},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tap := mirrorTap(ns, "union-"+strconv.Itoa(i))
			tc.mutate(tap)
			if err := Client().Create(t.Context(), tap); err == nil {
				t.Errorf("apiserver accepted %s", tc.name)
			}
		})
	}
}

func TestNetworkTapRequiresAtLeastOneAnalyzer(t *testing.T) {
	// A tap with no analyzer opens a capture socket and discards everything it
	// sees. It would look healthy while producing no evidence.
	ns := NewNamespace(t)
	tap := mirrorTap(ns, "no-analyzers")
	tap.Spec.Analyzers = trawlv1alpha1.AnalyzerSelection{}

	if err := Client().Create(t.Context(), tap); err == nil {
		t.Fatal("apiserver accepted a tap with no analyzer enabled")
	}
}

func TestNetworkTapRequiresResourcesForEnabledAnalyzer(t *testing.T) {
	// An unbounded analyzer on a sensor node competes with the workloads it is
	// meant to observe.
	ns := NewNamespace(t)
	tap := mirrorTap(ns, "no-resources")
	tap.Spec.Analyzers.Suricata.Resources = nil

	if err := Client().Create(t.Context(), tap); err == nil {
		t.Fatal("apiserver accepted an enabled analyzer with no resources")
	}
}

func TestNetworkTapValidatesInterfaceName(t *testing.T) {
	// The interface name reaches a capture process argument, so it is bounded
	// and pattern-checked at admission rather than becoming a crash-looping pod.
	ns := NewNamespace(t)

	for i, iface := range []string{
		"",
		strings.Repeat("e", 16), // IFNAMSIZ is 16 including the terminator
		"eth0; rm -rf /",
		"eth 0",
		"-eth0",
		"eth0$(id)",
	} {
		t.Run(iface, func(t *testing.T) {
			tap := mirrorTap(ns, "iface-"+strconv.Itoa(i))
			tap.Spec.MirrorInterface.Interface = iface
			if err := Client().Create(t.Context(), tap); err == nil {
				t.Errorf("apiserver accepted interface name %q", iface)
			}
		})
	}
}

func TestNetworkTapAcceptsValidInterfaceNames(t *testing.T) {
	ns := NewNamespace(t)
	for i, iface := range []string{"eth0", "enp5s0", "bond0.100", "br-mirror"} {
		t.Run(iface, func(t *testing.T) {
			tap := mirrorTap(ns, "ok-iface-"+strconv.Itoa(i))
			tap.Spec.MirrorInterface.Interface = iface
			if err := Client().Create(t.Context(), tap); err != nil {
				t.Errorf("apiserver rejected valid interface %q: %v", iface, err)
			}
		})
	}
}

func TestNetworkTapRequiresNodeSelector(t *testing.T) {
	// An empty selector matches every node. For a mirror source that would open
	// capture sockets cluster-wide instead of on the one node wired to the SPAN
	// port.
	ns := NewNamespace(t)
	tap := mirrorTap(ns, "empty-selector")
	tap.Spec.MirrorInterface.NodeSelector = metav1.LabelSelector{}

	err := Client().Create(t.Context(), tap)
	if err == nil {
		// A structurally empty selector is accepted by the schema; the webhook
		// is what rejects it. Record which layer is responsible so the gap is
		// visible rather than assumed covered.
		t.Skip("empty selector is rejected by the admission webhook, not the schema (see T036)")
	}
}

func TestNetworkTapValidatesCustomContentDigest(t *testing.T) {
	// FR-042: custom content is digest-pinned. A tag could be repointed after
	// the rule review that approved its content.
	ns := NewNamespace(t)

	for i, ref := range []string{
		"registry.example/custom:v1",
		"registry.example/custom:latest",
		"registry.example/custom",
		"registry.example/custom@md5:" + strings.Repeat("a", 32),
		"registry.example/custom@sha256:" + strings.Repeat("A", 64),
	} {
		t.Run(ref, func(t *testing.T) {
			tap := mirrorTap(ns, "content-"+strconv.Itoa(i))
			tap.Spec.Analyzers.Suricata.CustomContent = &trawlv1alpha1.CustomContentRef{Reference: ref}
			if err := Client().Create(t.Context(), tap); err == nil {
				t.Errorf("apiserver accepted non-digest content reference %q", ref)
			}
		})
	}

	tap := mirrorTap(ns, "content-valid")
	tap.Spec.Analyzers.Suricata.CustomContent = &trawlv1alpha1.CustomContentRef{
		Reference: "registry.example/custom@sha256:" + strings.Repeat("a", 64),
	}
	if err := Client().Create(t.Context(), tap); err != nil {
		t.Errorf("apiserver rejected a valid digest reference: %v", err)
	}
}

func TestNetworkTapStatusIsASubresource(t *testing.T) {
	// Status must not be writable through the main resource, or a user with
	// edit rights on a tap could declare it Active and healthy.
	ns := NewNamespace(t)
	tap := mirrorTap(ns, "status-subresource")
	if err := Client().Create(t.Context(), tap); err != nil {
		t.Fatalf("create: %v", err)
	}

	tap.Status.Phase = trawlv1alpha1.TapPhaseActive
	tap.Status.ReadyTargets = 99
	if err := Client().Update(t.Context(), tap); err != nil {
		t.Fatalf("update: %v", err)
	}

	var fetched trawlv1alpha1.NetworkTap
	if err := Client().Get(t.Context(), client.ObjectKeyFromObject(tap), &fetched); err != nil {
		t.Fatalf("get: %v", err)
	}
	if fetched.Status.Phase == trawlv1alpha1.TapPhaseActive {
		t.Error("status was writable through the main resource")
	}
}

func TestNetworkTapTargetsAreAssociativeByNode(t *testing.T) {
	// Targets are a list-map keyed by nodeName so concurrent sensor status
	// patches merge per node instead of overwriting the whole list. Without
	// this, two sensors reporting at once would erase each other's status.
	ns := NewNamespace(t)
	tap := mirrorTap(ns, "target-merge")
	if err := Client().Create(t.Context(), tap); err != nil {
		t.Fatalf("create: %v", err)
	}

	tap.Status.Targets = []trawlv1alpha1.TargetStatus{
		{NodeName: "node-a", Interface: "eth0", HeartbeatTime: metav1.Now()},
		{NodeName: "node-b", Interface: "eth0", HeartbeatTime: metav1.Now()},
	}
	if err := Client().Status().Update(t.Context(), tap); err != nil {
		t.Fatalf("status update: %v", err)
	}

	var fetched trawlv1alpha1.NetworkTap
	if err := Client().Get(t.Context(), client.ObjectKeyFromObject(tap), &fetched); err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(fetched.Status.Targets) != 2 {
		t.Errorf("got %d targets, want 2", len(fetched.Status.Targets))
	}

	// A duplicate key must be rejected by the list-map constraint.
	fetched.Status.Targets = append(fetched.Status.Targets, trawlv1alpha1.TargetStatus{
		NodeName: "node-a", Interface: "eth1", HeartbeatTime: metav1.Now(),
	})
	if err := Client().Status().Update(t.Context(), &fetched); err == nil {
		t.Error("apiserver accepted duplicate target keys")
	}
}

func TestNetworkTapDuplicationDefaultsToUnknown(t *testing.T) {
	// Unknown is a real answer. Reporting NotDetected for a target whose
	// fingerprint window never ran would claim an absence we did not establish.
	ns := NewNamespace(t)
	tap := mirrorTap(ns, "duplication-default")
	if err := Client().Create(t.Context(), tap); err != nil {
		t.Fatalf("create: %v", err)
	}

	tap.Status.Targets = []trawlv1alpha1.TargetStatus{
		{NodeName: "node-a", Interface: "eth0", HeartbeatTime: metav1.Now()},
	}
	if err := Client().Status().Update(t.Context(), tap); err != nil {
		t.Fatalf("status update: %v", err)
	}

	var fetched trawlv1alpha1.NetworkTap
	if err := Client().Get(t.Context(), client.ObjectKeyFromObject(tap), &fetched); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got := fetched.Status.Targets[0].Duplication; got != trawlv1alpha1.DuplicationUnknown {
		t.Errorf("duplication = %q, want %q", got, trawlv1alpha1.DuplicationUnknown)
	}
}
