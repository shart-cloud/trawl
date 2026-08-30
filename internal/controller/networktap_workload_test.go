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

package controller

import (
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/config"
)

// These are the tests that pin Trawl's privilege boundary. Every assertion here
// corresponds to something that would be invisible in a running cluster until
// it mattered: a capability nobody noticed, a token mounted where it should not
// be, an unbounded volume on a sensor node.

func testConfig() *config.Config {
	digest := func(c string) string {
		return "ghcr.io/trawl/x@sha256:" + strings.Repeat(c, 64)
	}
	return &config.Config{
		ClusterID:       "homelab",
		SystemNamespace: "trawl-system",
		SensorAgentResources: config.ResourceRequirements{
			RequestsCPU: "50m", RequestsMemory: "64Mi",
			LimitsCPU: "200m", LimitsMemory: "256Mi",
		},
		Content: config.ContentConfig{
			SuricataFeedURL: "https://rules.example/emerging.rules.tar.gz",
			ZeekScriptRepo:  "https://github.com/zeek/packages",
		},
		Images: config.ImageConfig{
			Suricata: digest("a"), Zeek: digest("b"), SensorAgent: digest("c"),
			CaptureRunner: digest("d"), ContentInit: digest("e"),
		},
	}
}

func testTap() *trawlv1alpha1.NetworkTap {
	res := &corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("500m"),
			corev1.ResourceMemory: resource.MustParse("512Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("1"),
			corev1.ResourceMemory: resource.MustParse("1Gi"),
		},
	}
	return &trawlv1alpha1.NetworkTap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "north-south", Namespace: "trawl-system",
			UID: "abcdef12-3456-7890-abcd-ef1234567890", Generation: 3,
		},
		Spec: trawlv1alpha1.NetworkTapSpec{
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
				Suricata: trawlv1alpha1.AnalyzerConfig{Enabled: true, Resources: res},
				Zeek:     trawlv1alpha1.AnalyzerConfig{Enabled: true, Resources: res},
			},
		},
	}
}

func renderer() *WorkloadRenderer { return &WorkloadRenderer{Config: testConfig()} }

func containerByName(spec corev1.PodSpec, name string) *corev1.Container {
	for i := range spec.Containers {
		if spec.Containers[i].Name == name {
			return &spec.Containers[i]
		}
	}
	return nil
}

func TestAnalyzerContainersGetExactlyTwoCapabilities(t *testing.T) {
	// ADR-0004: NET_RAW opens the packet socket, NET_ADMIN sets promiscuous
	// mode. Anything beyond those two is privilege nobody asked for, and the
	// only place it would be noticed is a security review that may not happen.
	spec := renderer().PodSpec(testTap())

	for _, name := range []string{"suricata", "zeek"} {
		t.Run(name, func(t *testing.T) {
			c := containerByName(spec, name)
			if c == nil {
				t.Fatalf("no %s container rendered", name)
			}
			sc := c.SecurityContext
			if sc == nil {
				t.Fatal("no security context")
			}
			if !slices.Contains(sc.Capabilities.Drop, corev1.Capability("ALL")) {
				t.Error("capabilities are not dropped before being added back")
			}
			want := []corev1.Capability{"NET_RAW", "NET_ADMIN"}
			if !slices.Equal(sc.Capabilities.Add, want) {
				t.Errorf("added capabilities = %v, want exactly %v", sc.Capabilities.Add, want)
			}
		})
	}
}

func TestAnalyzerContainersAreNeverPrivileged(t *testing.T) {
	// privileged: true would grant every capability, device access, and kernel
	// module loading in order to obtain the two above.
	spec := renderer().PodSpec(testTap())

	for _, c := range spec.Containers {
		if c.SecurityContext == nil {
			t.Fatalf("container %s has no security context", c.Name)
		}
		if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			t.Errorf("container %s is privileged", c.Name)
		}
		if c.SecurityContext.AllowPrivilegeEscalation == nil || *c.SecurityContext.AllowPrivilegeEscalation {
			t.Errorf("container %s allows privilege escalation", c.Name)
		}
	}
	for _, c := range spec.InitContainers {
		if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			t.Errorf("init container %s is privileged", c.Name)
		}
	}
}

func TestSensorSidecarHoldsNoCapabilities(t *testing.T) {
	// The split that makes the pod defensible: the containers with capture
	// privilege have no API reach, and the container with API reach has no
	// privilege.
	spec := renderer().PodSpec(testTap())

	sensor := containerByName(spec, "sensor-agent")
	if sensor == nil {
		t.Fatal("no sensor-agent container")
	}
	if len(sensor.SecurityContext.Capabilities.Add) != 0 {
		t.Errorf("sensor holds capabilities: %v", sensor.SecurityContext.Capabilities.Add)
	}
	if sensor.SecurityContext.RunAsNonRoot == nil || !*sensor.SecurityContext.RunAsNonRoot {
		t.Error("sensor does not run as non-root")
	}
}

func TestOnlyTheSensorReceivesAnAPIToken(t *testing.T) {
	// A packet-capture container with a Kubernetes token is a compromised host
	// interface with cluster API reach.
	spec := renderer().PodSpec(testTap())

	if spec.AutomountServiceAccountToken == nil || *spec.AutomountServiceAccountToken {
		t.Error("the pod automounts a service-account token into every container")
	}

	for _, c := range spec.Containers {
		hasToken := slices.ContainsFunc(c.VolumeMounts, func(m corev1.VolumeMount) bool {
			return m.Name == tokenVolume
		})
		if c.Name == "sensor-agent" {
			if !hasToken {
				t.Error("the sensor has no token mount and cannot report status")
			}
			continue
		}
		if hasToken {
			t.Errorf("analyzer container %s has a Kubernetes token mounted", c.Name)
		}
	}
}

func TestProjectedTokenIsShortLived(t *testing.T) {
	// A projected token is refreshed by the kubelet, so a long lifetime only
	// widens the window in which a leaked one is useful.
	spec := renderer().PodSpec(testTap())

	for _, v := range spec.Volumes {
		if v.Name != tokenVolume {
			continue
		}
		if v.Projected == nil || len(v.Projected.Sources) == 0 {
			t.Fatal("token volume is not a projected volume")
		}
		exp := v.Projected.Sources[0].ServiceAccountToken.ExpirationSeconds
		if exp == nil || *exp > 3600 {
			t.Errorf("token expiration = %v, want <= 3600s", exp)
		}
		return
	}
	t.Fatal("no projected token volume rendered")
}

func TestPodSharesOnlyTheHostNetworkNamespace(t *testing.T) {
	// The interface being observed belongs to the host, so hostNetwork is
	// unavoidable. Host PID, IPC, and filesystem are not, and each would extend
	// the blast radius of a compromised analyzer well past packet capture.
	spec := renderer().PodSpec(testTap())

	if !spec.HostNetwork {
		t.Error("hostNetwork is not set; the pod cannot see the host interface")
	}
	if spec.HostPID {
		t.Error("hostPID is set")
	}
	if spec.HostIPC {
		t.Error("hostIPC is set")
	}
	if spec.DNSPolicy != corev1.DNSClusterFirstWithHostNet {
		t.Errorf("dnsPolicy = %q; host-network pods need ClusterFirstWithHostNet to resolve cluster names", spec.DNSPolicy)
	}
}

func TestNoHostPathVolumes(t *testing.T) {
	// A hostPath would write evidence to a node the operator cannot audit and
	// breaks the immutable-host model.
	spec := renderer().PodSpec(testTap())

	for _, v := range spec.Volumes {
		if v.HostPath != nil {
			t.Errorf("volume %s is a hostPath", v.Name)
		}
	}
}

func TestSharedVolumesAreBounded(t *testing.T) {
	// An unbounded emptyDir on a sensor node is how a runaway fetch or a
	// downstream stall fills the node's disk and takes out unrelated workloads.
	spec := renderer().PodSpec(testTap())

	for _, v := range spec.Volumes {
		if v.EmptyDir == nil {
			continue
		}
		if v.EmptyDir.SizeLimit == nil || v.EmptyDir.SizeLimit.IsZero() {
			t.Errorf("emptyDir volume %s has no size limit", v.Name)
		}
	}
}

func TestAnalyzersMountContentReadOnly(t *testing.T) {
	// An analyzer must not be able to rewrite the detection rules it is being
	// evaluated against.
	spec := renderer().PodSpec(testTap())

	for _, name := range []string{"suricata", "zeek"} {
		c := containerByName(spec, name)
		for _, m := range c.VolumeMounts {
			if m.Name == contentVolume && !m.ReadOnly {
				t.Errorf("%s mounts analyzer content writable", name)
			}
		}
	}
}

func TestContentInitContainersRenderPerAnalyzer(t *testing.T) {
	// ADR-0005: content is resolved by init containers so an analyzer can never
	// start against half-written rules.
	spec := renderer().PodSpec(testTap())

	names := make([]string, 0, len(spec.InitContainers))
	for _, c := range spec.InitContainers {
		names = append(names, c.Name)
	}
	for _, want := range []string{"content-suricata", "content-zeek"} {
		if !slices.Contains(names, want) {
			t.Errorf("no %s init container; got %v", want, names)
		}
	}
}

func TestCustomContentRendersASeparateInitContainer(t *testing.T) {
	// A separate container rather than a flag, so a failed custom pull is
	// attributable on its own and cannot be confused with an upstream problem.
	tap := testTap()
	tap.Spec.Analyzers.Suricata.CustomContent = &trawlv1alpha1.CustomContentRef{
		Reference: "registry.example/custom@sha256:" + strings.Repeat("f", 64),
	}
	spec := renderer().PodSpec(tap)

	var custom *corev1.Container
	for i := range spec.InitContainers {
		if spec.InitContainers[i].Name == "content-suricata-custom" {
			custom = &spec.InitContainers[i]
		}
	}
	if custom == nil {
		t.Fatal("no custom content init container rendered")
	}
	if !slices.ContainsFunc(custom.Args, func(a string) bool {
		return strings.HasPrefix(a, "--reference=") && strings.Contains(a, "sha256:")
	}) {
		t.Errorf("custom init container args do not carry a digest reference: %v", custom.Args)
	}
}

func TestNoCustomInitContainerWhenNoneDeclared(t *testing.T) {
	spec := renderer().PodSpec(testTap())
	for _, c := range spec.InitContainers {
		if strings.HasSuffix(c.Name, "-custom") {
			t.Errorf("custom content init container %s rendered without a reference", c.Name)
		}
	}
}

func TestOnlyEnabledAnalyzersAreRendered(t *testing.T) {
	tap := testTap()
	tap.Spec.Analyzers.Zeek.Enabled = false
	spec := renderer().PodSpec(tap)

	if containerByName(spec, "zeek") != nil {
		t.Error("a disabled analyzer was rendered")
	}
	if containerByName(spec, "suricata") == nil {
		t.Error("the enabled analyzer was not rendered")
	}
	for _, c := range spec.InitContainers {
		if strings.Contains(c.Name, "zeek") {
			t.Errorf("init container %s rendered for a disabled analyzer", c.Name)
		}
	}
}

func TestSensorResourcesComeFromInstallationConfig(t *testing.T) {
	// Not from the NetworkTap: an under-provisioned sensor drops observations
	// silently, and that is not a knob a tap author should be able to get wrong.
	spec := renderer().PodSpec(testTap())
	sensor := containerByName(spec, "sensor-agent")

	if got := sensor.Resources.Requests.Cpu().String(); got != "50m" {
		t.Errorf("sensor cpu request = %q, want the installation default 50m", got)
	}
	if got := sensor.Resources.Limits.Memory().String(); got != "256Mi" {
		t.Errorf("sensor memory limit = %q, want the installation default 256Mi", got)
	}
}

func TestAnalyzerResourcesComeFromTheTap(t *testing.T) {
	spec := renderer().PodSpec(testTap())
	suricata := containerByName(spec, "suricata")

	if got := suricata.Resources.Limits.Cpu().String(); got != "1" {
		t.Errorf("suricata cpu limit = %q, want the tap's 1", got)
	}
}

func TestAllImagesAreDigestPinned(t *testing.T) {
	spec := renderer().PodSpec(testTap())

	all := append(append([]corev1.Container{}, spec.Containers...), spec.InitContainers...)
	for _, c := range all {
		if !strings.Contains(c.Image, "@sha256:") {
			t.Errorf("container %s uses a non-digest image %q", c.Name, c.Image)
		}
	}
}

func TestMirrorSourceRendersASingleReplicaDeployment(t *testing.T) {
	// The SPAN port is wired to one node; a second replica would be a pod with
	// nothing to observe.
	deployment, daemonSet := renderer().Workload(testTap())

	if deployment == nil {
		t.Fatal("mirror source did not render a Deployment")
	}
	if daemonSet != nil {
		t.Error("mirror source also rendered a DaemonSet")
	}
	if deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 1 {
		t.Errorf("replicas = %v, want 1", deployment.Spec.Replicas)
	}
}

func TestMirrorDeploymentUsesRecreateStrategy(t *testing.T) {
	// Two pods cannot hold the same mirror interface in promiscuous mode at
	// once; an overlap would duplicate every observation for the rollout.
	deployment, _ := renderer().Workload(testTap())

	if deployment.Spec.Strategy.Type != "Recreate" {
		t.Errorf("strategy = %q, want Recreate", deployment.Spec.Strategy.Type)
	}
}

func TestNodeSourceRendersADaemonSet(t *testing.T) {
	tap := testTap()
	tap.Spec.Type = trawlv1alpha1.TapSourceNodeInterface
	tap.Spec.NodeInterface = tap.Spec.MirrorInterface
	tap.Spec.MirrorInterface = nil

	deployment, daemonSet := renderer().Workload(tap)
	if daemonSet == nil {
		t.Fatal("node source did not render a DaemonSet")
	}
	if deployment != nil {
		t.Error("node source also rendered a Deployment")
	}
	if daemonSet.Spec.UpdateStrategy.RollingUpdate.MaxUnavailable.IntValue() != 1 {
		t.Error("DaemonSet rollout is not limited to one node at a time")
	}
}

func TestNamesDeriveFromUIDNotName(t *testing.T) {
	// A tap deleted and recreated with the same name is a different object.
	// Reusing the name would let the new tap adopt the old one's workload and
	// its status history.
	a := testTap()
	b := testTap()
	b.UID = "99999999-3456-7890-abcd-ef1234567890"

	nameA, _, _, _ := Names(a)
	nameB, _, _, _ := Names(b)
	if nameA == nameB {
		t.Error("two taps with the same name but different UIDs render the same workload name")
	}
}

func TestStatusRoleIsScopedToTheOwningTap(t *testing.T) {
	// The sensor runs beside a container holding NET_RAW on a host network. An
	// unscoped grant would let a compromised pod report healthy monitoring for
	// every tap in the cluster while producing nothing.
	role := renderer().StatusRole(testTap())

	if len(role.Rules) == 0 {
		t.Fatal("no rules")
	}
	for _, rule := range role.Rules {
		if len(rule.ResourceNames) != 1 || rule.ResourceNames[0] != "north-south" {
			t.Errorf("rule is not scoped by resourceNames to the owning tap: %+v", rule)
		}
		if slices.Contains(rule.Verbs, "*") || slices.Contains(rule.Resources, "*") {
			t.Errorf("rule contains a wildcard: %+v", rule)
		}
		for _, verb := range rule.Verbs {
			if verb == "delete" || verb == "create" {
				t.Errorf("sensor role grants %q, which it never needs", verb)
			}
		}
	}
}

func TestStatusRoleGrantsOnlyTheStatusSubresource(t *testing.T) {
	// Patching the spec would let a sensor change what it is asked to observe.
	role := renderer().StatusRole(testTap())

	for _, rule := range role.Rules {
		for _, res := range rule.Resources {
			if res == "networktaps" {
				if !slices.Equal(rule.Verbs, []string{"get"}) {
					t.Errorf("spec access = %v, want read-only", rule.Verbs)
				}
			}
		}
	}
}

func TestServiceAccountDoesNotAutomountTokens(t *testing.T) {
	sa := renderer().ServiceAccount(testTap())
	if sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken {
		t.Error("the sensor service account automounts tokens")
	}
}

func TestPodTemplateRecordsTheRenderedGeneration(t *testing.T) {
	// A rollout should be attributable to a specific spec revision rather than
	// inferred from timestamps.
	deployment, _ := renderer().Workload(testTap())
	got := deployment.Spec.Template.Annotations["trawl.cloud/spec-generation"]
	if got != "3" {
		t.Errorf("spec-generation annotation = %q, want 3", got)
	}
}

// The content fetchers run with a read-only root filesystem, which is correct,
// but suricata-update unpacks the feed to a temporary directory. With nowhere
// writable it failed with "No usable temporary directory found in ['/tmp',
// '/var/tmp', '/usr/tmp', '/']" and the init container crash-looped, so the
// sensor never started and the tap sat in Pending reporting no packets. The
// answer is a scratch volume, not a writable root.
func TestContentInitContainersHaveWritableScratch(t *testing.T) {
	tap := testTap()
	spec := renderer().PodSpec(tap)

	if len(spec.InitContainers) == 0 {
		t.Fatal("no content init containers rendered")
	}

	for _, c := range spec.InitContainers {
		t.Run(c.Name, func(t *testing.T) {
			if c.SecurityContext == nil || c.SecurityContext.ReadOnlyRootFilesystem == nil ||
				!*c.SecurityContext.ReadOnlyRootFilesystem {
				t.Error("the root filesystem should stay read-only; the scratch mount is what makes that possible")
			}

			var mount *corev1.VolumeMount
			for i := range c.VolumeMounts {
				if c.VolumeMounts[i].MountPath == tmpPath {
					mount = &c.VolumeMounts[i]
					break
				}
			}
			if mount == nil {
				t.Fatalf("no writable mount at %s; the content fetch cannot unpack anywhere", tmpPath)
			}
			if mount.ReadOnly {
				t.Errorf("the scratch mount at %s is read-only", tmpPath)
			}

			// An unbounded emptyDir on a sensor node is a memory-pressure
			// eviction waiting for a large feed.
			for _, v := range spec.Volumes {
				if v.Name != mount.Name {
					continue
				}
				if v.EmptyDir == nil {
					t.Fatalf("volume %q backing %s is not an emptyDir", v.Name, tmpPath)
				}
				if v.EmptyDir.SizeLimit == nil {
					t.Errorf("volume %q has no size limit", v.Name)
				}
			}
		})
	}
}
