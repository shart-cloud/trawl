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

// Package controller reconciles Trawl resources.
package controller

import (
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/config"
)

// Volume and path names shared by the rendered containers.
const (
	contentVolume = "analyzer-content"
	contentPath   = "/var/lib/trawl/content"

	logsVolume = "analyzer-logs"
	logsPath   = "/var/log/trawl"

	// tokenVolume carries the sensor's projected service-account token. Only
	// the sensor gets one; the analyzers get none.
	tokenVolume = "sensor-token"

	// Scratch space for the content fetchers. They run with a read-only
	// root filesystem, and suricata-update needs somewhere to unpack to:
	// without it the fetch fails with "No usable temporary directory found
	// in ['/tmp', '/var/tmp', '/usr/tmp', '/']" and the sensor never starts.
	// An emptyDir keeps the root filesystem read-only rather than trading
	// the hardening away for a writable path.
	tmpVolume = "content-tmp"
	tmpPath   = "/tmp"

	// The sensor pod runs on the host network, so this is a port on the
	// node, not a private one. cmd/sensor-agent defaults to :9100, which is
	// node_exporter's well-known port - on any cluster that scrapes node
	// metrics the sensor loses the race and exits with "listen tcp :9100:
	// bind: address already in use". Chosen outside the Prometheus exporter
	// range so it does not collide with the next exporter either.
	sensorProbePort = 19100
	// tokenPath is a mount path, not a credential; the token itself is
	// projected by the kubelet and never appears in this repository.
	tokenPath = "/var/run/secrets/trawl" //nolint:gosec // G101: mount path

	// tokenExpirationSeconds is deliberately short. A projected token is
	// refreshed by the kubelet, so a long lifetime only widens the window in
	// which a leaked one is useful.
	tokenExpirationSeconds int64 = 3600
)

// contentVolumeSize bounds the shared content volume. Detection rulesets are
// tens of megabytes; an unbounded emptyDir on a sensor node is a way to fill
// the node's disk with a runaway fetch.
var contentVolumeSize = resource.MustParse("512Mi")

// logVolumeSize bounds in-flight analyzer logs. The sensor tails and forwards
// them continuously, so this only needs to absorb a downstream stall.
var logVolumeSize = resource.MustParse("1Gi")

// Bounded so a malformed feed cannot fill the node's memory.
var tmpVolumeSize = resource.MustParse("256Mi")

// WorkloadRenderer builds the Kubernetes objects for one NetworkTap.
//
// Rendering is a pure function of the tap and installation config. Keeping it
// free of client calls is what lets the privilege decisions below be asserted
// by golden tests rather than discovered in a cluster.
type WorkloadRenderer struct {
	Config *config.Config
}

// Names returns the deterministic names for a tap's generated resources.
//
// Names derive from the tap UID rather than its name. A tap deleted and
// recreated with the same name is a different object, and reusing the name
// would let the new tap adopt the old one's workload and its status history.
func Names(tap *trawlv1alpha1.NetworkTap) (workload, serviceAccount, configMap, role string) {
	base := fmt.Sprintf("trawl-tap-%s", shortUID(tap.UID))
	return base, base, base + "-config", base + "-status"
}

func shortUID(uid types.UID) string {
	s := string(uid)
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// Labels returns the identifying labels for a tap's resources.
func Labels(tap *trawlv1alpha1.NetworkTap) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "trawl",
		"app.kubernetes.io/component":  "sensor",
		"app.kubernetes.io/managed-by": "trawl-controller-manager",
		"trawl.cloud/tap":              tap.Name,
		"trawl.cloud/tap-uid":          string(tap.UID),
	}
}

// analyzerSecurityContext returns the security context for an analyzer
// container.
//
// This is the narrowest grant that can open an AF_PACKET socket and set
// promiscuous mode. Everything else is dropped:
//
//   - NET_RAW opens the packet socket.
//   - NET_ADMIN sets promiscuous mode on the interface.
//
// privileged is never set. It would grant every capability, device access, and
// the ability to load kernel modules, in order to obtain two (ADR-0004).
// Privilege escalation is disabled so a setuid binary inside the image cannot
// widen this, and the root filesystem is read-only because an analyzer writes
// only to the mounted log and content volumes.
func analyzerSecurityContext() *corev1.SecurityContext {
	return &corev1.SecurityContext{
		Capabilities: &corev1.Capabilities{
			Drop: []corev1.Capability{"ALL"},
			Add:  []corev1.Capability{"NET_RAW", "NET_ADMIN"},
		},
		Privileged:               ptr.To(false),
		AllowPrivilegeEscalation: ptr.To(false),
		ReadOnlyRootFilesystem:   ptr.To(true),
		RunAsNonRoot:             ptr.To(false), // packet capture needs uid 0 with the caps above
		SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
}

// restrictedSecurityContext returns the context for containers that never touch
// the packet path: the sensor sidecar and the content init containers.
//
// They run with no capabilities at all. The sensor reads files and talks to the
// API server; the content init containers fetch over HTTPS and write a volume.
// Neither needs any capability, so neither gets one.
func restrictedSecurityContext() *corev1.SecurityContext {
	return &corev1.SecurityContext{
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		Privileged:               ptr.To(false),
		AllowPrivilegeEscalation: ptr.To(false),
		ReadOnlyRootFilesystem:   ptr.To(true),
		RunAsNonRoot:             ptr.To(true),
		RunAsUser:                ptr.To(int64(65532)),
		SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
}

// enabledAnalyzers returns the analyzers this tap has turned on, in a stable
// order so rendered output is deterministic.
func enabledAnalyzers(tap *trawlv1alpha1.NetworkTap) []trawlv1alpha1.AnalyzerName {
	out := make([]trawlv1alpha1.AnalyzerName, 0, 2)
	if tap.Spec.Analyzers.Suricata.Enabled {
		out = append(out, trawlv1alpha1.AnalyzerSuricata)
	}
	if tap.Spec.Analyzers.Zeek.Enabled {
		out = append(out, trawlv1alpha1.AnalyzerZeek)
	}
	return out
}

func analyzerConfig(tap *trawlv1alpha1.NetworkTap, name trawlv1alpha1.AnalyzerName) trawlv1alpha1.AnalyzerConfig {
	if name == trawlv1alpha1.AnalyzerSuricata {
		return tap.Spec.Analyzers.Suricata
	}
	return tap.Spec.Analyzers.Zeek
}

// sourceOf returns the tap's active interface source.
func sourceOf(tap *trawlv1alpha1.NetworkTap) *trawlv1alpha1.InterfaceSource {
	if tap.Spec.Type == trawlv1alpha1.TapSourceMirrorInterface {
		return tap.Spec.MirrorInterface
	}
	return tap.Spec.NodeInterface
}

// PodSpec renders the analyzer pod for a tap.
//
// Structure, and why:
//
//   - hostNetwork, because the interface being observed belongs to the host.
//     A pod-network namespace cannot see the mirror NIC at all.
//   - One init container per analyzer to fetch upstream content, plus one more
//     when a custom overlay is declared. Content resolution is tied to the pod
//     that consumes it, so an analyzer can never start against half-written
//     rules (ADR-0005).
//   - One container per enabled analyzer, each with the two capabilities it
//     needs and nothing else.
//   - One sensor sidecar, unprivileged, holding the only API token in the pod.
func (r *WorkloadRenderer) PodSpec(tap *trawlv1alpha1.NetworkTap) corev1.PodSpec {
	src := sourceOf(tap)
	workloadName, saName, configMapName, _ := Names(tap)
	_ = workloadName

	spec := corev1.PodSpec{
		ServiceAccountName: saName,
		// The pod observes a host interface, so it must share the host network
		// namespace. It shares nothing else: no host PID, IPC, or filesystem.
		HostNetwork: true,
		DNSPolicy:   corev1.DNSClusterFirstWithHostNet,
		// Analyzer containers need uid 0 to hold NET_RAW; the pod-level context
		// still pins seccomp so that choice does not also relax syscalls.
		SecurityContext: &corev1.PodSecurityContext{
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
		// The sensor holds the pod's only API credential, so automounting is
		// off and the token is projected into the sensor alone.
		AutomountServiceAccountToken: ptr.To(false),
		Volumes:                      r.volumes(configMapName),
		InitContainers:               r.contentInitContainers(tap),
		Containers:                   r.containers(tap, src),
		NodeSelector:                 nil,
		Tolerations: []corev1.Toleration{{
			// A sensor on a tainted node is still expected to observe it;
			// otherwise the tap would silently skip exactly the nodes an
			// operator marked as special.
			Operator: corev1.TolerationOpExists,
		}},
	}
	return spec
}

func (r *WorkloadRenderer) volumes(configMapName string) []corev1.Volume {
	return []corev1.Volume{
		{
			Name: contentVolume,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: &contentVolumeSize},
			},
		},
		{
			Name: logsVolume,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: &logVolumeSize},
			},
		},
		{
			Name: tmpVolume,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: &tmpVolumeSize},
			},
		},
		{
			Name: "analyzer-config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: configMapName},
				},
			},
		},
		{
			Name: tokenVolume,
			VolumeSource: corev1.VolumeSource{
				Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{{
						ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
							Path:              "token",
							ExpirationSeconds: ptr.To(tokenExpirationSeconds),
						},
					}},
				},
			},
		},
	}
}

// contentInitContainers renders upstream fetch and optional custom overlay.
func (r *WorkloadRenderer) contentInitContainers(tap *trawlv1alpha1.NetworkTap) []corev1.Container {
	analyzers := enabledAnalyzers(tap)
	// Each analyzer contributes an upstream container and may add a custom one.
	out := make([]corev1.Container, 0, len(analyzers)*2)

	for _, name := range analyzers {
		cfg := analyzerConfig(tap, name)

		args := []string{
			"fetch-upstream",
			"--analyzer=" + string(name),
			"--content-dir=" + contentPath,
		}
		switch name {
		case trawlv1alpha1.AnalyzerSuricata:
			args = append(args, "--feed-url="+r.Config.Content.SuricataFeedURL)
		case trawlv1alpha1.AnalyzerZeek:
			args = append(args, "--script-repo="+r.Config.Content.ZeekScriptRepo)
		}

		out = append(out, corev1.Container{
			Name:            "content-" + lower(string(name)),
			Image:           r.Config.Images.ContentInit,
			Args:            args,
			SecurityContext: restrictedSecurityContext(),
			Resources:       contentInitResources(),
			VolumeMounts: []corev1.VolumeMount{
				{Name: contentVolume, MountPath: contentPath},
				{Name: tmpVolume, MountPath: tmpPath},
			},
		})

		if cfg.CustomContent != nil {
			// A second container rather than a flag on the first, so a failed
			// custom pull is attributable on its own and cannot be confused
			// with an upstream feed problem.
			out = append(out, corev1.Container{
				Name:  "content-" + lower(string(name)) + "-custom",
				Image: r.Config.Images.ContentInit,
				Args: []string{
					"overlay-custom",
					"--analyzer=" + string(name),
					"--content-dir=" + contentPath,
					"--reference=" + cfg.CustomContent.Reference,
				},
				SecurityContext: restrictedSecurityContext(),
				Resources:       contentInitResources(),
				VolumeMounts: []corev1.VolumeMount{
					{Name: contentVolume, MountPath: contentPath},
					{Name: tmpVolume, MountPath: tmpPath},
				},
			})
		}
	}
	return out
}

func (r *WorkloadRenderer) containers(tap *trawlv1alpha1.NetworkTap, src *trawlv1alpha1.InterfaceSource) []corev1.Container {
	analyzers := enabledAnalyzers(tap)
	// One container per analyzer, plus the sensor sidecar.
	out := make([]corev1.Container, 0, len(analyzers)+1)

	for _, name := range analyzers {
		cfg := analyzerConfig(tap, name)
		image := r.Config.Images.Suricata
		if name == trawlv1alpha1.AnalyzerZeek {
			image = r.Config.Images.Zeek
		}

		container := corev1.Container{
			Name:  lower(string(name)),
			Image: image,
			Args: []string{
				"--interface=" + src.Interface,
				"--content-dir=" + contentPath,
				"--log-dir=" + logsPath,
			},
			SecurityContext: analyzerSecurityContext(),
			VolumeMounts: []corev1.VolumeMount{
				// Content is read-only to the analyzer: it consumes what the
				// init containers resolved and must not be able to rewrite the
				// detection rules it is being evaluated against.
				{Name: contentVolume, MountPath: contentPath, ReadOnly: true},
				{Name: logsVolume, MountPath: logsPath},
				{Name: "analyzer-config", MountPath: "/etc/trawl", ReadOnly: true},
			},
		}
		if cfg.Resources != nil {
			container.Resources = *cfg.Resources
		}
		out = append(out, container)
	}

	out = append(out, r.sensorContainer(tap, src))
	return out
}

// sensorContainer renders the sensor sidecar.
//
// It is the only container in the pod with a Kubernetes token, and it has no
// capabilities. That split is deliberate: the containers with packet-capture
// privilege have no API reach, and the container with API reach has no
// privilege (ADR-0004 applies the same split to capture).
func (r *WorkloadRenderer) sensorContainer(tap *trawlv1alpha1.NetworkTap, src *trawlv1alpha1.InterfaceSource) corev1.Container {
	args := []string{
		"--tap-namespace=" + tap.Namespace,
		"--tap-name=" + tap.Name,
		"--tap-uid=" + string(tap.UID),
		"--interface=" + src.Interface,
		"--log-dir=" + logsPath,
		"--content-dir=" + contentPath,
		"--probe-addr=:" + strconv.Itoa(sensorProbePort),
	}

	// These are the switches that turn each reader on: cmd/sensor-agent treats
	// an empty value as "this analyzer is not present". Without them the sensor
	// starts, tails nothing and reports no observations, which is
	// indistinguishable from an interface with no traffic on it.
	//
	// The paths are where the analyzers actually write. Zeek has no flag to
	// redirect its output, so its entrypoint chdirs into the log directory;
	// Suricata's eve-log filename is set in images/suricata/suricata.yaml.
	for _, name := range enabledAnalyzers(tap) {
		switch name {
		case trawlv1alpha1.AnalyzerZeek:
			// Matches where images/zeek/entrypoint.sh chdirs to.
			args = append(args, "--zeek-log-dir="+logsPath+"/zeek")
		case trawlv1alpha1.AnalyzerSuricata:
			args = append(args, "--suricata-log="+logsPath+"/suricata/eve.json")
		}
	}

	return corev1.Container{
		Name:  "sensor-agent",
		Image: r.Config.Images.SensorAgent,
		Args:  args,
		Env: []corev1.EnvVar{{
			Name: "TRAWL_NODE_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
			},
		}, {
			// The status reporter uses this to identify the sensor process.
			// Counters restart with the pod, and without knowing the instance
			// changed a reader would see the reset as traffic having stopped.
			Name: "POD_NAME",
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"},
			},
		}},
		SecurityContext: restrictedSecurityContext(),
		// Resources come from installation config, never the NetworkTap: an
		// under-provisioned sensor drops observations silently, and that is not
		// a knob a tap author should be able to get wrong.
		Resources: sensorResources(r.Config),
		VolumeMounts: []corev1.VolumeMount{
			{Name: logsVolume, MountPath: logsPath, ReadOnly: true},
			{Name: contentVolume, MountPath: contentPath, ReadOnly: true},
			{Name: tokenVolume, MountPath: tokenPath, ReadOnly: true},
		},
		ReadinessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{Path: "/readyz", Port: intstr.FromInt32(sensorProbePort)},
			},
			InitialDelaySeconds: 5,
			PeriodSeconds:       10,
		},
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt32(sensorProbePort)},
			},
			InitialDelaySeconds: 10,
			PeriodSeconds:       20,
		},
	}
}

func sensorResources(cfg *config.Config) corev1.ResourceRequirements {
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse(cfg.SensorAgentResources.RequestsCPU),
			corev1.ResourceMemory: resource.MustParse(cfg.SensorAgentResources.RequestsMemory),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse(cfg.SensorAgentResources.LimitsCPU),
			corev1.ResourceMemory: resource.MustParse(cfg.SensorAgentResources.LimitsMemory),
		},
	}
}

// contentInitResources bounds the fetch containers. They are short-lived and
// network-bound, but an unbounded init container can still starve the analyzers
// it is meant to prepare.
func contentInitResources() corev1.ResourceRequirements {
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("50m"),
			corev1.ResourceMemory: resource.MustParse("64Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("500m"),
			corev1.ResourceMemory: resource.MustParse("512Mi"),
		},
	}
}

func lower(s string) string {
	return strings.ToLower(s)
}
