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
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/capture"
	"trawl.cloud/trawl/internal/config"
)

// The capture runner pod is the second place Trawl grants packet-capture
// privilege, and unlike the tap it is created on demand by whoever may create
// a CaptureJob. These tests pin the same boundary the tap tests do: the
// container that can capture cannot reach the API, and the container that can
// reach the API cannot capture.

func testCaptureConfig() *config.Config {
	cfg := testConfig()
	cfg.Images.CaptureReporter = "ghcr.io/trawl/x@sha256:" + strings.Repeat("f", 64)
	cfg.Artifacts = config.BucketConfig{
		Endpoint: "minio.storage.svc:9000", Bucket: "trawl-artifacts", Region: "us-east-1",
	}
	cfg.Capture = config.CaptureConfig{
		CredentialsSecret: "trawl-artifact-credentials",
		StartupBudget:     config.Duration(5 * time.Minute),
		UploadBudget:      config.Duration(15 * time.Minute),
		RunnerResources: config.ResourceRequirements{
			RequestsCPU: "100m", RequestsMemory: "128Mi",
			LimitsCPU: "1", LimitsMemory: "512Mi",
		},
		ReporterResources: config.ResourceRequirements{
			RequestsCPU: "10m", RequestsMemory: "32Mi",
			LimitsCPU: "100m", LimitsMemory: "64Mi",
		},
	}
	return cfg
}

func testCaptureJob() *trawlv1alpha1.CaptureJob {
	return &trawlv1alpha1.CaptureJob{
		ObjectMeta: metav1.ObjectMeta{
			Name: "manual-tls", Namespace: "trawl-system",
			UID: "12345678-abcd-ef01-2345-6789abcdef01", Generation: 2,
		},
		Spec: trawlv1alpha1.CaptureJobSpec{
			RequestType: trawlv1alpha1.CaptureRequestManual,
			TapRef:      corev1.LocalObjectReference{Name: "north-south"},
			TargetNode:  "sensor-01",
			Filter:      "tcp port 443",
			Duration:    "2m",
			MaxSize:     resource.MustParse("64Mi"),
			Retention:   "168h",
		},
	}
}

func testBounds(t *testing.T, job *trawlv1alpha1.CaptureJob) capture.Bounds {
	t.Helper()
	b, err := capture.ParseBounds(job.Spec)
	if err != nil {
		t.Fatalf("ParseBounds: %v", err)
	}
	return b
}

func captureRenderer() *CaptureRenderer { return &CaptureRenderer{Config: testCaptureConfig()} }

func capturePod(t *testing.T) corev1.PodSpec {
	t.Helper()
	job := testCaptureJob()
	return captureRenderer().PodSpec(job, testBounds(t, job), "enp5s0")
}

const flagInterface = "interface"

func reporterSidecar(spec corev1.PodSpec) *corev1.Container {
	for i := range spec.InitContainers {
		if spec.InitContainers[i].Name == "capture-reporter" {
			return &spec.InitContainers[i]
		}
	}
	return nil
}

func TestRunnerGetsExactlyTwoCapabilities(t *testing.T) {
	spec := capturePod(t)
	c := containerByName(spec, "capture-runner")
	if c == nil {
		t.Fatal("no capture-runner container rendered")
	}
	sc := c.SecurityContext
	if sc == nil {
		t.Fatal("no security context")
	}
	if !slices.Contains(sc.Capabilities.Drop, corev1.Capability("ALL")) {
		t.Error("capabilities are not dropped before being added back")
	}
	want := []corev1.Capability{capNetRaw, capNetAdmin}
	if !slices.Equal(sc.Capabilities.Add, want) {
		t.Errorf("added capabilities = %v, want exactly %v", sc.Capabilities.Add, want)
	}
	if sc.Privileged != nil && *sc.Privileged {
		t.Error("runner is privileged")
	}
	if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
		t.Error("runner root filesystem is writable")
	}
}

func TestReporterHoldsNoCapabilities(t *testing.T) {
	spec := capturePod(t)
	c := reporterSidecar(spec)
	if c == nil {
		t.Fatal("no capture-reporter sidecar rendered")
	}
	sc := c.SecurityContext
	if sc == nil {
		t.Fatal("no security context")
	}
	if len(sc.Capabilities.Add) != 0 {
		t.Errorf("reporter adds capabilities %v; it needs none", sc.Capabilities.Add)
	}
	if sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
		t.Error("reporter may run as root")
	}
}

func TestReporterIsANativeSidecar(t *testing.T) {
	// An init container with restartPolicy Always starts before the runner
	// and is still running when the runner exits, so the final result record
	// is read; and the pod still completes once the runner does. Without the
	// policy it would be an ordinary init container and block the runner
	// forever.
	spec := capturePod(t)
	c := reporterSidecar(spec)
	if c == nil {
		t.Fatal("no capture-reporter sidecar rendered")
	}
	if c.RestartPolicy == nil || *c.RestartPolicy != corev1.ContainerRestartPolicyAlways {
		t.Errorf("reporter restartPolicy = %v, want Always", c.RestartPolicy)
	}
	if len(spec.Containers) != 1 || spec.Containers[0].Name != "capture-runner" {
		t.Errorf("regular containers = %v, want only the runner so its exit code is the pod's", names(spec.Containers))
	}
}

func names(cs []corev1.Container) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Name)
	}
	return out
}

func TestOnlyTheReporterReceivesAnAPIToken(t *testing.T) {
	spec := capturePod(t)
	if spec.AutomountServiceAccountToken == nil || *spec.AutomountServiceAccountToken {
		t.Error("pod automounts a service account token into every container")
	}
	runner := containerByName(spec, "capture-runner")
	reporter := reporterSidecar(spec)
	if runner == nil || reporter == nil {
		t.Fatal("containers missing")
	}
	if mountOf(runner, captureTokenVolume) != nil {
		t.Error("runner mounts the API token")
	}
	m := mountOf(reporter, captureTokenVolume)
	if m == nil {
		t.Fatal("reporter does not mount the API token")
	}
	if !m.ReadOnly {
		t.Error("token mount is writable")
	}
}

func TestOnlyTheRunnerReceivesBucketCredentials(t *testing.T) {
	spec := capturePod(t)
	runner := containerByName(spec, "capture-runner")
	reporter := reporterSidecar(spec)
	if runner == nil || reporter == nil {
		t.Fatal("containers missing")
	}
	if mountOf(reporter, captureCredentialsVolume) != nil {
		t.Error("reporter mounts the bucket credentials")
	}
	m := mountOf(runner, captureCredentialsVolume)
	if m == nil {
		t.Fatal("runner does not mount the bucket credentials")
	}
	if !m.ReadOnly {
		t.Error("credential mount is writable")
	}
	for _, c := range append(spec.InitContainers, spec.Containers...) {
		for _, e := range c.Env {
			if strings.Contains(strings.ToUpper(e.Name), "SECRET") || strings.Contains(strings.ToUpper(e.Name), "KEY") {
				t.Errorf("container %s carries %s in its environment; credentials are file mounts only", c.Name, e.Name)
			}
		}
	}
	var vol *corev1.Volume
	for i := range spec.Volumes {
		if spec.Volumes[i].Name == captureCredentialsVolume {
			vol = &spec.Volumes[i]
		}
	}
	if vol == nil || vol.Secret == nil {
		t.Fatal("credential volume is not a Secret")
	}
	if vol.Secret.SecretName != "trawl-artifact-credentials" {
		t.Errorf("credential Secret = %q, want the configured one", vol.Secret.SecretName)
	}
	if vol.Secret.DefaultMode == nil || *vol.Secret.DefaultMode != 0o400 {
		t.Errorf("credential mode = %v, want 0400", vol.Secret.DefaultMode)
	}
}

func mountOf(c *corev1.Container, volume string) *corev1.VolumeMount {
	for i := range c.VolumeMounts {
		if c.VolumeMounts[i].Name == volume {
			return &c.VolumeMounts[i]
		}
	}
	return nil
}

func TestReporterReadsProgressButCannotWriteIt(t *testing.T) {
	spec := capturePod(t)
	reporter := reporterSidecar(spec)
	runner := containerByName(spec, "capture-runner")
	rm := mountOf(reporter, captureProgressVolume)
	if rm == nil || !rm.ReadOnly {
		t.Error("reporter's progress mount is missing or writable")
	}
	wm := mountOf(runner, captureProgressVolume)
	if wm == nil || wm.ReadOnly {
		t.Error("runner's progress mount is missing or read-only")
	}
	if rm != nil && wm != nil && rm.MountPath != wm.MountPath {
		t.Errorf("progress paths differ: reporter %s, runner %s", rm.MountPath, wm.MountPath)
	}
}

func TestPodSharesOnlyTheHostNetwork(t *testing.T) {
	spec := capturePod(t)
	if !spec.HostNetwork {
		t.Error("hostNetwork is off; the interface is on the host")
	}
	if spec.HostPID || spec.HostIPC {
		t.Error("pod shares host PID or IPC namespaces")
	}
	if spec.DNSPolicy != corev1.DNSClusterFirstWithHostNet {
		t.Errorf("dnsPolicy = %q; a host-network pod resolves cluster names only with ClusterFirstWithHostNet", spec.DNSPolicy)
	}
	if spec.SecurityContext == nil || spec.SecurityContext.SeccompProfile == nil ||
		spec.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Error("pod does not set the RuntimeDefault seccomp profile")
	}
}

func TestNoHostPathVolumesInTheRunnerPod(t *testing.T) {
	for _, v := range capturePod(t).Volumes {
		if v.HostPath != nil {
			t.Errorf("volume %s is a hostPath", v.Name)
		}
	}
}

func TestRunnerVolumesAreBoundedByTheCapture(t *testing.T) {
	job := testCaptureJob()
	bounds := testBounds(t, job)
	spec := captureRenderer().PodSpec(job, bounds, "enp5s0")
	for _, v := range spec.Volumes {
		if v.EmptyDir == nil {
			continue
		}
		if v.EmptyDir.SizeLimit == nil || v.EmptyDir.SizeLimit.IsZero() {
			t.Errorf("emptyDir %s has no size limit", v.Name)
			continue
		}
		if v.Name == captureWorkVolume {
			want := capture.WorkVolumeBytes(bounds)
			if got := v.EmptyDir.SizeLimit.Value(); got != want {
				t.Errorf("work volume limit = %d, want %d (max size plus headroom)", got, want)
			}
		}
	}
	runner := containerByName(spec, "capture-runner")
	eph, ok := runner.Resources.Limits[corev1.ResourceEphemeralStorage]
	if !ok {
		t.Fatal("runner has no ephemeral-storage limit")
	}
	if eph.Value() < capture.WorkVolumeBytes(bounds) {
		t.Errorf("ephemeral-storage limit %d is below the work volume %d", eph.Value(), capture.WorkVolumeBytes(bounds))
	}
}

func TestRunnerJobRunsOnceOnTheTargetNode(t *testing.T) {
	job := testCaptureJob()
	bounds := testBounds(t, job)
	rendered := captureRenderer().Job(job, bounds, "enp5s0")
	if rendered.Spec.BackoffLimit == nil || *rendered.Spec.BackoffLimit != 0 {
		t.Error("backoffLimit is not 0; a retried capture is a different window")
	}
	if rendered.Spec.PodReplacementPolicy == nil || *rendered.Spec.PodReplacementPolicy != batchv1.Failed {
		t.Error("podReplacementPolicy is not Failed; a replacement could open the interface twice")
	}
	if rendered.Spec.TTLSecondsAfterFinished != nil {
		t.Error("Job sets a TTL; the owner reference is what cleans it up")
	}
	want := capture.ActiveDeadline(bounds, 5*time.Minute, 15*time.Minute)
	if rendered.Spec.ActiveDeadlineSeconds == nil || *rendered.Spec.ActiveDeadlineSeconds != int64(want.Seconds()) {
		t.Errorf("activeDeadlineSeconds = %v, want %v", rendered.Spec.ActiveDeadlineSeconds, want.Seconds())
	}
	pod := rendered.Spec.Template.Spec
	if pod.NodeSelector[corev1.LabelHostname] != "sensor-01" {
		t.Errorf("nodeSelector = %v, want the target node", pod.NodeSelector)
	}
	if pod.RestartPolicy != corev1.RestartPolicyNever {
		t.Errorf("restartPolicy = %q, want Never", pod.RestartPolicy)
	}
	if rendered.Spec.Template.Annotations["trawl.cloud/spec-generation"] != "2" {
		t.Error("pod template does not record the generation it was rendered from")
	}
}

func TestRunnerArgsMatchTheRunnerBinary(t *testing.T) {
	known := map[string]bool{
		"namespace": true, "name": true, "uid": true, flagInterface: true, "filter": true,
		"duration": true, "max-size": true, "snaplen": true, "work-dir": true, "progress-dir": true,
		"dumpcap": true, "artifact-endpoint": true, "artifact-bucket": true, "artifact-region": true,
		"artifact-tls": true, "artifact-credentials-dir": true,
	}
	c := containerByName(capturePod(t), "capture-runner")
	seen := flagsOf(t, c.Args, known, "cmd/capture-runner")
	for _, required := range []string{flagInterface, "duration", "max-size", "artifact-endpoint", "artifact-bucket"} {
		if seen[required] == "" {
			t.Errorf("--%s is not passed", required)
		}
	}
	if seen[flagInterface] != "enp5s0" {
		t.Errorf("--interface = %q, want the resolved interface", seen[flagInterface])
	}
	if seen["filter"] != "tcp port 443" {
		t.Errorf("--filter = %q", seen["filter"])
	}
	if seen["artifact-credentials-dir"] != captureCredentialsPath {
		t.Errorf("--artifact-credentials-dir = %q does not match the mount", seen["artifact-credentials-dir"])
	}
}

func TestReporterArgsMatchTheReporterBinary(t *testing.T) {
	known := map[string]bool{
		"namespace": true, "name": true, "uid": true, "generation": true,
		"progress-dir": true, "token-dir": true, "interval": true,
	}
	c := reporterSidecar(capturePod(t))
	seen := flagsOf(t, c.Args, known, "cmd/capture-reporter")
	if seen["generation"] != "2" {
		t.Errorf("--generation = %q, want the job's generation", seen["generation"])
	}
	if seen["uid"] != "12345678-abcd-ef01-2345-6789abcdef01" {
		t.Errorf("--uid = %q", seen["uid"])
	}
	if seen["token-dir"] != tokenPath {
		t.Errorf("--token-dir = %q does not match the mount", seen["token-dir"])
	}
}

func flagsOf(t *testing.T, args []string, known map[string]bool, binary string) map[string]string {
	t.Helper()
	seen := map[string]string{}
	for _, arg := range args {
		name, value, ok := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
		if !ok {
			t.Errorf("argument %q is not a --name=value flag", arg)
			continue
		}
		if !known[name] {
			t.Errorf("--%s is passed but %s does not define it; the binary exits 2 on an unknown flag", name, binary)
		}
		seen[name] = value
	}
	return seen
}

func TestCaptureImagesAreDigestPinned(t *testing.T) {
	for _, c := range append(capturePod(t).InitContainers, capturePod(t).Containers...) {
		if !strings.Contains(c.Image, "@sha256:") {
			t.Errorf("container %s image %q is not digest-pinned", c.Name, c.Image)
		}
	}
}

func TestCaptureNamesDeriveFromUIDNotName(t *testing.T) {
	a := testCaptureJob()
	b := testCaptureJob()
	b.UID = "fedcba98-7654-3210-fedc-ba9876543210"
	ja, _, _ := CaptureNames(a)
	jb, _, _ := CaptureNames(b)
	if ja == jb {
		t.Errorf("two captures named %q got the same Job name %q; a recreated capture would adopt the old Job", a.Name, ja)
	}
	if strings.Contains(ja, a.Name) {
		t.Errorf("Job name %q embeds the capture name", ja)
	}
}

func TestCaptureStatusRoleIsScopedToTheOwningJob(t *testing.T) {
	job := testCaptureJob()
	role := captureRenderer().StatusRole(job)
	if len(role.Rules) != 1 {
		t.Fatalf("role has %d rules, want 1", len(role.Rules))
	}
	rule := role.Rules[0]
	if !slices.Equal(rule.ResourceNames, []string{job.Name}) {
		t.Errorf("resourceNames = %v, want [%s]", rule.ResourceNames, job.Name)
	}
	if !slices.Equal(rule.Resources, []string{"capturejobs/status"}) {
		t.Errorf("resources = %v, want only the status subresource", rule.Resources)
	}
	if !slices.Equal(rule.Verbs, []string{"patch"}) {
		t.Errorf("verbs = %v, want only patch (server-side apply)", rule.Verbs)
	}
	binding := captureRenderer().StatusRoleBinding(job)
	sa := captureRenderer().ServiceAccount(job)
	if binding.RoleRef.Name != role.Name || binding.Subjects[0].Name != sa.Name {
		t.Error("binding does not join the rendered role and service account")
	}
	if sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken {
		t.Error("service account automounts tokens")
	}
}

func TestReporterTokenProjectionCarriesTheCA(t *testing.T) {
	var vol *corev1.Volume
	spec := capturePod(t)
	for i := range spec.Volumes {
		if spec.Volumes[i].Name == captureTokenVolume {
			vol = &spec.Volumes[i]
		}
	}
	if vol == nil || vol.Projected == nil {
		t.Fatal("token volume is not projected")
	}
	var token, ca bool
	for _, s := range vol.Projected.Sources {
		if s.ServiceAccountToken != nil {
			token = true
			if s.ServiceAccountToken.ExpirationSeconds == nil || *s.ServiceAccountToken.ExpirationSeconds > 3600 {
				t.Error("token lives longer than an hour")
			}
		}
		if s.ConfigMap != nil && s.ConfigMap.Name == "kube-root-ca.crt" {
			ca = true
		}
	}
	if !token || !ca {
		t.Errorf("projection token=%v ca=%v; the reporter needs both with automount off", token, ca)
	}
}
