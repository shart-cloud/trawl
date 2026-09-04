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
	"strconv"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/capture"
	"trawl.cloud/trawl/internal/config"
)

// Volume and path names for the runner pod.
const (
	// captureWorkVolume holds the pcapng while dumpcap writes it. Its size
	// limit is the capture's size bound plus headroom, so a runner that
	// ignored its bound would be evicted rather than fill the node.
	captureWorkVolume = "work"
	captureWorkPath   = "/var/lib/trawl/capture"

	// captureProgressVolume carries the runner's milestone records to the
	// reporter. The runner writes it; the reporter only reads.
	captureProgressVolume = "progress"

	// captureCredentialsVolume is the artifact-bucket credential Secret,
	// mounted into the runner alone. The reporter never sees it.
	captureCredentialsVolume = "artifact-credentials"
	captureCredentialsPath   = "/var/run/secrets/trawl-artifacts" //nolint:gosec // G101: mount path

	// captureTokenVolume is the reporter's projected API token. Only the
	// reporter gets one: the container with capture privilege has no API
	// reach, and the container with API reach has no privilege (ADR-0004).
	captureTokenVolume = "reporter-token"

	// captureTerminationGrace covers the runner's SIGINT-then-wait stop
	// sequence plus the reporter's final read and apply.
	captureTerminationGrace int64 = 30

	// captureCredentialsMode keeps the credential files owner-readable only.
	captureCredentialsMode int32 = 0o400
)

// Bounded so a runner cannot spam the reporter's directory.
var captureProgressVolumeSize = resource.MustParse("1Mi")

// captureEphemeralHeadroom is what the runner's ephemeral-storage request
// carries beyond its volumes, for logs and the like.
var captureEphemeralHeadroom = resource.MustParse("64Mi")

// CaptureRenderer builds the Kubernetes objects for one CaptureJob.
//
// Like WorkloadRenderer it is a pure function of the object and installation
// config, so the privilege decisions below are asserted by tests rather than
// discovered on a node.
type CaptureRenderer struct {
	Config *config.Config
}

// CaptureNames returns the deterministic names for a capture's generated
// resources. They derive from the UID, not the name, so a capture deleted and
// recreated under the same name cannot adopt the old one's Job.
func CaptureNames(job *trawlv1alpha1.CaptureJob) (runnerJob, serviceAccount, role string) {
	base := "trawl-capture-" + shortUID(job.UID)
	return base, base, base + "-status"
}

// CaptureLabels returns the identifying labels for a capture's resources.
func CaptureLabels(job *trawlv1alpha1.CaptureJob) map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":       "trawl",
		"app.kubernetes.io/component":  runnerContainerName,
		"app.kubernetes.io/managed-by": "trawl-controller-manager",
		"trawl.cloud/capturejob":       job.Name,
		"trawl.cloud/capturejob-uid":   string(job.UID),
	}
}

// ServiceAccount renders the reporter's identity. The token is projected into
// the reporter container explicitly, so nothing automounts one.
func (r *CaptureRenderer) ServiceAccount(job *trawlv1alpha1.CaptureJob) *corev1.ServiceAccount {
	_, saName, _ := CaptureNames(job)
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      saName,
			Namespace: job.Namespace,
			Labels:    CaptureLabels(job),
		},
		AutomountServiceAccountToken: ptrFalse(),
	}
}

// StatusRole grants the reporter patch on this one capture's status and
// nothing else. resourceNames is what turns "may patch capture status" into
// "may patch this capture's status".
func (r *CaptureRenderer) StatusRole(job *trawlv1alpha1.CaptureJob) *rbacv1.Role {
	_, _, roleName := CaptureNames(job)
	return &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      roleName,
			Namespace: job.Namespace,
			Labels:    CaptureLabels(job),
		},
		Rules: []rbacv1.PolicyRule{{
			APIGroups:     []string{trawlv1alpha1.GroupVersion.Group},
			Resources:     []string{"capturejobs/status"},
			ResourceNames: []string{job.Name},
			Verbs:         []string{verbPatch},
		}},
	}
}

// StatusRoleBinding binds the reporter's account to its status role.
func (r *CaptureRenderer) StatusRoleBinding(job *trawlv1alpha1.CaptureJob) *rbacv1.RoleBinding {
	_, saName, roleName := CaptureNames(job)
	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      roleName,
			Namespace: job.Namespace,
			Labels:    CaptureLabels(job),
		},
		Subjects: []rbacv1.Subject{{
			Kind:      rbacv1.ServiceAccountKind,
			Name:      saName,
			Namespace: job.Namespace,
		}},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     roleName,
		},
	}
}

// Job renders the runner Job for a capture whose bounds have been parsed and
// whose interface has been resolved from the tap.
//
// One attempt only. A capture is a bounded window of time; a retry would be a
// different window, and the controller decides whether to make a new capture
// rather than the Job silently rerunning the old one. The active deadline is
// the only thing that ends a runner nothing else has: startup budget for
// scheduling and image pulls, the capture's own duration, then the upload
// budget.
func (r *CaptureRenderer) Job(job *trawlv1alpha1.CaptureJob, bounds capture.Bounds, iface string) *batchv1.Job {
	name, _, _ := CaptureNames(job)
	labels := CaptureLabels(job)
	deadline := capture.ActiveDeadline(bounds,
		r.Config.Capture.StartupBudget.Duration(), r.Config.Capture.UploadBudget.Duration())

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: job.Namespace, Labels: labels},
		Spec: batchv1.JobSpec{
			BackoffLimit:          ptr.To(int32(0)),
			Completions:           ptr.To(int32(1)),
			Parallelism:           ptr.To(int32(1)),
			ActiveDeadlineSeconds: ptr.To(int64(deadline.Seconds())),
			// A replacement pod for one that is only terminating would open
			// the interface twice; wait for the failure to be final.
			PodReplacementPolicy: ptr.To(batchv1.Failed),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
					Annotations: map[string]string{
						"trawl.cloud/spec-generation": itoa(job.Generation),
					},
				},
				Spec: r.PodSpec(job, bounds, iface),
			},
		},
	}
}

// PodSpec renders the runner pod.
//
// Two containers, split by privilege. The reporter is a native sidecar - an
// init container with restartPolicy Always - so it is running before the
// runner starts and outlives it, and a Job pod with a completed runner is
// still Complete. The runner is the pod's only regular container, so its
// exit code is the pod's.
func (r *CaptureRenderer) PodSpec(job *trawlv1alpha1.CaptureJob, bounds capture.Bounds, iface string) corev1.PodSpec {
	_, saName, _ := CaptureNames(job)
	return corev1.PodSpec{
		ServiceAccountName: saName,
		// Pinned to the node the tap reported; the interface is a name on
		// that host and no other.
		NodeSelector: map[string]string{corev1.LabelHostname: job.Spec.TargetNode},
		Tolerations: []corev1.Toleration{{
			Operator: corev1.TolerationOpExists,
		}},
		// The interface belongs to the host, so the pod shares the host
		// network namespace and nothing else.
		HostNetwork:   true,
		DNSPolicy:     corev1.DNSClusterFirstWithHostNet,
		RestartPolicy: corev1.RestartPolicyNever,
		SecurityContext: &corev1.PodSecurityContext{
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
		AutomountServiceAccountToken:  ptr.To(false),
		TerminationGracePeriodSeconds: ptr.To(captureTerminationGrace),
		Volumes:                       r.volumes(bounds),
		InitContainers:                []corev1.Container{r.reporterContainer(job)},
		Containers:                    []corev1.Container{r.runnerContainer(job, bounds, iface)},
	}
}

func (r *CaptureRenderer) volumes(bounds capture.Bounds) []corev1.Volume {
	work := resource.NewQuantity(capture.WorkVolumeBytes(bounds), resource.BinarySI)
	return []corev1.Volume{
		{
			Name: captureWorkVolume,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: work},
			},
		},
		{
			Name: captureProgressVolume,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: &captureProgressVolumeSize},
			},
		},
		{
			Name: captureCredentialsVolume,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName:  r.Config.Capture.CredentialsSecret,
					DefaultMode: ptr.To(captureCredentialsMode),
				},
			},
		},
		{
			Name: captureTokenVolume,
			VolumeSource: corev1.VolumeSource{
				Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{{
						ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
							Path:              "token",
							ExpirationSeconds: ptr.To(tokenExpirationSeconds),
						},
					}, {
						// automountServiceAccountToken is off, so the API
						// server's CA has to come with the token; see the
						// sensor's projection for the reasoning.
						ConfigMap: &corev1.ConfigMapProjection{
							LocalObjectReference: corev1.LocalObjectReference{Name: rootCAConfigMap},
							Items:                []corev1.KeyToPath{{Key: rootCAKey, Path: rootCAKey}},
						},
					}},
				},
			},
		},
	}
}

// runnerContainer renders dumpcap's container.
//
// It gets the two capabilities packet capture needs and no API token. Its
// arguments are the resolved capture parameters; the bucket credential is a
// file mount, never an environment variable, so it cannot be read out of the
// pod spec.
func (r *CaptureRenderer) runnerContainer(job *trawlv1alpha1.CaptureJob, bounds capture.Bounds, iface string) corev1.Container {
	artifacts := r.Config.Artifacts
	args := []string{
		"--namespace=" + job.Namespace,
		"--name=" + job.Name,
		"--uid=" + string(job.UID),
		"--interface=" + iface,
		"--filter=" + job.Spec.Filter,
		"--duration=" + bounds.Duration.String(),
		"--max-size=" + strconv.FormatInt(bounds.MaxSizeBytes, 10),
		"--snaplen=" + strconv.Itoa(int(bounds.Snaplen)),
		"--work-dir=" + captureWorkPath,
		"--progress-dir=" + capture.DefaultProgressDir,
		"--artifact-endpoint=" + artifacts.Endpoint,
		"--artifact-bucket=" + artifacts.Bucket,
		"--artifact-region=" + artifacts.Region,
		"--artifact-tls=" + strconv.FormatBool(artifacts.UseTLS),
		"--artifact-credentials-dir=" + captureCredentialsPath,
	}

	ephemeral := resource.NewQuantity(capture.WorkVolumeBytes(bounds), resource.BinarySI)
	ephemeral.Add(captureProgressVolumeSize)
	ephemeral.Add(captureEphemeralHeadroom)
	resources := resourcesFrom(r.Config.Capture.RunnerResources)
	resources.Requests[corev1.ResourceEphemeralStorage] = *ephemeral
	resources.Limits[corev1.ResourceEphemeralStorage] = *ephemeral

	return corev1.Container{
		Name:            runnerContainerName,
		Image:           r.Config.Images.CaptureRunner,
		Args:            args,
		SecurityContext: analyzerSecurityContext(),
		Resources:       resources,
		VolumeMounts: []corev1.VolumeMount{
			{Name: captureWorkVolume, MountPath: captureWorkPath},
			{Name: captureProgressVolume, MountPath: capture.DefaultProgressDir},
			{Name: captureCredentialsVolume, MountPath: captureCredentialsPath, ReadOnly: true},
		},
	}
}

// reporterContainer renders the status sidecar. No capabilities, no bucket
// credential, read-only view of the progress directory, and the pod's only
// API token.
func (r *CaptureRenderer) reporterContainer(job *trawlv1alpha1.CaptureJob) corev1.Container {
	return corev1.Container{
		Name:  "capture-reporter",
		Image: r.Config.Images.CaptureReporter,
		Args: []string{
			"--namespace=" + job.Namespace,
			"--name=" + job.Name,
			"--uid=" + string(job.UID),
			"--generation=" + itoa(job.Generation),
			"--progress-dir=" + capture.DefaultProgressDir,
			"--token-dir=" + tokenPath,
		},
		// Always is what makes an init container a sidecar: it starts before
		// the runner and keeps running alongside it.
		RestartPolicy:   ptr.To(corev1.ContainerRestartPolicyAlways),
		SecurityContext: restrictedSecurityContext(),
		Resources:       resourcesFrom(r.Config.Capture.ReporterResources),
		VolumeMounts: []corev1.VolumeMount{
			{Name: captureProgressVolume, MountPath: capture.DefaultProgressDir, ReadOnly: true},
			{Name: captureTokenVolume, MountPath: tokenPath, ReadOnly: true},
		},
	}
}

func resourcesFrom(rr config.ResourceRequirements) corev1.ResourceRequirements {
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse(rr.RequestsCPU),
			corev1.ResourceMemory: resource.MustParse(rr.RequestsMemory),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse(rr.LimitsCPU),
			corev1.ResourceMemory: resource.MustParse(rr.LimitsMemory),
		},
	}
}
