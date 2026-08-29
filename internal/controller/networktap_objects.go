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

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
)

// Workload renders the tap's analyzer workload.
//
// A mirror source becomes a single-replica Deployment: the SPAN port is wired to
// exactly one node, so more than one replica would be a second pod with nothing
// to observe. A node source becomes a DaemonSet, since every selected node has
// its own interface to watch.
func (r *WorkloadRenderer) Workload(tap *trawlv1alpha1.NetworkTap) (deployment *appsv1.Deployment, daemonSet *appsv1.DaemonSet) {
	name, _, _, _ := Names(tap)
	labels := Labels(tap)
	src := sourceOf(tap)

	podTemplate := corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Labels: labels,
			Annotations: map[string]string{
				// The rendered generation is recorded so a rollout is
				// attributable to a specific spec revision rather than inferred
				// from timestamps.
				"trawl.cloud/spec-generation": itoa(tap.Generation),
			},
		},
		Spec: r.PodSpec(tap),
	}
	podTemplate.Spec.NodeSelector = src.NodeSelector.MatchLabels

	selector := &metav1.LabelSelector{MatchLabels: map[string]string{
		"trawl.cloud/tap-uid": string(tap.UID),
	}}

	if tap.Spec.Type == trawlv1alpha1.TapSourceMirrorInterface {
		return &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: tap.Namespace, Labels: labels},
			Spec: appsv1.DeploymentSpec{
				Replicas: ptr.To(int32(1)),
				Selector: selector,
				Template: podTemplate,
				Strategy: appsv1.DeploymentStrategy{
					// Recreate, not RollingUpdate. Two pods cannot hold the same
					// mirror interface in promiscuous mode at once, and an
					// overlap would duplicate every observation for the duration
					// of the rollout.
					Type: appsv1.RecreateDeploymentStrategyType,
				},
			},
		}, nil
	}

	return nil, &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: tap.Namespace, Labels: labels},
		Spec: appsv1.DaemonSetSpec{
			Selector: selector,
			Template: podTemplate,
			UpdateStrategy: appsv1.DaemonSetUpdateStrategy{
				Type: appsv1.RollingUpdateDaemonSetStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDaemonSet{
					// One node at a time: a rollout must not blind the whole
					// cluster's monitoring simultaneously.
					MaxUnavailable: ptrIntOrString(1),
				},
			},
		},
	}
}

// ConfigMap renders analyzer configuration for a tap.
func (r *WorkloadRenderer) ConfigMap(tap *trawlv1alpha1.NetworkTap) *corev1.ConfigMap {
	_, _, cmName, _ := Names(tap)
	src := sourceOf(tap)

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: tap.Namespace,
			Labels:    Labels(tap),
		},
		Data: map[string]string{
			"interface":   src.Interface,
			"promiscuous": boolString(src.Promiscuous),
			"tap-uid":     string(tap.UID),
			"cluster":     r.Config.ClusterID,
		},
	}
}

func itoa(i int64) string { return strconv.FormatInt(i, 10) }

func boolString(b bool) string { return strconv.FormatBool(b) }

func ptrIntOrString(i int32) *intstr.IntOrString {
	v := intstr.FromInt32(i)
	return &v
}
