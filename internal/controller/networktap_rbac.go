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
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
)

// verbGet is the only verb the sensor needs on the tap's spec.
const verbGet = "get"

// ServiceAccount renders the identity for a tap's sensor pods.
func (r *WorkloadRenderer) ServiceAccount(tap *trawlv1alpha1.NetworkTap) *corev1.ServiceAccount {
	_, saName, _, _ := Names(tap)
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      saName,
			Namespace: tap.Namespace,
			Labels:    Labels(tap),
		},
		// The token is projected explicitly into the sensor container with a
		// short expiry, so the account itself does not automount one anywhere.
		AutomountServiceAccountToken: ptrFalse(),
	}
}

// StatusRole renders the sensor's Role.
//
// The grant is deliberately as narrow as Kubernetes RBAC allows: patch on the
// status subresource of one named NetworkTap. Not the kind, not the namespace —
// that single object.
//
// This matters because the sensor runs beside a container holding NET_RAW on a
// host network. If that pod were compromised, an unscoped grant would let it
// rewrite every tap's status and report healthy monitoring across the cluster
// while producing nothing. Scoping by resourceNames means the worst it can do
// is lie about itself, which the controller's own observations contradict.
func (r *WorkloadRenderer) StatusRole(tap *trawlv1alpha1.NetworkTap) *rbacv1.Role {
	_, _, _, roleName := Names(tap)
	return &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      roleName,
			Namespace: tap.Namespace,
			Labels:    Labels(tap),
		},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{trawlv1alpha1.GroupVersion.Group},
			Resources: []string{"networktaps/status"},
			// resourceNames is what turns "may patch tap status" into "may
			// patch this tap's status".
			ResourceNames: []string{tap.Name},
			Verbs:         []string{verbGet, "patch", "update"},
		}, {
			// Reading the owning tap's spec is needed to know which analyzers
			// are expected. Also scoped to the one object.
			APIGroups:     []string{trawlv1alpha1.GroupVersion.Group},
			Resources:     []string{"networktaps"},
			ResourceNames: []string{tap.Name},
			Verbs:         []string{verbGet},
		}},
	}
}

// StatusRoleBinding binds the sensor's Role to its ServiceAccount.
func (r *WorkloadRenderer) StatusRoleBinding(tap *trawlv1alpha1.NetworkTap) *rbacv1.RoleBinding {
	_, saName, _, roleName := Names(tap)
	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      roleName,
			Namespace: tap.Namespace,
			Labels:    Labels(tap),
		},
		Subjects: []rbacv1.Subject{{
			Kind:      rbacv1.ServiceAccountKind,
			Name:      saName,
			Namespace: tap.Namespace,
		}},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     roleName,
		},
	}
}

func ptrFalse() *bool {
	v := false
	return &v
}
