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

// Package v1alpha1 contains the Trawl API types.
//
// Stored field shapes are a compatibility commitment within v1alpha1 (plan.md,
// "Delivery, Upgrade, Rollback"). Additive fields need defaulting plus tests
// against objects written by an older operator; a breaking shape needs a new
// served and stored version with a conversion plan.
//
// The scheme is built on apimachinery alone rather than controller-runtime's
// helper. An API package should be cheap for a client to import, and pulling in
// controller-runtime would make every consumer of these types depend on the
// operator's machinery.
// +kubebuilder:object:generate=true
// +groupName=trawl.cloud
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// GroupVersion is the group and version these objects are registered under.
	GroupVersion = schema.GroupVersion{Group: "trawl.cloud", Version: "v1alpha1"}

	// SchemeBuilder registers the Go types for this group-version.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme adds the types in this group-version to a scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion,
		&NetworkTap{},
		&NetworkTapList{},
		&CaptureJob{},
		&CaptureJobList{},
	)
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}
