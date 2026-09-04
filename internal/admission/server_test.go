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
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func resourceRequest(object, oldObject string) admission.Request {
	req := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		UID:       "req-uid-1",
		Kind:      metav1.GroupVersionKind{Group: "trawl.cloud", Version: "v1alpha1", Kind: KindCaptureJob},
		Resource:  metav1.GroupVersionResource{Group: "trawl.cloud", Version: "v1alpha1", Resource: "capturejobs"},
		Name:      "manual-tls",
		Namespace: "trawl-system",
	}}
	if object != "" {
		req.Object = runtime.RawExtension{Raw: []byte(object)}
	}
	if oldObject != "" {
		req.OldObject = runtime.RawExtension{Raw: []byte(oldObject)}
	}
	return req
}

// The ledger exists to be joined: an admission record and the transition
// records that follow it describe one object. Recording req.UID as the
// resource's UID made resource.uid a copy of requestID and named the
// admission call instead, so the two halves of a capture's history could not
// be tied together by anything but namespace and name.
func TestResourceFromNamesTheObjectNotTheAdmissionCall(t *testing.T) {
	req := resourceRequest(`{"metadata":{"name":"manual-tls","uid":"obj-uid-1"}}`, "")

	got := ResourceFrom(req)
	if got.UID != "obj-uid-1" {
		t.Errorf("UID = %q, want the object's own uid", got.UID)
	}
	if got.UID == string(req.UID) {
		t.Errorf("UID = %q, which is the admission request's UID", got.UID)
	}
	if got.Name != "manual-tls" || got.Namespace != "trawl-system" || got.Kind != KindCaptureJob {
		t.Errorf("resource %+v does not describe the request", got)
	}
}

// A delete carries the object it is deleting in oldObject and nothing in
// object, so a record for one would otherwise name no resource at all.
func TestResourceFromFallsBackToTheOldObject(t *testing.T) {
	req := resourceRequest("", `{"metadata":{"name":"manual-tls","uid":"obj-uid-2"}}`)

	if got := ResourceFrom(req).UID; got != "obj-uid-2" {
		t.Errorf("UID = %q, want the old object's uid", got)
	}
}

// A create whose UID the apiserver has not stamped yet leaves the field
// empty. An empty UID does not identify the wrong thing, which is the whole
// improvement; requestID still ties the record to the API server's own audit.
func TestResourceFromLeavesTheUIDEmptyWhenTheObjectHasNone(t *testing.T) {
	req := resourceRequest(`{"metadata":{"name":"manual-tls"}}`, "")

	if got := ResourceFrom(req).UID; got != "" {
		t.Errorf("UID = %q, want empty rather than a borrowed one", got)
	}
}

// Malformed content must not take the webhook down; the record is simply
// written without a UID.
func TestResourceFromToleratesAnUndecodableObject(t *testing.T) {
	req := resourceRequest(`{"metadata":`, "")

	if got := ResourceFrom(req).UID; got != "" {
		t.Errorf("UID = %q, want empty", got)
	}
}
