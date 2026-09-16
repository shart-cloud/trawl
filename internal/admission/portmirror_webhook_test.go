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
	"context"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/audit"
)

// The CRD schema owns shape: the provider and direction enums, the port-name
// pattern, MinItems on sources, and a CEL rule for the target/source overlap.
// What is tested here is what the schema cannot know - which namespace is the
// installation's, which fields name hardware this resource has already changed,
// and whether the mutation reached the ledger before it was admitted - plus the
// stored-object path through the rules the schema does own.

func mirrorWebhook() (*PortMirrorWebhook, *recordingCommitter) {
	committer := &recordingCommitter{}
	return &PortMirrorWebhook{
		Gate: &Gate{SystemNamespace: "trawl-system", Audit: committer},
	}, committer
}

// mirrorActor is the authenticated identity the admission requests here carry,
// asserted against what reaches the ledger.
const mirrorActor = "alice"

// mirrorRequestCtx is requestCtx for this kind. The kind in the request is what
// ActionFor dispatches on, so a shared helper carrying CaptureJob would have
// every assertion here pass against the wrong action.
func mirrorRequestCtx(op admissionv1.Operation) context.Context {
	req := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		UID:       types.UID("req-mirror-" + string(op)),
		Kind:      metav1.GroupVersionKind{Group: "trawl.cloud", Version: "v1alpha1", Kind: "PortMirror"},
		Resource:  metav1.GroupVersionResource{Group: "trawl.cloud", Version: "v1alpha1", Resource: "portmirrors"},
		Name:      "lab-switch-span",
		Namespace: "trawl-system",
		Operation: op,
		UserInfo:  authenticationv1.UserInfo{Username: mirrorActor, UID: "u"},
	}}
	return admission.NewContextWithRequest(context.Background(), req)
}

func validMirror() *trawlv1alpha1.PortMirror {
	return &trawlv1alpha1.PortMirror{
		ObjectMeta: metav1.ObjectMeta{
			Name: "lab-switch-span", Namespace: "trawl-system", UID: "mirror-uid",
		},
		Spec: trawlv1alpha1.PortMirrorSpec{
			Provider:  trawlv1alpha1.MirrorProviderMikroTikRouterOS7,
			DeviceRef: corev1.LocalObjectReference{Name: "lab-switch"},
			Sources:   []string{"ether1", "ether2"},
			Target:    "ether24",
			Direction: trawlv1alpha1.MirrorDirectionBoth,
		},
	}
}

func TestValidatePortMirrorAcceptsReferenceSpec(t *testing.T) {
	if errs := ValidatePortMirrorSpec(&validMirror().Spec); len(errs) > 0 {
		t.Fatalf("reference spec rejected: %v", errs)
	}
}

func TestPortMirrorIsRefusedOutsideTheSystemNamespace(t *testing.T) {
	// The gap this webhook closes. The controller already declines to act on an
	// off-namespace mirror, but until now the API server accepted one, so the
	// object existed and read as configuration that had taken effect. The CRD
	// contract says the validating webhook rejects it; for this kind that was
	// not true.
	w, committer := mirrorWebhook()

	for _, ns := range []string{"default", "kube-system", ""} {
		mirror := validMirror()
		mirror.Namespace = ns
		if _, err := w.ValidateCreate(t.Context(), mirror); err == nil {
			t.Errorf("a PortMirror in namespace %q was accepted", ns)
		}
	}
	if len(committer.records) != 0 {
		t.Errorf("a refused create was recorded as allowed: %v", committer.records)
	}
}

func TestPortMirrorRejectsRepointingToAnotherDevice(t *testing.T) {
	// Revert follows the current spec, so repointing a live mirror leaves the
	// previous switch copying traffic with nothing in the cluster recording it.
	w, _ := mirrorWebhook()
	old := validMirror()
	updated := validMirror()
	updated.Spec.DeviceRef.Name = "other-switch"

	_, err := w.ValidateUpdate(t.Context(), old, updated)
	if err == nil {
		t.Fatal("deviceRef was repointed on a live PortMirror")
	}
	if !strings.Contains(err.Error(), "deviceRef") {
		t.Errorf("error does not name the field: %v", err)
	}
}

func TestPortMirrorRejectsProviderChange(t *testing.T) {
	w, _ := mirrorWebhook()
	old := validMirror()
	updated := validMirror()
	updated.Spec.Provider = "MikroTikRouterOS8"

	if _, err := w.ValidateUpdate(t.Context(), old, updated); err == nil {
		t.Fatal("provider was changed on a live PortMirror")
	}
}

func TestPortMirrorAllowsReconfiguringTheSameDevice(t *testing.T) {
	// Changing which ports are copied is reconfiguring the device this resource
	// already owns, which the controller handles by rewriting its own mirror.
	// Making it immutable would mean deleting and recreating a resource to add
	// a source port, and each cycle un-configures the switch in between.
	w, committer := mirrorWebhook()
	old := validMirror()
	updated := validMirror()
	updated.Spec.Sources = []string{"ether1", "ether2", "ether3"}
	updated.Spec.Target = "ether23"
	updated.Spec.Direction = trawlv1alpha1.MirrorDirectionIngress

	ctx := mirrorRequestCtx(admissionv1.Update)
	if _, err := w.ValidateUpdate(ctx, old, updated); err != nil {
		t.Fatalf("reconfiguring the same device was rejected: %v", err)
	}
	if len(committer.records) != 1 {
		t.Fatalf("records = %d, want 1", len(committer.records))
	}
	if got := committer.records[0].Action; got != audit.ActionPortMirrorUpdate {
		t.Errorf("action = %q, want %q", got, audit.ActionPortMirrorUpdate)
	}
}

func TestValidatePortMirrorRejectsTargetAmongSources(t *testing.T) {
	// The CRD's CEL rule covers this on write. A stored object predating it
	// would configure a port to mirror itself, which the switch accepts.
	spec := validMirror().Spec
	spec.Target = "ether1"

	errs := ValidatePortMirrorSpec(&spec)
	if len(errs) == 0 {
		t.Fatal("a target that is also a source was accepted")
	}
	if !strings.Contains(errs.ToAggregate().Error(), "target must not also be a source") {
		t.Errorf("unexpected error: %v", errs)
	}
}

func TestValidatePortMirrorRejectsNamelessDeviceRef(t *testing.T) {
	// LocalObjectReference's name is optional, so "deviceRef: {}" is
	// structurally valid and refers to nothing.
	spec := validMirror().Spec
	spec.DeviceRef = corev1.LocalObjectReference{}

	errs := ValidatePortMirrorSpec(&spec)
	if len(errs) == 0 {
		t.Fatal("a PortMirror with no device Secret was accepted")
	}
	if !strings.Contains(errs.ToAggregate().Error(), "deviceRef") {
		t.Errorf("error does not name the field: %v", errs)
	}
}

func TestValidatePortMirrorRejectsDuplicateSources(t *testing.T) {
	// A duplicate is a second write to the same port, and the device returns
	// one copy - so a correctly configured mirror would report Degraded
	// forever, which is the worst of the available outcomes.
	spec := validMirror().Spec
	spec.Sources = []string{"ether1", "ether1"}

	if errs := ValidatePortMirrorSpec(&spec); len(errs) == 0 {
		t.Fatal("duplicate source ports were accepted")
	}
}

func TestValidatePortMirrorRejectsEmptyAndUnknownValues(t *testing.T) {
	base := validMirror().Spec
	for name, mutate := range map[string]func(*trawlv1alpha1.PortMirrorSpec){
		"no sources":        func(s *trawlv1alpha1.PortMirrorSpec) { s.Sources = nil },
		"blank source":      func(s *trawlv1alpha1.PortMirrorSpec) { s.Sources = []string{""} },
		"no target":         func(s *trawlv1alpha1.PortMirrorSpec) { s.Target = "" },
		"unknown provider":  func(s *trawlv1alpha1.PortMirrorSpec) { s.Provider = "Cisco" },
		"unknown direction": func(s *trawlv1alpha1.PortMirrorSpec) { s.Direction = "Sideways" },
	} {
		spec := base
		spec.Sources = append([]string(nil), base.Sources...)
		mutate(&spec)
		if errs := ValidatePortMirrorSpec(&spec); len(errs) == 0 {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestValidatePortMirrorAcceptsAnUnsetDirection(t *testing.T) {
	// The API server applies the structural default while decoding, so an unset
	// direction is what the reconciler sees for an object stored before the
	// field existed. Rejecting it would strand that object as invalid when the
	// driver treats empty as Both anyway.
	spec := validMirror().Spec
	spec.Direction = ""

	if errs := ValidatePortMirrorSpec(&spec); len(errs) > 0 {
		t.Errorf("an unset direction was rejected: %v", errs)
	}
}

func TestPortMirrorCreateIsRecordedBeforeAdmission(t *testing.T) {
	w, committer := mirrorWebhook()

	ctx := mirrorRequestCtx(admissionv1.Create)
	if _, err := w.ValidateCreate(ctx, validMirror()); err != nil {
		t.Fatalf("ValidateCreate: %v", err)
	}
	if len(committer.records) != 1 {
		t.Fatalf("records = %d, want 1", len(committer.records))
	}
	rec := committer.records[0]
	if rec.Action != audit.ActionPortMirrorCreate {
		t.Errorf("action = %q, want %q", rec.Action, audit.ActionPortMirrorCreate)
	}
	if rec.Decision != audit.DecisionAllowed {
		t.Errorf("decision = %q, want %q", rec.Decision, audit.DecisionAllowed)
	}
	if rec.Actor.Username != mirrorActor {
		t.Errorf("actor = %q, want the authenticated identity", rec.Actor.Username)
	}
}

func TestPortMirrorDeleteIsRecorded(t *testing.T) {
	// Deleting a PortMirror is how mirroring stops. The device-side revert is a
	// separate record with a separate actor, and an unreachable switch produces
	// this one and no revert - the state an operator has to be able to find.
	w, committer := mirrorWebhook()

	ctx := mirrorRequestCtx(admissionv1.Delete)
	if _, err := w.ValidateDelete(ctx, validMirror()); err != nil {
		t.Fatalf("ValidateDelete: %v", err)
	}
	if len(committer.records) != 1 {
		t.Fatalf("records = %d, want 1", len(committer.records))
	}
	if got := committer.records[0].Action; got != audit.ActionPortMirrorDelete {
		t.Errorf("action = %q, want %q", got, audit.ActionPortMirrorDelete)
	}
}

func TestPortMirrorIsRefusedWhenTheLedgerIsUnavailable(t *testing.T) {
	// FR-036 fails closed. Refusing a kubectl apply is the lesser harm; an
	// unrecorded request to reconfigure network hardware is the greater one.
	committer := &recordingCommitter{err: ErrAuditUnavailable}
	w := &PortMirrorWebhook{Gate: &Gate{SystemNamespace: "trawl-system", Audit: committer}}

	ctx := mirrorRequestCtx(admissionv1.Create)
	if _, err := w.ValidateCreate(ctx, validMirror()); err == nil {
		t.Fatal("a PortMirror was admitted with no durable audit record")
	}
}
