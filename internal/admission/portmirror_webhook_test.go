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
	"errors"
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

// PortMirror is the only Trawl resource that writes to hardware outside the
// cluster, and it went without a webhook until after the other three had one.
// What is tested here is what only admission can do: name the human who asked,
// and refuse the two edits that would strand a live mirror on a device nothing
// will ever revert.

func mirrorWebhook() (*PortMirrorWebhook, *recordingCommitter) {
	committer := &recordingCommitter{}
	return &PortMirrorWebhook{
		Gate: &Gate{SystemNamespace: "trawl-system", Audit: committer},
	}, committer
}

func mirrorRequestCtx(op admissionv1.Operation, username string) context.Context {
	req := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		UID:       types.UID("req-" + string(op)),
		Kind:      metav1.GroupVersionKind{Group: "trawl.cloud", Version: "v1alpha1", Kind: "PortMirror"},
		Resource:  metav1.GroupVersionResource{Group: "trawl.cloud", Version: "v1alpha1", Resource: "portmirrors"},
		Name:      "lab-switch",
		Namespace: "trawl-system",
		Operation: op,
		UserInfo:  authenticationv1.UserInfo{Username: username, UID: "u"},
	}}
	return admission.NewContextWithRequest(context.Background(), req)
}

func testMirror(mutate ...func(*trawlv1alpha1.PortMirror)) *trawlv1alpha1.PortMirror {
	m := &trawlv1alpha1.PortMirror{
		ObjectMeta: metav1.ObjectMeta{Name: "lab-switch", Namespace: "trawl-system", UID: "mirror-uid"},
		Spec: trawlv1alpha1.PortMirrorSpec{
			Provider:  trawlv1alpha1.MirrorProviderMikroTikRouterOS7,
			DeviceRef: corev1.LocalObjectReference{Name: "lab-switch-credential"},
			Sources:   []string{"ether1", "ether2"},
			Target:    "ether7",
			Direction: trawlv1alpha1.MirrorDirectionBoth,
		},
	}
	for _, mut := range mutate {
		mut(m)
	}
	return m
}

func TestPortMirrorRefusesOutsideSystemNamespace(t *testing.T) {
	// FR-001. Until this webhook existed the reconciler's own namespace check
	// was the only thing standing between an off-namespace mirror and a
	// switch, which made it load-bearing rather than defence in depth.
	w, _ := mirrorWebhook()
	elsewhere := testMirror(func(m *trawlv1alpha1.PortMirror) { m.Namespace = "default" })

	if _, err := w.ValidateCreate(mirrorRequestCtx(admissionv1.Create, "alice"), elsewhere); err == nil {
		t.Fatal("a PortMirror outside the system namespace was admitted")
	}
	if _, err := w.ValidateDelete(mirrorRequestCtx(admissionv1.Delete, "alice"), elsewhere); err == nil {
		t.Fatal("an off-namespace PortMirror was accepted for deletion")
	}

	// The control: the identical object in the system namespace is admitted,
	// so the rejections above are attributable to the namespace alone.
	if _, err := w.ValidateCreate(mirrorRequestCtx(admissionv1.Create, "alice"), testMirror()); err != nil {
		t.Fatalf("the same mirror in trawl-system was rejected: %v", err)
	}
}

func TestPortMirrorDefaultStampsTheRequester(t *testing.T) {
	// This is the field the ledger was missing. The controller audits every
	// device write under its own workload identity, so without this the record
	// of a switch being reconfigured names the controller and no human.
	w, _ := mirrorWebhook()
	m := testMirror()

	if err := w.Default(mirrorRequestCtx(admissionv1.Create, "alice"), m); err != nil {
		t.Fatalf("Default: %v", err)
	}
	if got := m.Annotations[trawlv1alpha1.AnnotationRequester]; got != "alice" {
		t.Errorf("requester = %q, want alice", got)
	}

	// An update must not re-stamp it, or the mirror would be attributed to
	// whoever edited it last rather than whoever asked for it.
	if err := w.Default(mirrorRequestCtx(admissionv1.Update, "bob"), m); err != nil {
		t.Fatalf("Default on update: %v", err)
	}
	if got := m.Annotations[trawlv1alpha1.AnnotationRequester]; got != "alice" {
		t.Errorf("requester after bob's update = %q, want alice", got)
	}
}

func TestPortMirrorRepointingTheDeviceIsRefused(t *testing.T) {
	// The rule this webhook exists for. The revert finalizer runs only on
	// deletion, so repointing deviceRef configures the new device and abandons
	// the old one still mirroring, with no resource naming it and nothing that
	// will ever un-configure it. Trawl only looks at devices it is told about,
	// so nothing detects it afterwards either.
	w, _ := mirrorWebhook()
	old := testMirror()
	moved := testMirror(func(m *trawlv1alpha1.PortMirror) {
		m.Spec.DeviceRef.Name = "other-switch-credential"
	})

	_, err := w.ValidateUpdate(mirrorRequestCtx(admissionv1.Update, "alice"), old, moved)
	if err == nil {
		t.Fatal("deviceRef was repointed without objection")
	}
	if !strings.Contains(err.Error(), "deviceRef") {
		t.Errorf("error does not name the field: %v", err)
	}

	// The control: an edit that does not move the device is allowed, so the
	// resource is not frozen outright.
	retargeted := testMirror(func(m *trawlv1alpha1.PortMirror) {
		m.Spec.Sources = []string{"ether1", "ether2", "ether3"}
	})
	if _, err := w.ValidateUpdate(mirrorRequestCtx(admissionv1.Update, "alice"), old, retargeted); err != nil {
		t.Fatalf("adding a source port was rejected: %v", err)
	}
}

func TestPortMirrorProviderIsImmutable(t *testing.T) {
	// Narrower version of the same argument: the driver that configured a
	// device is the one that would have to speak to it to revert it.
	w, _ := mirrorWebhook()
	old := testMirror()
	swapped := testMirror(func(m *trawlv1alpha1.PortMirror) { m.Spec.Provider = "SomethingElse" })

	if _, err := w.ValidateUpdate(mirrorRequestCtx(admissionv1.Update, "alice"), old, swapped); err == nil {
		t.Fatal("the provider was changed under a live mirror")
	}
}

func TestPortMirrorRequesterAnnotationIsFrozen(t *testing.T) {
	w, _ := mirrorWebhook()
	old := testMirror(func(m *trawlv1alpha1.PortMirror) {
		m.Annotations = map[string]string{trawlv1alpha1.AnnotationRequester: "alice"}
	})
	rewritten := testMirror(func(m *trawlv1alpha1.PortMirror) {
		m.Annotations = map[string]string{trawlv1alpha1.AnnotationRequester: "mallory"}
	})

	if _, err := w.ValidateUpdate(mirrorRequestCtx(admissionv1.Update, "alice"), old, rewritten); err == nil {
		t.Fatal("the requester annotation was rewritten")
	}
}

func TestPortMirrorMutationsAreRecordedBeforeAdmission(t *testing.T) {
	// FR-036. The record is committed first, so a mirror that reaches etcd
	// always has a durable record of who asked for it.
	for name, tc := range map[string]struct {
		call   func(*PortMirrorWebhook) error
		action string
	}{
		"create": {
			call: func(w *PortMirrorWebhook) error {
				_, err := w.ValidateCreate(mirrorRequestCtx(admissionv1.Create, "alice"), testMirror())
				return err
			},
			action: audit.ActionPortMirrorCreate,
		},
		"update": {
			call: func(w *PortMirrorWebhook) error {
				updated := testMirror(func(m *trawlv1alpha1.PortMirror) { m.Spec.Target = "ether8" })
				_, err := w.ValidateUpdate(mirrorRequestCtx(admissionv1.Update, "alice"), testMirror(), updated)
				return err
			},
			action: audit.ActionPortMirrorUpdate,
		},
		"delete": {
			call: func(w *PortMirrorWebhook) error {
				_, err := w.ValidateDelete(mirrorRequestCtx(admissionv1.Delete, "alice"), testMirror())
				return err
			},
			action: audit.ActionPortMirrorDelete,
		},
	} {
		t.Run(name, func(t *testing.T) {
			w, committer := mirrorWebhook()
			if err := tc.call(w); err != nil {
				t.Fatalf("admitting: %v", err)
			}
			if len(committer.records) != 1 {
				t.Fatalf("committed %d records, want 1", len(committer.records))
			}
			rec := committer.records[0]
			if rec.Action != tc.action {
				t.Errorf("action = %q, want %q", rec.Action, tc.action)
			}
			if rec.Actor.Username != "alice" {
				t.Errorf("actor = %q, want alice", rec.Actor.Username)
			}
			if rec.Decision != audit.DecisionAllowed {
				t.Errorf("decision = %q, want %q", rec.Decision, audit.DecisionAllowed)
			}
		})
	}
}

func TestPortMirrorIsRefusedWhenTheLedgerIsUnavailable(t *testing.T) {
	// Fail closed. A switch reconfigured without a record of who asked is
	// exactly what the ledger exists to prevent, and this is the resource where
	// it matters most.
	w, committer := mirrorWebhook()
	committer.err = errors.New("ledger unreachable")

	if _, err := w.ValidateCreate(mirrorRequestCtx(admissionv1.Create, "alice"), testMirror()); err == nil {
		t.Fatal("a mirror was admitted while the ledger was unavailable")
	} else if !errors.Is(err, ErrAuditUnavailable) {
		t.Errorf("error = %v, want ErrAuditUnavailable", err)
	}
}

func TestPortMirrorContentionIsNotSettledHere(t *testing.T) {
	// Deliberate omission, pinned so nobody later reads it as a hole.
	//
	// Two mirrors naming one device both pass admission, because whether they
	// contend depends on what else is stored at the moment they are compared
	// and a webhook sees one object. checkDeviceConflict settles it at
	// reconcile time, where the younger claim yields.
	w, _ := mirrorWebhook()

	first := testMirror()
	second := testMirror(func(m *trawlv1alpha1.PortMirror) {
		m.Name = "lab-switch-again"
		m.UID = "other-uid"
	})

	for _, m := range []*trawlv1alpha1.PortMirror{first, second} {
		if _, err := w.ValidateCreate(mirrorRequestCtx(admissionv1.Create, "alice"), m); err != nil {
			t.Fatalf("%s was refused at admission: %v", m.Name, err)
		}
	}
}

func TestValidatePortMirrorSpecRejectsWhatTheSchemaWould(t *testing.T) {
	// The reconciler calls this on a stored object, which may never have met
	// CEL. Each case is one the schema also catches on write.
	for name, mutate := range map[string]func(*trawlv1alpha1.PortMirrorSpec){
		"target is also a source": func(s *trawlv1alpha1.PortMirrorSpec) { s.Target = "ether1" },
		"no sources":              func(s *trawlv1alpha1.PortMirrorSpec) { s.Sources = nil },
		"duplicate source":        func(s *trawlv1alpha1.PortMirrorSpec) { s.Sources = []string{"ether1", "ether1"} },
		"empty port name":         func(s *trawlv1alpha1.PortMirrorSpec) { s.Sources = []string{""} },
		"port name with a space":  func(s *trawlv1alpha1.PortMirrorSpec) { s.Target = "ether 7" },
		"port name with a quote":  func(s *trawlv1alpha1.PortMirrorSpec) { s.Target = `ether7";drop` },
		"unknown provider":        func(s *trawlv1alpha1.PortMirrorSpec) { s.Provider = "Cisco" },
		"unknown direction":       func(s *trawlv1alpha1.PortMirrorSpec) { s.Direction = "Sideways" },
		"no deviceRef":            func(s *trawlv1alpha1.PortMirrorSpec) { s.DeviceRef.Name = "" },
		"too many sources": func(s *trawlv1alpha1.PortMirrorSpec) {
			s.Sources = make([]string, maxMirrorSources+1)
			for i := range s.Sources {
				s.Sources[i] = "ether" + string(rune('a'+i%26)) + string(rune('a'+i/26))
			}
		},
		"port name too long": func(s *trawlv1alpha1.PortMirrorSpec) {
			s.Target = strings.Repeat("e", maxMirrorPortLen+1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			spec := testMirror().Spec
			mutate(&spec)
			if errs := ValidatePortMirrorSpec(&spec); len(errs) == 0 {
				t.Errorf("%s was accepted", name)
			}
		})
	}

	// The control, including the one optional field left empty: an unset
	// direction is defaulted by the schema and must not be rejected here.
	valid := testMirror().Spec
	valid.Direction = ""
	if errs := ValidatePortMirrorSpec(&valid); len(errs) > 0 {
		t.Errorf("a valid spec was rejected: %v", errs.ToAggregate())
	}
}
