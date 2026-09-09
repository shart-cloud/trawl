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
	"errors"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/audit"
)

// T105. The CRD's schema owns shape and bounds; what is tested here is what it
// cannot know - the namespace, the placeholder contract with internal/policy,
// the installation's ceiling, and whether the mutation was durably recorded
// before it was admitted.

func policyWebhook(t *testing.T) (*CapturePolicyWebhook, *recordingCommitter) {
	t.Helper()
	committer := &recordingCommitter{}
	return &CapturePolicyWebhook{
		Gate:   &Gate{SystemNamespace: "trawl-system", Audit: committer},
		Config: captureConfig(),
	}, committer
}

func testPolicy(mutate ...func(*trawlv1alpha1.CapturePolicy)) *trawlv1alpha1.CapturePolicy {
	p := &trawlv1alpha1.CapturePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "ssh-brute", Namespace: "trawl-system", UID: "policy-uid"},
		Spec: trawlv1alpha1.CapturePolicySpec{
			TapRef: corev1.LocalObjectReference{Name: "node-eno1"},
			Trigger: trawlv1alpha1.CapturePolicyTrigger{
				Type:          trawlv1alpha1.CaptureTriggerSuricataAlert,
				SuricataAlert: &trawlv1alpha1.SuricataAlertTrigger{Severities: []int32{1, 2}},
			},
			Capture: trawlv1alpha1.PolicyCaptureBounds{
				Duration: "60s",
				MaxSize:  resource.MustParse("64Mi"),
			},
			Retention: "24h",
			RateLimit: trawlv1alpha1.CaptureRateLimit{
				MaxCapturesPerHour: 10,
				Cooldown:           metav1.Duration{Duration: 5 * time.Minute},
			},
		},
	}
	for _, m := range mutate {
		m(p)
	}
	return p
}

func TestCapturePolicyCreateRefusesOutsideSystemNamespace(t *testing.T) {
	// FR-001. A policy in another namespace would be evaluated by a worker
	// watching the system namespace only, so it would sit there looking armed
	// and never fire - and nothing about the object would say why.
	w, _ := policyWebhook(t)
	p := testPolicy(func(p *trawlv1alpha1.CapturePolicy) { p.Namespace = "default" })

	if _, err := w.ValidateCreate(requestCtx(admissionv1.Create, "alice"), p); err == nil {
		t.Fatal("a policy outside the system namespace was admitted")
	}

	// The control: the identical object in the system namespace is admitted, so
	// the rejection above is attributable to the namespace and nothing else.
	if _, err := w.ValidateCreate(requestCtx(admissionv1.Create, "alice"), testPolicy()); err != nil {
		t.Fatalf("the same policy in trawl-system was rejected: %v", err)
	}
}

func TestCapturePolicyCreateRejectsAnUnrenderableFilterTemplate(t *testing.T) {
	// The placeholder set is a contract between this type and internal/policy,
	// and no schema rule can express "one of these five names". Caught here,
	// the operator is told at write time; missed here, the policy arms cleanly
	// and the capture fails only when an alert finally fires - in the worker's
	// logs, not on the object, which goes on reporting itself armed.
	w, _ := policyWebhook(t)

	for name, template := range map[string]string{
		"unknown placeholder": "host {{source.mac}}",
		"payload field":       "host {{signature.message}}",
		"unterminated":        "host {{source.ip",
	} {
		t.Run(name, func(t *testing.T) {
			p := testPolicy(func(p *trawlv1alpha1.CapturePolicy) {
				p.Spec.Capture.FilterTemplate = template
			})
			if _, err := w.ValidateCreate(requestCtx(admissionv1.Create, "alice"), p); err == nil {
				t.Errorf("template %q was admitted", template)
			}
		})
	}

	// The control: a template using the documented placeholders is admitted.
	p := testPolicy(func(p *trawlv1alpha1.CapturePolicy) {
		p.Spec.Capture.FilterTemplate = "host {{source.ip}} and {{protocol}} port {{destination.port}}"
	})
	if _, err := w.ValidateCreate(requestCtx(admissionv1.Create, "alice"), p); err != nil {
		t.Fatalf("a documented template was rejected: %v", err)
	}
}

func TestCapturePolicyRetentionIsClampedToTheInstallationCeiling(t *testing.T) {
	// The API default is 30d, the contract maximum. This installation's ceiling
	// is 7d, so a policy that left retention blank would otherwise be rejected
	// on every create.
	w, _ := policyWebhook(t)
	p := testPolicy(func(p *trawlv1alpha1.CapturePolicy) { p.Spec.Retention = "" })

	if err := w.Default(requestCtx(admissionv1.Create, "alice"), p); err != nil {
		t.Fatalf("defaulting: %v", err)
	}
	if p.Spec.Retention != "7d" {
		t.Errorf("retention defaulted to %q, want the 7d ceiling", p.Spec.Retention)
	}

	// And a policy asking for more than the ceiling is refused outright.
	over := testPolicy(func(p *trawlv1alpha1.CapturePolicy) { p.Spec.Retention = "30d" })
	if _, err := w.ValidateCreate(requestCtx(admissionv1.Create, "alice"), over); err == nil {
		t.Error("retention above the installation ceiling was admitted")
	}
}

func TestCapturePolicyDefaultStampsTheRequesterOnceOnly(t *testing.T) {
	// Provenance: who armed this. Stamped from the authenticated identity on
	// create, and refused thereafter so a later edit cannot reattribute the
	// policy to whoever touched it last.
	w, _ := policyWebhook(t)
	p := testPolicy()

	if err := w.Default(requestCtx(admissionv1.Create, "alice"), p); err != nil {
		t.Fatalf("defaulting: %v", err)
	}
	if got := p.Annotations[trawlv1alpha1.AnnotationRequester]; got != "alice" {
		t.Errorf("requester = %q, want alice", got)
	}

	updated := testPolicy(func(u *trawlv1alpha1.CapturePolicy) {
		u.Annotations = map[string]string{trawlv1alpha1.AnnotationRequester: "mallory"}
	})
	if _, err := w.ValidateUpdate(requestCtx(admissionv1.Update, "mallory"), p, updated); err == nil {
		t.Error("the requester annotation was allowed to change on update")
	}
}

func TestArmingAndDisarmingAreAuditedAsTheirOwnActions(t *testing.T) {
	// Arming starts automatic collection and disarming stops it. Recorded as a
	// generic update, the ledger could only answer "when did this begin
	// capturing" by diffing every revision of the object.
	ctx := requestCtx(admissionv1.Update, "alice")

	for name, tc := range map[string]struct {
		from, to bool
		want     string
	}{
		"arming":    {false, true, audit.ActionCapturePolicyArm},
		"disarming": {true, false, audit.ActionCapturePolicyDisarm},
		"unrelated": {true, true, audit.ActionCapturePolicyUpdate},
		"stays off": {false, false, audit.ActionCapturePolicyUpdate},
	} {
		t.Run(name, func(t *testing.T) {
			w, committer := policyWebhook(t)
			old := testPolicy(func(p *trawlv1alpha1.CapturePolicy) { p.Spec.Armed = tc.from })
			updated := testPolicy(func(p *trawlv1alpha1.CapturePolicy) { p.Spec.Armed = tc.to })

			if _, err := w.ValidateUpdate(ctx, old, updated); err != nil {
				t.Fatalf("update: %v", err)
			}
			if len(committer.records) != 1 {
				t.Fatalf("recorded %d audit entries, want 1", len(committer.records))
			}
			if got := committer.records[0].Action; got != tc.want {
				t.Errorf("action = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCreatingAnAlreadyArmedPolicyIsAuditedAsArming(t *testing.T) {
	// A policy created armed begins collecting immediately. Recorded only as a
	// creation, the moment collection started would be absent from the ledger.
	w, committer := policyWebhook(t)
	p := testPolicy(func(p *trawlv1alpha1.CapturePolicy) { p.Spec.Armed = true })

	if _, err := w.ValidateCreate(requestCtx(admissionv1.Create, "alice"), p); err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(committer.records) != 1 || committer.records[0].Action != audit.ActionCapturePolicyArm {
		t.Errorf("audit records = %+v, want a single arm action", committer.records)
	}
}

func TestCapturePolicyCreateRefusesWhenAuditIsUnavailable(t *testing.T) {
	// FR-036, fail closed. A policy admitted while the ledger was unreachable
	// would be collecting evidence with no durable record of who armed it.
	w, committer := policyWebhook(t)
	committer.err = errors.New("ledger unreachable")

	if _, err := w.ValidateCreate(requestCtx(admissionv1.Create, "alice"), testPolicy()); err == nil {
		t.Fatal("a policy was admitted while the audit ledger was unavailable")
	}
}

func TestValidateCapturePolicySpecRechecksBoundsTheSchemaAlsoEnforces(t *testing.T) {
	// The same reasoning as the CaptureJob webhook's equivalent: an object
	// restored into etcd, or written before a rule existed, never passed
	// through CEL. The worker re-checks a stored policy before rendering a
	// privileged capture from it.
	ceiling := 7 * 24 * time.Hour

	for name, mutate := range map[string]func(*trawlv1alpha1.CapturePolicySpec){
		"duration below the floor":  func(s *trawlv1alpha1.CapturePolicySpec) { s.Capture.Duration = "10ms" },
		"duration above the cap":    func(s *trawlv1alpha1.CapturePolicySpec) { s.Capture.Duration = "2h" },
		"snaplen below the floor":   func(s *trawlv1alpha1.CapturePolicySpec) { s.Capture.Snaplen = 32 },
		"maxSize below the floor":   func(s *trawlv1alpha1.CapturePolicySpec) { s.Capture.MaxSize = resource.MustParse("512Ki") },
		"maxSize above the cap":     func(s *trawlv1alpha1.CapturePolicySpec) { s.Capture.MaxSize = resource.MustParse("2Gi") },
		"hourly limit of zero":      func(s *trawlv1alpha1.CapturePolicySpec) { s.RateLimit.MaxCapturesPerHour = 0 },
		"hourly limit over the cap": func(s *trawlv1alpha1.CapturePolicySpec) { s.RateLimit.MaxCapturesPerHour = 101 },
		"cooldown below the floor": func(s *trawlv1alpha1.CapturePolicySpec) {
			s.RateLimit.Cooldown = metav1.Duration{Duration: time.Millisecond}
		},
		"cooldown above the cap": func(s *trawlv1alpha1.CapturePolicySpec) {
			s.RateLimit.Cooldown = metav1.Duration{Duration: 2 * time.Hour}
		},
	} {
		t.Run(name, func(t *testing.T) {
			spec := testPolicy().Spec
			mutate(&spec)
			if errs := ValidateCapturePolicySpec(&spec, ceiling); len(errs) == 0 {
				t.Errorf("%s was accepted", name)
			}
		})
	}

	if errs := ValidateCapturePolicySpec(&testPolicy().Spec, ceiling); len(errs) > 0 {
		t.Errorf("a valid spec was rejected: %v", errs)
	}
}

func TestCapturePolicyValidationDoesNotEchoTheTemplate(t *testing.T) {
	// A filter template names internal addresses and ports. Admission errors
	// reach the requester and the API server's own logs, so a rejected value
	// must not travel with the rejection.
	secret := "host {{source.mac}} and host 10.11.12.13"
	spec := testPolicy().Spec
	spec.Capture.FilterTemplate = secret

	errs := ValidateCapturePolicySpec(&spec, 7*24*time.Hour)
	if len(errs) == 0 {
		t.Fatal("the template was accepted")
	}
	if strings.Contains(errs.ToAggregate().Error(), "10.11.12.13") {
		t.Errorf("the rejection echoed the template: %v", errs.ToAggregate())
	}
}
