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

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
)

// T096. These run against a real API server so the schema is enforced by the
// thing that will enforce it in the cluster. Asserting that the markers are
// present in the source would test that someone typed them; only the API server
// can say whether they mean what they were meant to mean - CEL rules in
// particular are easy to write in a form that admits everything.

func policySpec(mutate ...func(*trawlv1alpha1.CapturePolicySpec)) trawlv1alpha1.CapturePolicySpec {
	spec := trawlv1alpha1.CapturePolicySpec{
		TapRef: corev1.LocalObjectReference{Name: "node-eno1"},
		Trigger: trawlv1alpha1.CapturePolicyTrigger{
			Type: trawlv1alpha1.CaptureTriggerSuricataAlert,
			SuricataAlert: &trawlv1alpha1.SuricataAlertTrigger{
				Severities: []int32{1, 2},
			},
		},
		Capture: trawlv1alpha1.PolicyCaptureBounds{
			Duration: "60s",
			MaxSize:  resource.MustParse("64Mi"),
		},
		RateLimit: trawlv1alpha1.CaptureRateLimit{
			MaxCapturesPerHour: 10,
			Cooldown:           metav1.Duration{Duration: 300000000000},
		},
	}
	for _, m := range mutate {
		m(&spec)
	}
	return spec
}

func newPolicy(t *testing.T, ns, name string, mutate ...func(*trawlv1alpha1.CapturePolicySpec)) *trawlv1alpha1.CapturePolicy {
	t.Helper()
	return &trawlv1alpha1.CapturePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       policySpec(mutate...),
	}
}

func TestAValidPolicyIsAdmittedAndDefaulted(t *testing.T) {
	// The control for every rejection below. A rejection only means what it
	// claims if the otherwise-identical valid object is admitted in the same
	// breath - otherwise the test proves the schema rejects things, not that it
	// rejects the right things.
	ns := NewNamespace(t)
	policy := newPolicy(t, ns, "valid")

	if err := Client().Create(context.Background(), policy); err != nil {
		t.Fatalf("a valid policy was rejected: %v", err)
	}

	if policy.Spec.Armed {
		t.Error("armed defaulted true; creating a policy must not be the same act as switching it on")
	}
	if policy.Spec.Retention != "30d" {
		t.Errorf("retention defaulted to %q, want 30d", policy.Spec.Retention)
	}
	if policy.Spec.Capture.Snaplen != 0 {
		t.Errorf("snaplen defaulted to %d, want 0 (whole packets)", policy.Spec.Capture.Snaplen)
	}
}

func TestTheTriggerUnionIsClosedInBothDirections(t *testing.T) {
	// A type naming a body that is not there arms an object that can never
	// match. A second body that the type does not name is silently ignored, so
	// an operator editing the wrong one sees no error and no change in
	// behavior. Both are refused.
	ns := NewNamespace(t)

	for name, mutate := range map[string]func(*trawlv1alpha1.CapturePolicySpec){
		"named body absent": func(s *trawlv1alpha1.CapturePolicySpec) {
			s.Trigger.SuricataAlert = nil
		},
		"unnamed body present": func(s *trawlv1alpha1.CapturePolicySpec) {
			s.Trigger.HubbleDrop = &trawlv1alpha1.HubbleDropTrigger{Reasons: []string{"POLICY_DENIED"}}
		},
		"hubble type with suricata body": func(s *trawlv1alpha1.CapturePolicySpec) {
			s.Trigger.Type = trawlv1alpha1.CaptureTriggerHubbleDrop
		},
		"unknown trigger type": func(s *trawlv1alpha1.CapturePolicySpec) {
			s.Trigger.Type = "Anomaly"
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := Client().Create(context.Background(), newPolicy(t, ns, "union-"+strings.ReplaceAll(name, " ", "-"), mutate))
			if err == nil {
				t.Fatal("the API server admitted a malformed trigger union")
			}
		})
	}
}

func TestOutOfRangeBoundsAreRefused(t *testing.T) {
	// Each of these is a bound the design depends on, and each is refused by
	// the API server rather than by a controller that would have to decide what
	// to do with an object it should never have received.
	ns := NewNamespace(t)

	for name, mutate := range map[string]func(*trawlv1alpha1.CapturePolicySpec){
		"severity below the scale": func(s *trawlv1alpha1.CapturePolicySpec) {
			s.Trigger.SuricataAlert.Severities = []int32{0}
		},
		"severity above the scale": func(s *trawlv1alpha1.CapturePolicySpec) {
			s.Trigger.SuricataAlert.Severities = []int32{5}
		},
		"no severities at all": func(s *trawlv1alpha1.CapturePolicySpec) {
			s.Trigger.SuricataAlert.Severities = []int32{}
		},
		"hourly limit of zero": func(s *trawlv1alpha1.CapturePolicySpec) {
			s.RateLimit.MaxCapturesPerHour = 0
		},
		"hourly limit above the ceiling": func(s *trawlv1alpha1.CapturePolicySpec) {
			s.RateLimit.MaxCapturesPerHour = 101
		},
		"unparseable capture duration": func(s *trawlv1alpha1.CapturePolicySpec) {
			s.Capture.Duration = "forever"
		},
		"unparseable retention": func(s *trawlv1alpha1.CapturePolicySpec) {
			s.Retention = "a while"
		},
		"filter template over the byte bound": func(s *trawlv1alpha1.CapturePolicySpec) {
			s.Capture.FilterTemplate = strings.Repeat("a", 1025)
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := Client().Create(context.Background(), newPolicy(t, ns, "bound-"+strings.ReplaceAll(name, " ", "-"), mutate))
			if err == nil {
				t.Fatalf("the API server admitted %s", name)
			}
		})
	}
}

func TestADropTriggerRequiresReasonsAndBoundsItsThreshold(t *testing.T) {
	// A drop policy with no reasons matches every denied flow in the cluster,
	// which on a busy cluster is a capture storm rather than a policy.
	ns := NewNamespace(t)
	hubble := func(mutate func(*trawlv1alpha1.HubbleDropTrigger)) func(*trawlv1alpha1.CapturePolicySpec) {
		return func(s *trawlv1alpha1.CapturePolicySpec) {
			s.Trigger.Type = trawlv1alpha1.CaptureTriggerHubbleDrop
			s.Trigger.SuricataAlert = nil
			s.Trigger.HubbleDrop = &trawlv1alpha1.HubbleDropTrigger{Reasons: []string{"POLICY_DENIED"}}
			mutate(s.Trigger.HubbleDrop)
		}
	}

	if err := Client().Create(context.Background(),
		newPolicy(t, ns, "drop-valid", hubble(func(*trawlv1alpha1.HubbleDropTrigger) {}))); err != nil {
		t.Fatalf("a valid drop policy was rejected: %v", err)
	}

	for name, mutate := range map[string]func(*trawlv1alpha1.HubbleDropTrigger){
		"no reasons": func(h *trawlv1alpha1.HubbleDropTrigger) { h.Reasons = []string{} },
		"threshold zero": func(h *trawlv1alpha1.HubbleDropTrigger) {
			h.Threshold = &trawlv1alpha1.DropThreshold{Count: 0, Window: metav1.Duration{Duration: 60000000000}}
		},
		"threshold huge": func(h *trawlv1alpha1.HubbleDropTrigger) {
			h.Threshold = &trawlv1alpha1.DropThreshold{Count: 10001, Window: metav1.Duration{Duration: 60000000000}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := Client().Create(context.Background(),
				newPolicy(t, ns, "drop-"+strings.ReplaceAll(name, " ", "-"), hubble(mutate)))
			if err == nil {
				t.Fatalf("the API server admitted %s", name)
			}
		})
	}
}

func TestArmingAnExistingPolicyIsAllowedAndBumpsGeneration(t *testing.T) {
	// Arming is the ordinary operational act this type exists for, and the
	// generation bump is what lets the worker tell "the policy I evaluated"
	// from "the policy as it is now" - the pin every CaptureJob carries.
	ns := NewNamespace(t)
	policy := newPolicy(t, ns, "armable")
	ctx := context.Background()

	if err := Client().Create(ctx, policy); err != nil {
		t.Fatalf("creating: %v", err)
	}
	before := policy.Generation

	policy.Spec.Armed = true
	if err := Client().Update(ctx, policy); err != nil {
		t.Fatalf("arming a policy was rejected: %v", err)
	}

	if policy.Generation <= before {
		t.Errorf("generation did not advance on a spec change: %d then %d", before, policy.Generation)
	}
	if !policy.Spec.Armed {
		t.Error("armed did not persist")
	}
}

func TestStatusIsASubresourceAndSurvivesASpecWrite(t *testing.T) {
	// Counters are the record of what a policy has been doing. If a spec
	// update could carry a stale status, an operator editing a filter would
	// silently reset the evidence of everything the policy had decided.
	ns := NewNamespace(t)
	policy := newPolicy(t, ns, "statusful")
	ctx := context.Background()

	if err := Client().Create(ctx, policy); err != nil {
		t.Fatalf("creating: %v", err)
	}

	policy.Status.Phase = trawlv1alpha1.CapturePolicyArmed
	policy.Status.TotalCaptures = 7
	if err := Client().Status().Update(ctx, policy); err != nil {
		t.Fatalf("writing status: %v", err)
	}

	// A spec write carrying an empty status must not clear it.
	policy.Status = trawlv1alpha1.CapturePolicyStatus{}
	policy.Spec.Capture.Duration = "90s"
	if err := Client().Update(ctx, policy); err != nil {
		t.Fatalf("updating spec: %v", err)
	}

	var reread trawlv1alpha1.CapturePolicy
	if err := Client().Get(ctx, client.ObjectKeyFromObject(policy), &reread); err != nil {
		t.Fatalf("re-reading: %v", err)
	}
	if reread.Status.TotalCaptures != 7 {
		t.Errorf("totalCaptures = %d after a spec write, want 7 preserved", reread.Status.TotalCaptures)
	}
}

func TestDeletingAPolicyDoesNotRequireAnything(t *testing.T) {
	// Policies are deletable without ceremony. The evidence they produced is
	// not owned by them - CaptureJobs carry no ownerReference to a policy
	// precisely so that deleting the rule never garbage-collects the packets
	// it collected.
	ns := NewNamespace(t)
	policy := newPolicy(t, ns, "deletable")
	ctx := context.Background()

	if err := Client().Create(ctx, policy); err != nil {
		t.Fatalf("creating: %v", err)
	}
	if err := Client().Delete(ctx, policy); err != nil {
		t.Fatalf("deleting a policy was refused: %v", err)
	}
}

func TestTheThresholdWindowIsBoundedAtBothEnds(t *testing.T) {
	// The pattern that shapes the string cannot express a range over what it
	// denotes: `^([0-9]+(s|m))+$` admits both "0s" and "600m", and neither is a
	// wrong-looking value that fails loudly.
	//
	// A zero window expires every event that is not simultaneous with the
	// newest, so a count of five can never be reached and the policy silently
	// never fires - armed, matching, and structurally incapable of the thing it
	// was written to do. A window past the reconnect replay bound cannot be
	// rebuilt after a disconnect, so it under-counts with nothing to say so.
	ns := NewNamespace(t)

	// Both values are chosen to reach CEL rather than to be caught before it.
	// Sub-second is not here because the pattern already refuses it - `s` is its
	// smallest unit. Nor is anything an hour or more: metav1.Duration marshals
	// 600m as "10h0m0s", which the pattern refuses for the `h`, so a test using
	// it would pass with this rule deleted. 16m is the smallest value that is
	// expressible, well-formed, and over the line.
	for name, window := range map[string]string{
		"zero":           "0s",
		"past the bound": "16m",
	} {
		t.Run(name, func(t *testing.T) {
			p := newPolicy(t, ns, "threshold-"+strings.ReplaceAll(name, " ", "-"),
				func(s *trawlv1alpha1.CapturePolicySpec) {
					s.Trigger = trawlv1alpha1.CapturePolicyTrigger{
						Type: trawlv1alpha1.CaptureTriggerHubbleDrop,
						HubbleDrop: &trawlv1alpha1.HubbleDropTrigger{
							Reasons: []string{"POLICY_DENIED"},
							Threshold: &trawlv1alpha1.DropThreshold{
								Count:  5,
								Window: metav1.Duration{Duration: mustParseWindow(t, window)},
							},
						},
					}
				})
			if err := Client().Create(context.Background(), p); err == nil {
				t.Errorf("a threshold window of %s was admitted", window)
			}
		})
	}

	// The control. A rejection only means what it claims if the otherwise
	// identical valid object is admitted in the same breath.
	valid := newPolicy(t, ns, "threshold-valid", func(s *trawlv1alpha1.CapturePolicySpec) {
		s.Trigger = trawlv1alpha1.CapturePolicyTrigger{
			Type: trawlv1alpha1.CaptureTriggerHubbleDrop,
			HubbleDrop: &trawlv1alpha1.HubbleDropTrigger{
				Reasons: []string{"POLICY_DENIED"},
				Threshold: &trawlv1alpha1.DropThreshold{
					Count:  5,
					Window: metav1.Duration{Duration: time.Minute},
				},
			},
		}
	})
	if err := Client().Create(context.Background(), valid); err != nil {
		t.Fatalf("a one-minute threshold window was rejected: %v", err)
	}
}

func mustParseWindow(t *testing.T, s string) time.Duration {
	t.Helper()
	d, err := time.ParseDuration(s)
	if err != nil {
		t.Fatalf("parsing %q: %v", s, err)
	}
	return d
}
