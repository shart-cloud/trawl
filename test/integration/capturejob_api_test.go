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
	"strconv"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
)

// The CaptureJob rules that matter most - immutability and bounds - are CEL,
// because a capture whose filter or size changed after it ran is evidence of
// something other than what its status describes, and that must hold even
// when the webhook is down. CEL only exists in a real apiserver, so these run
// there.

func manualCapture(namespace, name string) *trawlv1alpha1.CaptureJob {
	return &trawlv1alpha1.CaptureJob{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: trawlv1alpha1.CaptureJobSpec{
			RequestType: trawlv1alpha1.CaptureRequestManual,
			TapRef:      corev1.LocalObjectReference{Name: "north-south-mirror"},
			TargetNode:  "talos-sensor-01",
			Filter:      "host 10.0.0.50 and tcp port 443",
			Duration:    "2m",
			Snaplen:     0,
			MaxSize:     resource.MustParse("50Mi"),
			Retention:   "7d",
		},
	}
}

func policyFields() (*trawlv1alpha1.ImmutablePolicyReference, *trawlv1alpha1.TriggerSnapshot, string) {
	digest := "sha256:" + strings.Repeat("a", 64)
	return &trawlv1alpha1.ImmutablePolicyReference{Name: "on-alert", UID: "6e4f5c85-4a55-4f10-9ccd-6bb937a5f855", Generation: 3},
		&trawlv1alpha1.TriggerSnapshot{
			Source:      trawlv1alpha1.TriggerSourceSuricataAlert,
			Fingerprint: digest,
			EventTime:   metav1.Now(),
			ObservedAt:  metav1.Now(),
			Suricata:    &trawlv1alpha1.SuricataTriggerContext{RuleID: 2024897, Severity: 1},
		},
		digest
}

func TestCaptureJobAcceptsValidManualRequest(t *testing.T) {
	ns := NewNamespace(t)
	if err := Client().Create(t.Context(), manualCapture(ns, "valid-manual")); err != nil {
		t.Fatalf("valid manual capture rejected: %v", err)
	}
}

func TestCaptureJobDefaultsRequestTypeAndRetention(t *testing.T) {
	ns := NewNamespace(t)
	job := manualCapture(ns, "defaults")
	job.Spec.RequestType = ""
	job.Spec.Retention = ""
	if err := Client().Create(t.Context(), job); err != nil {
		t.Fatalf("create: %v", err)
	}
	got := &trawlv1alpha1.CaptureJob{}
	if err := Client().Get(t.Context(), client.ObjectKeyFromObject(job), got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Spec.RequestType != trawlv1alpha1.CaptureRequestManual {
		t.Errorf("requestType = %q, want Manual", got.Spec.RequestType)
	}
	if got.Spec.Retention != "30d" {
		t.Errorf("retention = %q, want 30d", got.Spec.Retention)
	}
}

func TestCaptureJobEnforcesBounds(t *testing.T) {
	ns := NewNamespace(t)

	cases := []struct {
		name   string
		mutate func(*trawlv1alpha1.CaptureJob)
	}{
		{"duration below 1s", func(j *trawlv1alpha1.CaptureJob) { j.Spec.Duration = "500ms" }},
		{"duration above 1h", func(j *trawlv1alpha1.CaptureJob) { j.Spec.Duration = "61m" }},
		{"duration in days", func(j *trawlv1alpha1.CaptureJob) { j.Spec.Duration = "1d" }},
		{"snaplen below 64", func(j *trawlv1alpha1.CaptureJob) { j.Spec.Snaplen = 63 }},
		{"snaplen above 262144", func(j *trawlv1alpha1.CaptureJob) { j.Spec.Snaplen = 262145 }},
		{"maxSize below 1Mi", func(j *trawlv1alpha1.CaptureJob) { j.Spec.MaxSize = resource.MustParse("1023Ki") }},
		{"maxSize above 1Gi", func(j *trawlv1alpha1.CaptureJob) { j.Spec.MaxSize = resource.MustParse("1025Mi") }},
		{"retention below 1h", func(j *trawlv1alpha1.CaptureJob) { j.Spec.Retention = "59m" }},
		{"retention above 30d in days", func(j *trawlv1alpha1.CaptureJob) { j.Spec.Retention = "31d" }},
		{"retention above 30d in hours", func(j *trawlv1alpha1.CaptureJob) { j.Spec.Retention = "721h" }},
		{"retention zero days", func(j *trawlv1alpha1.CaptureJob) { j.Spec.Retention = "0d" }},
		{"filter over 1024 bytes", func(j *trawlv1alpha1.CaptureJob) { j.Spec.Filter = strings.Repeat("a", 1025) }},
		{"bad deduplication key form", func(j *trawlv1alpha1.CaptureJob) {
			j.Spec.RequestType = trawlv1alpha1.CaptureRequestPolicy
			j.Spec.PolicyRef, j.Spec.Trigger, _ = policyFields()
			j.Spec.DeduplicationKey = "md5:abc"
		}},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			job := manualCapture(ns, "bounds-"+strconv.Itoa(i))
			tc.mutate(job)
			if err := Client().Create(t.Context(), job); err == nil {
				t.Errorf("apiserver accepted %s", tc.name)
			}
		})
	}
}

func TestCaptureJobAcceptsBoundaryValues(t *testing.T) {
	ns := NewNamespace(t)

	cases := []struct {
		name   string
		mutate func(*trawlv1alpha1.CaptureJob)
	}{
		{"duration 1s", func(j *trawlv1alpha1.CaptureJob) { j.Spec.Duration = "1s" }},
		{"duration 1h", func(j *trawlv1alpha1.CaptureJob) { j.Spec.Duration = "1h" }},
		{"duration composite", func(j *trawlv1alpha1.CaptureJob) { j.Spec.Duration = "2m30s" }},
		{"snaplen 64", func(j *trawlv1alpha1.CaptureJob) { j.Spec.Snaplen = 64 }},
		{"snaplen 262144", func(j *trawlv1alpha1.CaptureJob) { j.Spec.Snaplen = 262144 }},
		{"maxSize 1Mi", func(j *trawlv1alpha1.CaptureJob) { j.Spec.MaxSize = resource.MustParse("1Mi") }},
		{"maxSize 1Gi", func(j *trawlv1alpha1.CaptureJob) { j.Spec.MaxSize = resource.MustParse("1Gi") }},
		{"retention 1h", func(j *trawlv1alpha1.CaptureJob) { j.Spec.Retention = "1h" }},
		{"retention 30d", func(j *trawlv1alpha1.CaptureJob) { j.Spec.Retention = "30d" }},
		{"retention 720h", func(j *trawlv1alpha1.CaptureJob) { j.Spec.Retention = "720h" }},
		{"empty filter", func(j *trawlv1alpha1.CaptureJob) { j.Spec.Filter = "" }},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			job := manualCapture(ns, "boundary-"+strconv.Itoa(i))
			tc.mutate(job)
			if err := Client().Create(t.Context(), job); err != nil {
				t.Errorf("apiserver rejected %s: %v", tc.name, err)
			}
		})
	}
}

func TestCaptureJobEnforcesRequestTypeShape(t *testing.T) {
	// Manual and Policy are closed shapes: a manual request carrying policy
	// context would claim an automatic provenance it does not have.
	ns := NewNamespace(t)

	t.Run("manual without targetNode", func(t *testing.T) {
		job := manualCapture(ns, "shape-no-target")
		job.Spec.TargetNode = ""
		if err := Client().Create(t.Context(), job); err == nil {
			t.Error("apiserver accepted a Manual request without targetNode")
		}
	})
	t.Run("manual with policy context", func(t *testing.T) {
		job := manualCapture(ns, "shape-manual-policy")
		job.Spec.PolicyRef, job.Spec.Trigger, job.Spec.DeduplicationKey = policyFields()
		if err := Client().Create(t.Context(), job); err == nil {
			t.Error("apiserver accepted a Manual request with policyRef")
		}
	})
	t.Run("policy without context", func(t *testing.T) {
		job := manualCapture(ns, "shape-policy-bare")
		job.Spec.RequestType = trawlv1alpha1.CaptureRequestPolicy
		if err := Client().Create(t.Context(), job); err == nil {
			t.Error("apiserver accepted a Policy request without policyRef")
		}
	})
	t.Run("policy with full context", func(t *testing.T) {
		job := manualCapture(ns, "shape-policy-full")
		job.Spec.RequestType = trawlv1alpha1.CaptureRequestPolicy
		job.Spec.PolicyRef, job.Spec.Trigger, job.Spec.DeduplicationKey = policyFields()
		if err := Client().Create(t.Context(), job); err != nil {
			t.Errorf("apiserver rejected a complete Policy request: %v", err)
		}
	})
	t.Run("trigger source without its branch", func(t *testing.T) {
		job := manualCapture(ns, "shape-trigger-branch")
		job.Spec.RequestType = trawlv1alpha1.CaptureRequestPolicy
		job.Spec.PolicyRef, job.Spec.Trigger, job.Spec.DeduplicationKey = policyFields()
		job.Spec.Trigger.Suricata = nil
		if err := Client().Create(t.Context(), job); err == nil {
			t.Error("apiserver accepted a SuricataAlert trigger without suricata context")
		}
	})
}

func TestCaptureJobSpecIsImmutableExceptRetention(t *testing.T) {
	ns := NewNamespace(t)

	cases := []struct {
		name   string
		mutate func(*trawlv1alpha1.CaptureJob)
	}{
		{"tapRef", func(j *trawlv1alpha1.CaptureJob) { j.Spec.TapRef.Name = "other" }},
		{"targetNode", func(j *trawlv1alpha1.CaptureJob) { j.Spec.TargetNode = "other-node" }},
		{"filter", func(j *trawlv1alpha1.CaptureJob) { j.Spec.Filter = "tcp" }},
		{"filter cleared", func(j *trawlv1alpha1.CaptureJob) { j.Spec.Filter = "" }},
		{"duration", func(j *trawlv1alpha1.CaptureJob) { j.Spec.Duration = "3m" }},
		{"snaplen", func(j *trawlv1alpha1.CaptureJob) { j.Spec.Snaplen = 128 }},
		{"maxSize", func(j *trawlv1alpha1.CaptureJob) { j.Spec.MaxSize = resource.MustParse("60Mi") }},
		{"requestType", func(j *trawlv1alpha1.CaptureJob) {
			j.Spec.RequestType = trawlv1alpha1.CaptureRequestPolicy
			j.Spec.PolicyRef, j.Spec.Trigger, j.Spec.DeduplicationKey = policyFields()
		}},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			job := manualCapture(ns, "immutable-"+strconv.Itoa(i))
			if err := Client().Create(t.Context(), job); err != nil {
				t.Fatalf("create: %v", err)
			}
			tc.mutate(job)
			if err := Client().Update(t.Context(), job); err == nil {
				t.Errorf("apiserver accepted a change to %s", tc.name)
			}
		})
	}

	t.Run("retention", func(t *testing.T) {
		job := manualCapture(ns, "immutable-retention")
		if err := Client().Create(t.Context(), job); err != nil {
			t.Fatalf("create: %v", err)
		}
		job.Spec.Retention = "2d"
		if err := Client().Update(t.Context(), job); err != nil {
			t.Errorf("apiserver rejected a retention change: %v", err)
		}
	})
}

func TestCaptureJobStatusIsASubresource(t *testing.T) {
	// The reporter's Role grants patch on capturejobs/status only. If status
	// were part of the main resource that grant would be meaningless.
	ns := NewNamespace(t)
	job := manualCapture(ns, "status-sub")
	if err := Client().Create(t.Context(), job); err != nil {
		t.Fatalf("create: %v", err)
	}

	job.Status.Phase = trawlv1alpha1.CapturePhaseCapturing
	if err := Client().Update(t.Context(), job); err != nil {
		t.Fatalf("update: %v", err)
	}
	got := &trawlv1alpha1.CaptureJob{}
	if err := Client().Get(t.Context(), client.ObjectKeyFromObject(job), got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status.Phase != "" {
		t.Errorf("main-resource update wrote status phase %q", got.Status.Phase)
	}

	got.Status.Phase = trawlv1alpha1.CapturePhaseCapturing
	if err := Client().Status().Update(t.Context(), got); err != nil {
		t.Fatalf("status update: %v", err)
	}
	if err := Client().Get(t.Context(), client.ObjectKeyFromObject(job), got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status.Phase != trawlv1alpha1.CapturePhaseCapturing {
		t.Errorf("status subresource update did not persist phase, got %q", got.Status.Phase)
	}
}
