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

package status

import (
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Constitution II: status must describe observed reality, and a resource must
// not claim readiness that has not been verified. These tests pin the mechanics
// that make that checkable — observedGeneration, stable reasons, and transition
// times that only move on real change.

func TestSetUpdatesInPlaceWithoutDuplicating(t *testing.T) {
	var conds []metav1.Condition

	Set(&conds, New(TypeAccepted, metav1.ConditionTrue, ReasonAccepted, "accepted", 1))
	Set(&conds, New(TypeAccepted, metav1.ConditionFalse, ReasonInvalidSpec, "bad interface", 2))

	if len(conds) != 1 {
		t.Fatalf("got %d conditions, want 1 (associative update)", len(conds))
	}
	if conds[0].Status != metav1.ConditionFalse {
		t.Errorf("status = %v, want False", conds[0].Status)
	}
	if conds[0].ObservedGeneration != 2 {
		t.Errorf("observedGeneration = %d, want 2", conds[0].ObservedGeneration)
	}
}

func TestTransitionTimeMovesOnlyOnStatusChange(t *testing.T) {
	// A reconcile loop runs constantly. If LastTransitionTime advanced on every
	// pass, "how long has this been degraded" would be unanswerable.
	var conds []metav1.Condition

	Set(&conds, New(TypeWorkloadReady, metav1.ConditionTrue, ReasonWorkloadReady, "ready", 1))
	first := Get(conds, TypeWorkloadReady).LastTransitionTime

	// Same status, new generation and message: time must not move.
	Set(&conds, New(TypeWorkloadReady, metav1.ConditionTrue, ReasonWorkloadReady, "ready, 3 targets", 2))
	second := Get(conds, TypeWorkloadReady).LastTransitionTime
	if !second.Equal(&first) {
		t.Errorf("LastTransitionTime moved without a status change: %v -> %v", first, second)
	}
	if got := Get(conds, TypeWorkloadReady).Message; got != "ready, 3 targets" {
		t.Errorf("message was not updated: %q", got)
	}

	// Status change: time must move.
	Set(&conds, New(TypeWorkloadReady, metav1.ConditionFalse, ReasonWorkloadUnavailable, "0 of 3 ready", 3))
	third := Get(conds, TypeWorkloadReady).LastTransitionTime
	if third.Equal(&first) {
		t.Error("LastTransitionTime did not move on a status change")
	}
}

func TestMessagesAreSanitizedAndBounded(t *testing.T) {
	// A dependency error carrying a token must not reach a status field, and a
	// long one must not exceed the 512-byte contract limit.
	var conds []metav1.Condition
	leaky := "upload failed: https://minio:9000/b/o?X-Amz-Signature=deadbeef " + strings.Repeat("x", 900)

	Set(&conds, New(TypeArtifactVerified, metav1.ConditionFalse, ReasonStorageFailure, leaky, 1))
	got := Get(conds, TypeArtifactVerified).Message

	if strings.Contains(got, "deadbeef") {
		t.Errorf("condition message leaked a signature: %q", got)
	}
	if len(got) > MaxMessageBytes {
		t.Errorf("message is %d bytes, want <= %d", len(got), MaxMessageBytes)
	}
}

func TestReasonsArePascalCaseAndBounded(t *testing.T) {
	// Reasons are a low-cardinality enum consumed by dashboards and alerts.
	// A free-form reason would break both.
	for _, r := range AllReasons() {
		if r == "" {
			t.Fatal("empty reason in enum")
		}
		if c := r[0]; c < 'A' || c > 'Z' {
			t.Errorf("reason %q is not PascalCase", r)
		}
		if strings.ContainsAny(r, " _-.") {
			t.Errorf("reason %q contains a separator", r)
		}
		if len(r) > 64 {
			t.Errorf("reason %q is %d bytes, want <= 64", r, len(r))
		}
	}
}

func TestIsStaleComparesObservedGeneration(t *testing.T) {
	// contracts/telemetry.md: status is stale when observedGeneration lags
	// metadata.generation, and dashboards must surface that rather than trust it.
	var conds []metav1.Condition
	Set(&conds, New(TypeAccepted, metav1.ConditionTrue, ReasonAccepted, "ok", 4))

	if IsStale(conds, TypeAccepted, 4) {
		t.Error("condition at the current generation reported stale")
	}
	if !IsStale(conds, TypeAccepted, 5) {
		t.Error("condition behind the current generation did not report stale")
	}
	if !IsStale(conds, TypeAnalyzersHealthy, 1) {
		t.Error("missing condition must be treated as stale, not current")
	}
}

func TestGetReturnsNilForMissing(t *testing.T) {
	if got := Get(nil, TypeAccepted); got != nil {
		t.Errorf("Get on empty conditions = %v, want nil", got)
	}
}

func TestIsTrueRequiresCurrentGeneration(t *testing.T) {
	// The core anti-lie rule: a True condition from an older generation is not
	// evidence about the current spec.
	var conds []metav1.Condition
	Set(&conds, New(TypePacketsObserved, metav1.ConditionTrue, ReasonPacketsObserved, "seen", 2))

	if !IsTrue(conds, TypePacketsObserved, 2) {
		t.Error("current-generation True condition did not report true")
	}
	if IsTrue(conds, TypePacketsObserved, 3) {
		t.Error("stale True condition reported true for a newer generation")
	}
}

func TestSetPreservesUnrelatedConditions(t *testing.T) {
	var conds []metav1.Condition
	Set(&conds, New(TypeAccepted, metav1.ConditionTrue, ReasonAccepted, "a", 1))
	Set(&conds, New(TypeTargetsResolved, metav1.ConditionTrue, ReasonTargetsResolved, "b", 1))
	Set(&conds, New(TypeAccepted, metav1.ConditionFalse, ReasonInvalidSpec, "c", 2))

	if len(conds) != 2 {
		t.Fatalf("got %d conditions, want 2", len(conds))
	}
	if tr := Get(conds, TypeTargetsResolved); tr == nil || tr.Status != metav1.ConditionTrue {
		t.Error("unrelated condition was disturbed")
	}
}

func TestNewUsesInjectedClock(t *testing.T) {
	// Reconciliation tests need deterministic timestamps.
	fixed := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	SetClockForTest(t, func() time.Time { return fixed })

	var conds []metav1.Condition
	Set(&conds, New(TypeAccepted, metav1.ConditionTrue, ReasonAccepted, "ok", 1))

	if got := Get(conds, TypeAccepted).LastTransitionTime.Time; !got.Equal(fixed) {
		t.Errorf("LastTransitionTime = %v, want %v", got, fixed)
	}
}

func TestUnknownIsDistinctFromFalse(t *testing.T) {
	// "We could not determine this" and "this is broken" drive different
	// operator responses, so Unknown must survive a round trip.
	var conds []metav1.Condition
	Set(&conds, New(TypeAnalyzersHealthy, metav1.ConditionUnknown, ReasonProbeUnavailable, "no heartbeat yet", 1))

	c := Get(conds, TypeAnalyzersHealthy)
	if c.Status != metav1.ConditionUnknown {
		t.Errorf("status = %v, want Unknown", c.Status)
	}
	if IsTrue(conds, TypeAnalyzersHealthy, 1) {
		t.Error("Unknown must not satisfy IsTrue")
	}
}
