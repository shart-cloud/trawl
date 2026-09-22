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
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
)

func TestTapPhaseRequiresEveryLayerOfReadiness(t *testing.T) {
	tests := []struct {
		name      string
		matched   int
		ready     int32
		workload  metav1.ConditionStatus
		analyzers metav1.ConditionStatus
		want      trawlv1alpha1.TapPhase
	}{
		{"no targets is an error", 0, 0, metav1.ConditionFalse, metav1.ConditionUnknown, trawlv1alpha1.TapPhaseError},
		{"workload not ready is pending", 1, 1, metav1.ConditionFalse, metav1.ConditionTrue, trawlv1alpha1.TapPhasePending},
		{"workload state unknown is pending", 1, 1, metav1.ConditionUnknown, metav1.ConditionTrue, trawlv1alpha1.TapPhasePending},
		{"analyzer health unknown is pending", 1, 1, metav1.ConditionTrue, metav1.ConditionUnknown, trawlv1alpha1.TapPhasePending},
		{"no ready target is pending", 1, 0, metav1.ConditionTrue, metav1.ConditionTrue, trawlv1alpha1.TapPhasePending},
		{"partial target readiness is degraded", 2, 1, metav1.ConditionTrue, metav1.ConditionTrue, trawlv1alpha1.TapPhaseDegraded},
		{"analyzer failure is degraded", 1, 1, metav1.ConditionTrue, metav1.ConditionFalse, trawlv1alpha1.TapPhaseDegraded},
		{"complete observed readiness is active", 1, 1, metav1.ConditionTrue, metav1.ConditionTrue, trawlv1alpha1.TapPhaseActive},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := derivePhase(tt.matched, tt.ready, tt.workload, tt.analyzers); got != tt.want {
				t.Errorf("derivePhase() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTargetHealthRequiresAtLeastOneHealthyAnalyzer(t *testing.T) {
	tests := []struct {
		name      string
		analyzers []trawlv1alpha1.AnalyzerStatus
		want      bool
	}{
		{"no report is not health", nil, false},
		{"one healthy analyzer", []trawlv1alpha1.AnalyzerStatus{{Healthy: true}}, true},
		{"one failed analyzer", []trawlv1alpha1.AnalyzerStatus{{Healthy: false}}, false},
		{"partial analyzer health", []trawlv1alpha1.AnalyzerStatus{{Healthy: true}, {Healthy: false}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := &trawlv1alpha1.TargetStatus{Analyzers: tt.analyzers}
			if got := allAnalyzersHealthy(target); got != tt.want {
				t.Errorf("allAnalyzersHealthy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTargetSummaryExcludesStaleHealthAndKeepsPacketHistory(t *testing.T) {
	now := time.Now()
	oldPacket := metav1.NewTime(now.Add(-2 * staleHeartbeat))
	newPacket := metav1.NewTime(now.Add(-time.Second))
	tap := &trawlv1alpha1.NetworkTap{Status: trawlv1alpha1.NetworkTapStatus{
		Targets: []trawlv1alpha1.TargetStatus{
			{
				HeartbeatTime:  metav1.NewTime(now.Add(-2 * staleHeartbeat)),
				LastPacketTime: &oldPacket,
				Analyzers:      []trawlv1alpha1.AnalyzerStatus{{Healthy: true}},
			},
			{
				HeartbeatTime:  metav1.NewTime(now),
				LastPacketTime: &newPacket,
				Analyzers:      []trawlv1alpha1.AnalyzerStatus{{Healthy: true}},
			},
		},
	}}

	got := projectNetworkTapStatus(tap.Status, networkTapStatusFacts{
		generation:      7,
		matchedTargets:  2,
		workloadReady:   metav1.ConditionTrue,
		workloadMessage: workloadReadyMessage,
		now:             now,
	})
	if got.ReadyTargets != 1 {
		t.Errorf("ready targets = %d, want only the fresh target", got.ReadyTargets)
	}
	if got.LastPacketTime == nil || !got.LastPacketTime.Equal(&newPacket) {
		t.Errorf("last packet = %v, want %v", got.LastPacketTime, newPacket)
	}
	if got.Phase != trawlv1alpha1.TapPhaseDegraded {
		t.Errorf("phase = %q, want Degraded for one of two ready targets", got.Phase)
	}
	if got.ObservedGeneration != 7 || got.MatchedTargets != 2 {
		t.Errorf("generation/targets = %d/%d, want 7/2", got.ObservedGeneration, got.MatchedTargets)
	}
	if len(got.Conditions) != 5 {
		t.Errorf("conditions = %+v, want the complete five-condition projection", got.Conditions)
	}
}
