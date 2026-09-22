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

func TestStalenessChangesCurrentHealthWithoutErasingPacketHistory(t *testing.T) {
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	staleHeartbeatTime := metav1.NewTime(now.Add(-2 * staleHeartbeat))
	freshHeartbeatTime := metav1.NewTime(now)
	oldPacket := metav1.NewTime(now.Add(-time.Hour))

	project := func(targets []trawlv1alpha1.TargetStatus, matched int) trawlv1alpha1.NetworkTapStatus {
		return projectNetworkTapStatus(trawlv1alpha1.NetworkTapStatus{Targets: targets}, networkTapStatusFacts{
			generation:      3,
			matchedTargets:  matched,
			workloadReady:   metav1.ConditionTrue,
			workloadMessage: workloadReadyMessage,
			now:             now,
		})
	}

	t.Run("stale-only packet history survives", func(t *testing.T) {
		got := project([]trawlv1alpha1.TargetStatus{{
			NodeName:       "old-node",
			HeartbeatTime:  staleHeartbeatTime,
			LastPacketTime: &oldPacket,
			Analyzers:      []trawlv1alpha1.AnalyzerStatus{{Name: "Suricata", Healthy: true}},
		}}, 1)
		if got.LastPacketTime == nil || !got.LastPacketTime.Equal(&oldPacket) {
			t.Errorf("last packet = %v, want historical %v", got.LastPacketTime, oldPacket)
		}
		if got.ReadyTargets != 0 || got.Phase != trawlv1alpha1.TapPhasePending {
			t.Errorf("ready/phase = %d/%s, want 0/Pending", got.ReadyTargets, got.Phase)
		}
		analyzers := tapCondition(got.Conditions, "AnalyzersHealthy")
		if analyzers == nil || analyzers.Status != metav1.ConditionUnknown || analyzers.Reason != "ProbeUnavailable" {
			t.Errorf("analyzer condition = %+v, want Unknown/ProbeUnavailable", analyzers)
		}
		packets := tapCondition(got.Conditions, "PacketsObserved")
		if packets == nil || packets.Status != metav1.ConditionTrue {
			t.Errorf("packet condition = %+v, want historical True", packets)
		}
	})

	t.Run("stale unhealthy evidence does not override fresh health", func(t *testing.T) {
		got := project([]trawlv1alpha1.TargetStatus{
			{
				NodeName:      "old-node",
				HeartbeatTime: staleHeartbeatTime,
				Analyzers:     []trawlv1alpha1.AnalyzerStatus{{Name: "Suricata", Healthy: false}},
			},
			{
				NodeName:      "current-node",
				HeartbeatTime: freshHeartbeatTime,
				Analyzers:     []trawlv1alpha1.AnalyzerStatus{{Name: "Suricata", Healthy: true}},
			},
		}, 2)
		analyzers := tapCondition(got.Conditions, "AnalyzersHealthy")
		if analyzers == nil || analyzers.Status != metav1.ConditionTrue {
			t.Errorf("analyzer condition = %+v, want current healthy evidence", analyzers)
		}
		if got.ReadyTargets != 1 || got.Phase != trawlv1alpha1.TapPhaseDegraded {
			t.Errorf("ready/phase = %d/%s, want 1/Degraded for partial current coverage",
				got.ReadyTargets, got.Phase)
		}
	})
}

func tapCondition(conditions []metav1.Condition, conditionType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return &conditions[i]
		}
	}
	return nil
}
