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
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/sanitize"
	"trawl.cloud/trawl/internal/status"
)

// networkTapStatusFacts are the observations gathered by one reconcile. The
// projection below performs no Kubernetes reads or writes, so every aggregate
// truth rule can be tested against an explicit clock.
type networkTapStatusFacts struct {
	generation      int64
	matchedTargets  int
	workloadReady   metav1.ConditionStatus
	workloadMessage string
	now             time.Time
}

// projectNetworkTapStatus returns the complete controller-owned aggregate
// status while preserving the sensor-owned target reports in current.
func projectNetworkTapStatus(
	current trawlv1alpha1.NetworkTapStatus,
	facts networkTapStatusFacts,
) trawlv1alpha1.NetworkTapStatus {
	desired := *current.DeepCopy()
	desired.ObservedGeneration = facts.generation
	//nolint:gosec // node counts are bounded by cluster size
	desired.MatchedTargets = int32(facts.matchedTargets)

	ready, lastPacket := summarizeTargetStatus(desired.Targets, facts.now)
	desired.ReadyTargets = ready
	desired.LastPacketTime = lastPacket

	setTapCondition(&desired.Conditions, facts.now, status.TypeAccepted,
		metav1.ConditionTrue, status.ReasonAccepted, "spec accepted", facts.generation)
	setTapCondition(&desired.Conditions, facts.now, status.TypeTargetsResolved,
		boolCondition(facts.matchedTargets > 0), targetsReason(facts.matchedTargets),
		fmt.Sprintf("%d eligible node(s)", facts.matchedTargets), facts.generation)
	setTapCondition(&desired.Conditions, facts.now, status.TypeWorkloadReady,
		facts.workloadReady, workloadReasonEnum(facts.workloadReady),
		facts.workloadMessage, facts.generation)

	analyzersHealthy, analyzerMessage := projectedAnalyzerHealth(desired.Targets, facts.now)
	setTapCondition(&desired.Conditions, facts.now, status.TypeAnalyzersHealthy,
		analyzersHealthy, analyzerReasonEnum(analyzersHealthy),
		analyzerMessage, facts.generation)

	packetsSeen := lastPacket != nil
	setTapCondition(&desired.Conditions, facts.now, status.TypePacketsObserved,
		boolCondition(packetsSeen), packetsReason(packetsSeen),
		packetsMessage(lastPacket), facts.generation)

	desired.Phase = derivePhase(facts.matchedTargets, ready, facts.workloadReady, analyzersHealthy)
	return desired
}

func setTapCondition(
	conditions *[]metav1.Condition,
	now time.Time,
	conditionType string,
	conditionStatus metav1.ConditionStatus,
	reason, message string,
	generation int64,
) {
	status.Set(conditions, metav1.Condition{
		Type:               conditionType,
		Status:             conditionStatus,
		Reason:             reason,
		Message:            sanitize.String(message),
		ObservedGeneration: generation,
		LastTransitionTime: metav1.NewTime(now),
	})
}

func summarizeTargetStatus(
	targets []trawlv1alpha1.TargetStatus,
	now time.Time,
) (ready int32, lastPacket *metav1.Time) {
	for i := range targets {
		target := &targets[i]
		// Packet time is historical evidence. Heartbeat expiry changes whether
		// this target is healthy now; it cannot make an observed packet never
		// have happened.
		if target.LastPacketTime != nil &&
			(lastPacket == nil || target.LastPacketTime.After(lastPacket.Time)) {
			lastPacket = target.LastPacketTime
		}
		if targetIsFresh(target, now) && allAnalyzersHealthy(target) {
			ready++
		}
	}
	return ready, lastPacket
}

func targetIsFresh(target *trawlv1alpha1.TargetStatus, now time.Time) bool {
	return now.Sub(target.HeartbeatTime.Time) <= staleHeartbeat
}

func projectedAnalyzerHealth(
	targets []trawlv1alpha1.TargetStatus,
	now time.Time,
) (metav1.ConditionStatus, string) {
	if len(targets) == 0 {
		return metav1.ConditionUnknown, "no sensor has reported yet"
	}

	var unhealthy []string
	fresh := 0
	incomplete := false
	for i := range targets {
		target := &targets[i]
		if !targetIsFresh(target, now) {
			continue
		}
		fresh++
		if len(target.Analyzers) == 0 {
			incomplete = true
		}
		for _, analyzer := range target.Analyzers {
			if !analyzer.Healthy {
				unhealthy = append(unhealthy, fmt.Sprintf("%s/%s", target.NodeName, analyzer.Name))
			}
		}
	}
	if len(unhealthy) == 0 {
		switch {
		case fresh == 0:
			return metav1.ConditionUnknown, "all sensor reports are stale"
		case incomplete:
			return metav1.ConditionUnknown, "a current sensor has not reported analyzer health"
		default:
			return metav1.ConditionTrue, "all current analyzers healthy"
		}
	}
	return metav1.ConditionFalse, sanitize.String(fmt.Sprintf("unhealthy: %v", unhealthy))
}
