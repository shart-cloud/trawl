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

// Package status builds the Kubernetes conditions that Trawl resources publish.
//
// Constitution II requires status to describe observed reality rather than echo
// desired configuration. Two mechanics carry most of that weight and are easy to
// get subtly wrong, so they live here rather than in each reconciler:
//
//   - observedGeneration on every condition, and helpers that refuse to report
//     a stale condition as current truth. A True condition written against an
//     older spec is not evidence about the spec in front of you.
//   - LastTransitionTime that moves only when status actually changes, so
//     "how long has this been degraded" has an answer.
//
// Reason strings are a closed enum. Dashboards and alerts group by them, so a
// free-form reason is a cardinality bug and a broken alert at the same time.
package status

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"trawl.cloud/trawl/internal/sanitize"
)

// MaxMessageBytes mirrors the condition-message bound in
// contracts/telemetry.md.
const MaxMessageBytes = sanitize.MaxMessageBytes

// Condition types, fixed by contracts/telemetry.md.
const (
	// NetworkTap.
	TypeAccepted         = "Accepted"
	TypeTargetsResolved  = "TargetsResolved"
	TypeWorkloadReady    = "WorkloadReady"
	TypeAnalyzersHealthy = "AnalyzersHealthy"
	TypePacketsObserved  = "PacketsObserved"

	// CapturePolicy.
	TypeTapResolved     = "TapResolved"
	TypeSourceConnected = "SourceConnected"
	TypeWithinRateLimit = "WithinRateLimit"
	TypeReady           = "Ready"

	// CaptureJob.
	TypeTargetReady       = "TargetReady"
	TypeFilterValid       = "FilterValid"
	TypeCaptureStarted    = "CaptureStarted"
	TypeArtifactVerified  = "ArtifactVerified"
	TypeDownloadable      = "Downloadable"
	TypeRetentionEnforced = "RetentionEnforced"
)

// Reasons. PascalCase, no separators, bounded length: these are consumed as
// low-cardinality metric and dashboard dimensions.
const (
	ReasonAccepted            = "Accepted"
	ReasonInvalidSpec         = "InvalidSpec"
	ReasonWrongNamespace      = "WrongNamespace"
	ReasonAuditUnavailable    = "AuditUnavailable"
	ReasonTargetsResolved     = "TargetsResolved"
	ReasonNoEligibleTargets   = "NoEligibleTargets"
	ReasonAmbiguousTargets    = "AmbiguousTargets"
	ReasonProbePortConflict   = "ProbePortConflict"
	ReasonWorkloadReady       = "WorkloadReady"
	ReasonWorkloadUnavailable = "WorkloadUnavailable"
	ReasonWorkloadProgressing = "WorkloadProgressing"
	ReasonAnalyzersHealthy    = "AnalyzersHealthy"
	ReasonAnalyzerDegraded    = "AnalyzerDegraded"
	ReasonAnalyzerFailed      = "AnalyzerFailed"
	ReasonProbeUnavailable    = "ProbeUnavailable"
	ReasonPacketsObserved     = "PacketsObserved"
	ReasonNoPacketsObserved   = "NoPacketsObserved"
	ReasonInterfaceMissing    = "InterfaceMissing"
	ReasonContentStale        = "ContentStale"
	ReasonTapResolved         = "TapResolved"
	ReasonTapNotFound         = "TapNotFound"
	ReasonTapNotActive        = "TapNotActive"
	ReasonSourceConnected     = "SourceConnected"
	ReasonSourceDisconnected  = "SourceDisconnected"
	ReasonSourceGap           = "SourceGap"
	ReasonWithinRateLimit     = "WithinRateLimit"
	ReasonRateLimited         = "RateLimited"
	ReasonCooldownActive      = "CooldownActive"
	ReasonDisarmed            = "Disarmed"
	ReasonTargetReady         = "TargetReady"
	ReasonTargetUnavailable   = "TargetUnavailable"
	ReasonFilterValid         = "FilterValid"
	ReasonFilterInvalid       = "FilterInvalid"
	ReasonCaptureStarted      = "CaptureStarted"
	ReasonCaptureFailed       = "CaptureFailed"
	ReasonArtifactVerified    = "ArtifactVerified"
	ReasonArtifactMissing     = "ArtifactMissing"
	ReasonChecksumMismatch    = "ChecksumMismatch"
	ReasonStorageFailure      = "StorageFailure"
	ReasonDownloadable        = "Downloadable"
	ReasonNotDownloadable     = "NotDownloadable"
	ReasonRetentionEnforced   = "RetentionEnforced"
	ReasonRetentionFailed     = "RetentionFailed"
	ReasonExpired             = "Expired"
	ReasonPending             = "Pending"
)

// AllReasons lists every reason in the enum. The contract test walks it to
// prove the shape rules hold, and it doubles as the documented set.
func AllReasons() []string {
	return []string{
		ReasonAccepted, ReasonInvalidSpec, ReasonWrongNamespace, ReasonAuditUnavailable,
		ReasonTargetsResolved, ReasonNoEligibleTargets, ReasonAmbiguousTargets,
		ReasonWorkloadReady, ReasonWorkloadUnavailable, ReasonWorkloadProgressing,
		ReasonAnalyzersHealthy, ReasonAnalyzerDegraded, ReasonAnalyzerFailed,
		ReasonProbeUnavailable, ReasonPacketsObserved, ReasonNoPacketsObserved,
		ReasonInterfaceMissing, ReasonContentStale,
		ReasonTapResolved, ReasonTapNotFound, ReasonTapNotActive,
		ReasonSourceConnected, ReasonSourceDisconnected, ReasonSourceGap,
		ReasonWithinRateLimit, ReasonRateLimited, ReasonCooldownActive, ReasonDisarmed,
		ReasonTargetReady, ReasonTargetUnavailable,
		ReasonFilterValid, ReasonFilterInvalid,
		ReasonCaptureStarted, ReasonCaptureFailed,
		ReasonArtifactVerified, ReasonArtifactMissing, ReasonChecksumMismatch,
		ReasonStorageFailure, ReasonDownloadable, ReasonNotDownloadable,
		ReasonRetentionEnforced, ReasonRetentionFailed, ReasonExpired, ReasonPending,
	}
}

// now is indirected so reconciliation tests can pin timestamps.
var now = time.Now

// New builds a condition with the message sanitized and bounded.
//
// LastTransitionTime is filled in by Set, which is the only place that can tell
// whether this is actually a transition.
func New(condType string, condStatus metav1.ConditionStatus, reason, message string, generation int64) metav1.Condition {
	return metav1.Condition{
		Type:               condType,
		Status:             condStatus,
		Reason:             reason,
		Message:            sanitize.String(message),
		ObservedGeneration: generation,
		LastTransitionTime: metav1.NewTime(now()),
	}
}

// Set inserts or updates cond in conditions, keyed by type.
//
// LastTransitionTime is carried forward when Status is unchanged, so repeated
// reconciles of a steady resource do not rewrite history.
func Set(conditions *[]metav1.Condition, cond metav1.Condition) {
	if conditions == nil {
		return
	}
	for i := range *conditions {
		existing := &(*conditions)[i]
		if existing.Type != cond.Type {
			continue
		}
		if existing.Status == cond.Status {
			cond.LastTransitionTime = existing.LastTransitionTime
		}
		*existing = cond
		return
	}
	*conditions = append(*conditions, cond)
}

// Get returns the condition of the given type, or nil when absent.
func Get(conditions []metav1.Condition, condType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == condType {
			return &conditions[i]
		}
	}
	return nil
}

// IsStale reports whether the condition is missing or was observed against an
// older generation than the one supplied.
//
// A missing condition is stale, not current: absence of evidence is not
// evidence of health.
func IsStale(conditions []metav1.Condition, condType string, generation int64) bool {
	c := Get(conditions, condType)
	return c == nil || c.ObservedGeneration < generation
}

// IsTrue reports whether the condition is True and was observed against the
// current generation. A stale True is not a True.
func IsTrue(conditions []metav1.Condition, condType string, generation int64) bool {
	c := Get(conditions, condType)
	return c != nil && c.Status == metav1.ConditionTrue && c.ObservedGeneration >= generation
}
