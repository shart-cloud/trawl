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

package telemetry

import "slices"

// Closed label-value enums from contracts/telemetry.md.
//
// These are what keep the metric label sets bounded. Prometheus creates a new
// time series per distinct label value, so a caller that passes an arbitrary
// string — a rule ID, an IP, an error message — turns one series into
// thousands. The enums make that a caught bug rather than a slow leak.

// Audit decisions and commit results.
const (
	AuditDecisionAllowed   = "allowed"
	AuditDecisionDenied    = "denied"
	AuditDecisionSucceeded = "succeeded"
	AuditDecisionFailed    = "failed"

	AuditResultSuccess     = "success"
	AuditResultRetry       = "retry"
	AuditResultUnavailable = "unavailable"
	AuditResultConflict    = "conflict"
)

// Controllers and reconcile outcomes.
const (
	ControllerNetworkTap = "networktap"
	ControllerCaptureJob = "capturejob"
	ControllerRetention  = "retention"

	ReconcileSuccess               = "success"
	ReconcileRequeue               = "requeue"
	ReconcileInvalid               = "invalid"
	ReconcileDependencyUnavailable = "dependency_unavailable"
	ReconcileError                 = "error"
)

// Sensor and ingestion.
const (
	SourceTypeMirrorInterface = "mirror_interface"
	SourceTypeNodeInterface   = "node_interface"

	AnalyzerSuricata = "suricata"
	AnalyzerZeek     = "zeek"

	RecordAccepted    = "accepted"
	RecordUnsupported = "unsupported"
	RecordMalformed   = "malformed"
)

// Trigger evaluation.
const (
	TriggerSourceSuricataLoki = "suricata_loki"
	TriggerSourceHubbleRelay  = "hubble_relay"

	PolicyNotMatched  = "not_matched"
	PolicyCreated     = "created"
	PolicyDuplicate   = "duplicate"
	PolicyRateLimited = "rate_limited"
	PolicyDisarmed    = "disarmed"
	PolicyFailed      = "failed"
)

// Capture lifecycle and artifact storage.
const (
	RequestTypeManual = "manual"
	RequestTypePolicy = "policy"

	// Capture request outcomes: admitted by the webhook, or resolved by the
	// controller to a runner or a failure.
	RequestAccepted = "accepted"
	RequestRejected = "rejected"
	RequestStarted  = "started"
	RequestFailed   = "failed"

	BoundDuration  = "duration"
	BoundSize      = "size"
	BoundCancelled = "cancelled"
	BoundError     = "error"

	ArtifactOpUpload  = "upload"
	ArtifactOpVerify  = "verify"
	ArtifactOpPresign = "presign"
	ArtifactOpDelete  = "delete"

	ArtifactResultSuccess     = "success"
	ArtifactResultFailure     = "failure"
	ArtifactResultUnavailable = "unavailable"
)

var (
	auditDecisions   = []string{AuditDecisionAllowed, AuditDecisionDenied, AuditDecisionSucceeded, AuditDecisionFailed}
	auditResults     = []string{AuditResultSuccess, AuditResultRetry, AuditResultUnavailable, AuditResultConflict}
	controllers      = []string{ControllerNetworkTap, ControllerCaptureJob, ControllerRetention}
	reconcileResults = []string{ReconcileSuccess, ReconcileRequeue, ReconcileInvalid, ReconcileDependencyUnavailable, ReconcileError}
	sourceTypes      = []string{SourceTypeMirrorInterface, SourceTypeNodeInterface}
	analyzers        = []string{AnalyzerSuricata, AnalyzerZeek}
	recordResults    = []string{RecordAccepted, RecordUnsupported, RecordMalformed}
	triggerSources   = []string{TriggerSourceSuricataLoki, TriggerSourceHubbleRelay}
	policyDecisions  = []string{PolicyNotMatched, PolicyCreated, PolicyDuplicate, PolicyRateLimited, PolicyDisarmed, PolicyFailed}
	requestTypes     = []string{RequestTypeManual, RequestTypePolicy}
	requestResults   = []string{RequestAccepted, RequestRejected, RequestStarted, RequestFailed}
	bounds           = []string{BoundDuration, BoundSize, BoundCancelled, BoundError}
	artifactOps      = []string{ArtifactOpUpload, ArtifactOpVerify, ArtifactOpPresign, ArtifactOpDelete}
	artifactResults  = []string{ArtifactResultSuccess, ArtifactResultFailure, ArtifactResultUnavailable}
)

// IsValidAuditDecision reports whether v is a contract audit decision.
func IsValidAuditDecision(v string) bool { return slices.Contains(auditDecisions, v) }

// IsValidAuditResult reports whether v is a contract audit commit result.
func IsValidAuditResult(v string) bool { return slices.Contains(auditResults, v) }

// IsValidController reports whether v names a contract controller.
func IsValidController(v string) bool { return slices.Contains(controllers, v) }

// IsValidReconcileResult reports whether v is a contract reconcile result.
func IsValidReconcileResult(v string) bool { return slices.Contains(reconcileResults, v) }

// IsValidSourceType reports whether v is a contract traffic-source type.
func IsValidSourceType(v string) bool { return slices.Contains(sourceTypes, v) }

// IsValidAnalyzer reports whether v names a contract analyzer.
func IsValidAnalyzer(v string) bool { return slices.Contains(analyzers, v) }

// IsValidRecordResult reports whether v is a contract record-processing result.
func IsValidRecordResult(v string) bool { return slices.Contains(recordResults, v) }

// IsValidTriggerSource reports whether v names a contract trigger source.
func IsValidTriggerSource(v string) bool { return slices.Contains(triggerSources, v) }

// IsValidPolicyDecision reports whether v is a contract policy decision.
func IsValidPolicyDecision(v string) bool { return slices.Contains(policyDecisions, v) }

// IsValidRequestType reports whether v is a contract capture request type.
func IsValidRequestType(v string) bool { return slices.Contains(requestTypes, v) }

// IsValidRequestResult reports whether v is a contract capture request result.
func IsValidRequestResult(v string) bool { return slices.Contains(requestResults, v) }

// IsValidBound reports whether v is a contract capture stop bound.
func IsValidBound(v string) bool { return slices.Contains(bounds, v) }

// IsValidArtifactOp reports whether v is a contract artifact operation.
func IsValidArtifactOp(v string) bool { return slices.Contains(artifactOps, v) }

// IsValidArtifactResult reports whether v is a contract artifact operation result.
func IsValidArtifactResult(v string) bool { return slices.Contains(artifactResults, v) }

// BoundFor maps a CaptureJob stop reason onto the bound label. Anything the
// API does not name is counted as an error stop rather than a new series.
func BoundFor(stopReason string) string {
	switch stopReason {
	case "Duration":
		return BoundDuration
	case "Size":
		return BoundSize
	case "Cancelled":
		return BoundCancelled
	default:
		return BoundError
	}
}
