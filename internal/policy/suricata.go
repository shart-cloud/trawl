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

// Package policy decides whether an observation should start a capture.
//
// Matching is a pure function of a trigger and an observation. It reads no
// cluster state, opens no connections, and holds nothing between calls, so a
// decision can be reproduced from the record that produced it - which is what
// makes a policy execution explainable after the fact.
package policy

import (
	"fmt"
	"math"
	"slices"
	"unicode/utf8"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/observation"
)

// Decision is the outcome of evaluating one observation against one trigger.
type Decision struct {
	// Matched says whether the observation qualifies.
	Matched bool

	// Reason names why it did not. Empty when Matched.
	Reason NotMatchedReason
}

// NotMatchedReason is the closed set of reasons an observation did not match.
//
// Closed because these values reach status counters and dashboards. A free-form
// string would let a new code path invent a label nothing aggregates.
type NotMatchedReason string

const (
	// ReasonNotAnAlert means the observation carries no Suricata signature.
	// The worker reads one stream of every observation type, so this is the
	// ordinary outcome for most records rather than an error.
	ReasonNotAnAlert NotMatchedReason = "NotAnAlert"

	// ReasonSeverityNotListed means the alert's severity is not in the trigger.
	ReasonSeverityNotListed NotMatchedReason = "SeverityNotListed"

	// ReasonRuleNotListed means the trigger narrows by rule ID and this alert's
	// signature is not among them.
	ReasonRuleNotListed NotMatchedReason = "RuleNotListed"

	// ReasonCategoryNotListed means the trigger narrows by category and this
	// alert's category is not among them.
	ReasonCategoryNotListed NotMatchedReason = "CategoryNotListed"

	// ReasonNotAClusterFlow means the observation carries no Hubble cluster
	// flow, the counterpart of ReasonNotAnAlert for drop triggers.
	ReasonNotAClusterFlow NotMatchedReason = "NotAClusterFlow"

	// ReasonDropReasonNotListed means the flow's drop reason is not in the
	// trigger.
	ReasonDropReasonNotListed NotMatchedReason = "DropReasonNotListed"

	// ReasonNotDenied means the flow was not denied, whatever reason it
	// carries.
	ReasonNotDenied NotMatchedReason = "NotDenied"

	// ReasonNamespaceNotListed means the trigger narrows by source namespace
	// and this flow left a different one.
	ReasonNamespaceNotListed NotMatchedReason = "NamespaceNotListed"

	// ReasonBelowThreshold means the flow qualifies but the trigger's rolling
	// window has not yet seen enough of them.
	ReasonBelowThreshold NotMatchedReason = "BelowThreshold"
)

// MatchSuricata evaluates a Suricata alert trigger against an observation.
func MatchSuricata(t trawlv1alpha1.SuricataAlertTrigger, obs *observation.Observation) Decision {
	sig := obs.Details.Signature
	if sig == nil || obs.Source.Kind != observation.SourceSuricata {
		return Decision{Reason: ReasonNotAnAlert}
	}
	if !slices.Contains(t.Severities, sig.Severity) {
		return Decision{Reason: ReasonSeverityNotListed}
	}
	// The optional fields narrow only when set. An empty list is "no opinion",
	// not "match nothing".
	if len(t.RuleIDs) > 0 && !slices.Contains(t.RuleIDs, sig.RuleID) {
		return Decision{Reason: ReasonRuleNotListed}
	}
	// Whole-string comparison. Substring matching would quietly widen a
	// trigger beyond the categories the operator listed.
	if len(t.Categories) > 0 && !slices.Contains(t.Categories, sig.Category) {
		return Decision{Reason: ReasonCategoryNotListed}
	}
	return Decision{Matched: true}
}

// Snapshot field bounds, mirroring the CaptureJob API's MaxLength markers.
//
// Restated here because the markers are validation the API server applies to a
// job we have already built: exceeding one produces a rejected CaptureJob
// rather than a truncated field, and the capture is lost over a field that
// exists only to describe it. The API remains the authority - these are the
// lengths this package must not exceed, not a second definition of the limit.
const (
	maxSnapshotCategory = 128
	maxSnapshotMessage  = 512
)

// SuricataSnapshot copies the alert that fired into the immutable trigger
// context recorded on the CaptureJob.
//
// It carries identity and classification only. The packet payload, the raw EVE
// record and the matched content are all deliberately absent: the snapshot is
// written to an object readable by anyone who can read CaptureJobs, which is a
// wider audience than the one authorized to download the capture itself.
func SuricataSnapshot(obs *observation.Observation, fingerprint string) (*trawlv1alpha1.TriggerSnapshot, error) {
	sig := obs.Details.Signature
	if sig == nil {
		return nil, fmt.Errorf("observation %s carries no signature", obs.ID)
	}

	snapshot := &trawlv1alpha1.TriggerSnapshot{
		Source:      trawlv1alpha1.TriggerSourceSuricataAlert,
		Fingerprint: fingerprint,
		EventTime:   metav1.NewTime(obs.EventTime),
		ObservedAt:  metav1.NewTime(obs.ObservedAt),
		Suricata: &trawlv1alpha1.SuricataTriggerContext{
			RuleID:   sig.RuleID,
			Severity: sig.Severity,
			Category: truncate(sig.Category, maxSnapshotCategory),
			Message:  truncate(sig.Message, maxSnapshotMessage),
		},
	}
	// Only when it fits. The envelope carries a revision as int64 and the API
	// bounds it to a non-negative int32, so a plain conversion of an implausible
	// value wraps negative and the API server rejects the whole CaptureJob.
	// Losing the revision costs a detail about the signature; losing the job
	// costs the packets.
	if sig.Revision != nil && *sig.Revision >= 0 && *sig.Revision <= math.MaxInt32 {
		snapshot.Suricata.Revision = int32(*sig.Revision)
	}
	snapshot.Flow = flowSnapshot(obs.Flow)
	return snapshot, nil
}

// flowSnapshot copies the matched five-tuple, or nothing when the observation
// has no flow.
func flowSnapshot(flow *observation.Flow) *trawlv1alpha1.FlowSnapshot {
	if flow == nil {
		return nil
	}
	snapshot := &trawlv1alpha1.FlowSnapshot{
		SourceIP:      flow.Source.IP,
		DestinationIP: flow.Destination.IP,
		Protocol:      flow.Protocol,
		CommunityID:   flow.CommunityID,
	}
	if flow.Source.Port != nil {
		snapshot.SourcePort = *flow.Source.Port
	}
	if flow.Destination.Port != nil {
		snapshot.DestinationPort = *flow.Destination.Port
	}
	return snapshot
}

// truncate bounds a string by bytes, not runes.
//
// The API's MaxLength is a byte count, so cutting on a rune boundary is what
// keeps a multi-byte character from being split into invalid UTF-8 while still
// respecting the bound the server enforces.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.ValidString(s[:cut]) {
		cut--
	}
	return s[:cut]
}
