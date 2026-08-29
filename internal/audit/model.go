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

// Package audit implements Trawl's durable audit ledger.
//
// FR-036 makes this a gate rather than a log: a security-sensitive action is not
// reported as done until its record is durably committed, and a user-initiated
// action fails closed when that commit cannot be verified. Monitored traffic is
// never affected either way — the constitution's fail-open rule applies to
// packets, not to privileged operations.
//
// The private object ledger is authoritative. Loki receives a replayed,
// searchable copy and is explicitly not the durability boundary, so a Loki
// outage degrades searchability without losing the record.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"trawl.cloud/trawl/internal/sanitize"
)

// SchemaVersion identifies the record format. It is stored on every record so a
// reader can interpret an object written by an older operator.
const SchemaVersion = "trawl.audit/v1"

// DefaultPrefix is the ledger key prefix (plan.md "Audit lifecycle").
const DefaultPrefix = "audit/v1/"

// Actions, fixed by contracts/telemetry.md. These are indexed Loki labels, so
// the set is closed.
const (
	ActionNetworkTapCreate = "networktap.create"
	ActionNetworkTapUpdate = "networktap.update"
	ActionNetworkTapDelete = "networktap.delete"

	ActionCapturePolicyCreate = "capturepolicy.create"
	ActionCapturePolicyUpdate = "capturepolicy.update"
	ActionCapturePolicyDelete = "capturepolicy.delete"
	ActionCapturePolicyArm    = "capturepolicy.arm"
	ActionCapturePolicyDisarm = "capturepolicy.disarm"

	ActionCaptureJobManualCreate = "capturejob.manual_create"
	ActionCaptureJobPolicyCreate = "capturejob.policy_create"
	ActionCaptureJobTransition   = "capturejob.transition"

	ActionArtifactDownload = "artifact.download"
	ActionRetentionChange  = "retention.change"
	ActionArtifactExpire   = "artifact.expire"
)

// Decisions, fixed by contracts/telemetry.md.
//
// A fallible action produces two records: an `allowed` intent before the work
// and a `succeeded`/`failed` outcome after it. Collapsing them would make an
// authorized-but-failed action indistinguishable from one that never started.
const (
	DecisionAllowed   = "allowed"
	DecisionDenied    = "denied"
	DecisionSucceeded = "succeeded"
	DecisionFailed    = "failed"
)

// Commit results, mirroring the trawl_audit_commit_total `result` label.
const (
	ResultSuccess     = "success"
	ResultRetry       = "retry"
	ResultUnavailable = "unavailable"
	ResultConflict    = "conflict"
)

var validActions = []string{
	ActionNetworkTapCreate, ActionNetworkTapUpdate, ActionNetworkTapDelete,
	ActionCapturePolicyCreate, ActionCapturePolicyUpdate, ActionCapturePolicyDelete,
	ActionCapturePolicyArm, ActionCapturePolicyDisarm,
	ActionCaptureJobManualCreate, ActionCaptureJobPolicyCreate, ActionCaptureJobTransition,
	ActionArtifactDownload, ActionRetentionChange, ActionArtifactExpire,
}

var validDecisions = []string{DecisionAllowed, DecisionDenied, DecisionSucceeded, DecisionFailed}

// Actor identifies who performed an action.
//
// For API mutations this is the authenticated admission identity. For automatic
// actions it is the workload identity, with the initiating policy or user kept
// as a separate structured field rather than impersonated.
type Actor struct {
	Username string   `json:"username,omitempty"`
	UID      string   `json:"uid,omitempty"`
	Groups   []string `json:"groups,omitempty"`
}

// Resource identifies what an action concerned.
type Resource struct {
	Group     string `json:"group,omitempty"`
	Kind      string `json:"kind,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
	UID       string `json:"uid,omitempty"`
}

// Record is one audit entry.
//
// It carries no token material, presigned URL, storage credential, packet
// payload, or unbounded request body. Every free-text field is sanitized on the
// way in, so a caller cannot smuggle one through an error message.
type Record struct {
	SchemaVersion string    `json:"schemaVersion"`
	RecordedAt    time.Time `json:"recordedAt"`

	Action   string `json:"action"`
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
	Message  string `json:"message,omitempty"`

	Actor    Actor    `json:"actor"`
	Resource Resource `json:"resource"`

	RequestID string `json:"requestID,omitempty"`
	StableKey string `json:"stableKey"`

	// InitiatedBy names the policy or user behind an automatic action, so a
	// workload-identity record still answers "on whose behalf".
	InitiatedBy string `json:"initiatedBy,omitempty"`

	// LedgerKey and CommittedAt are filled in by the sink after verification.
	LedgerKey   string    `json:"ledgerKey,omitempty"`
	CommittedAt time.Time `json:"committedAt,omitempty"`
}

// Validate checks the enum fields and required identity.
//
// Action and decision are indexed labels, so an out-of-enum value is a
// cardinality problem as well as a correctness one.
func (r *Record) Validate() error {
	var errs []string
	if !slices.Contains(validActions, r.Action) {
		errs = append(errs, "action is not in the audit contract enum")
	}
	if !slices.Contains(validDecisions, r.Decision) {
		errs = append(errs, "decision is not in the audit contract enum")
	}
	if strings.TrimSpace(r.StableKey) == "" {
		errs = append(errs, "stableKey is required")
	}
	if len(errs) > 0 {
		return fmt.Errorf("invalid audit record: %s", strings.Join(errs, "; "))
	}
	return nil
}

// Sanitized returns a copy with every free-text field bounded and redacted.
//
// Reason and message routinely originate as dependency errors, which is exactly
// where credentials leak from.
func (r Record) Sanitized() Record {
	out := r
	out.Reason = sanitize.String(r.Reason)
	out.Message = sanitize.String(r.Message)
	out.InitiatedBy = sanitize.String(r.InitiatedBy)
	out.RequestID = sanitize.String(r.RequestID)

	out.Actor.Username = sanitize.String(r.Actor.Username)
	out.Actor.UID = sanitize.String(r.Actor.UID)
	if r.Actor.Groups != nil {
		out.Actor.Groups = make([]string, len(r.Actor.Groups))
		for i, g := range r.Actor.Groups {
			out.Actor.Groups[i] = sanitize.String(g)
		}
	}

	out.Resource.Group = sanitize.String(r.Resource.Group)
	out.Resource.Kind = sanitize.String(r.Resource.Kind)
	out.Resource.Namespace = sanitize.String(r.Resource.Namespace)
	out.Resource.Name = sanitize.String(r.Resource.Name)
	out.Resource.UID = sanitize.String(r.Resource.UID)
	return out
}

// Encode serializes a record for the ledger.
//
// Keys are sorted by encoding/json's struct field order, which is stable, so
// byte-identical input produces byte-identical output. Conflict detection
// depends on that: it compares stored bytes against what a retry would write.
func Encode(r Record) ([]byte, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return nil, sanitize.Errorf("encoding audit record: %v", err)
	}
	return data, nil
}

// Decode parses a ledger object.
func Decode(data []byte) (Record, error) {
	var r Record
	if err := json.Unmarshal(data, &r); err != nil {
		return Record{}, sanitize.Errorf("decoding audit record: %v", err)
	}
	return r, nil
}

// StableKeyForAdmission derives the idempotency key for an API mutation.
//
// The admission UID is unique per request, so a webhook retry of the same
// request converges on one record. Decision is part of the key because intent
// and outcome are separate records for the same request (FR-036).
func StableKeyForAdmission(admissionUID, action, decision string) string {
	if admissionUID == "" {
		return ""
	}
	return "admission/" + digest(admissionUID, action, decision)
}

// StableKeyForAutomatic derives the idempotency key for an action with no
// admission request behind it — a lifecycle transition, an expiry, a
// policy-created capture.
//
// Identity comes from the action plus the object and the specific step, so a
// reconciler that re-evaluates the same transition after a restart does not
// write a second record for it.
func StableKeyForAutomatic(action, objectUID, step string) string {
	return "automatic/" + digest(action, objectUID, step)
}

func digest(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		// Length-prefix so ("ab","c") and ("a","bc") cannot collide.
		_, _ = fmt.Fprintf(h, "%d:%s", len(p), p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// errConflict marks a stable key reused with different content.
var errConflict = errors.New("audit record conflict: stable key already holds different content")
