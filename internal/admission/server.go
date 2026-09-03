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

// Package admission implements Trawl's validating and defaulting webhooks.
//
// Two responsibilities here are security boundaries rather than conveniences:
//
//   - Namespace enforcement (FR-001). Trawl CRDs are cluster-scoped in
//     discovery but only ever reconciled in the configured system namespace.
//     The webhook is what makes that true, because a CRD alone cannot express
//     "only in this one namespace".
//   - The durable-audit gate (FR-036). A user mutation is admitted only after
//     its audit record is durably committed. When the ledger is unavailable the
//     mutation is rejected — fail closed. This never touches monitored traffic,
//     which is what the constitution's fail-open rule protects.
package admission

import (
	"context"
	"errors"
	"fmt"

	admissionv1 "k8s.io/api/admission/v1"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"trawl.cloud/trawl/internal/audit"
	"trawl.cloud/trawl/internal/sanitize"
	"trawl.cloud/trawl/internal/telemetry"
)

// AuditCommitter is the subset of the audit client the webhook path needs.
type AuditCommitter interface {
	Commit(ctx context.Context, rec audit.Record) (audit.CommitResult, error)
}

// Gate enforces namespace scope and the durable-audit requirement for every
// Trawl resource mutation.
//
// It is shared by the per-kind webhooks so the two rules cannot drift apart
// between NetworkTap, CapturePolicy, and CaptureJob.
type Gate struct {
	// SystemNamespace is the only namespace in which Trawl resources are
	// accepted.
	SystemNamespace string

	// Audit commits the mutation record. A nil Audit is a configuration error,
	// not an opt-out: the gate refuses to admit anything without it.
	Audit AuditCommitter

	Metrics *telemetry.Metrics
}

// ErrAuditUnavailable is returned when the durable audit commit could not be
// verified, and the mutation must therefore be refused.
var ErrAuditUnavailable = errors.New("audit ledger unavailable; mutation refused")

// CheckNamespace rejects a request outside the configured system namespace.
//
// Cluster-wide CRD discovery does not imply cluster-wide reconciliation. Without
// this check a user with namespace-scoped create rights elsewhere could get
// Trawl to render privileged workloads in their own namespace.
func (g *Gate) CheckNamespace(namespace string) error {
	if namespace != g.SystemNamespace {
		return fmt.Errorf(
			"trawl resources are accepted only in the %q namespace; this resource targets %q",
			g.SystemNamespace, sanitize.String(namespace))
	}
	return nil
}

// ActorFrom extracts the authenticated identity from an admission request.
//
// The identity is the API server's, not anything the object claims about
// itself, so a user cannot audit a mutation as somebody else.
func ActorFrom(req admission.Request) audit.Actor {
	return audit.Actor{
		Username: req.UserInfo.Username,
		UID:      req.UserInfo.UID,
		Groups:   req.UserInfo.Groups,
	}
}

// ResourceFrom describes the object a request concerns.
func ResourceFrom(req admission.Request) audit.Resource {
	return audit.Resource{
		Group:     req.Resource.Group,
		Kind:      req.Kind.Kind,
		Namespace: req.Namespace,
		Name:      req.Name,
		UID:       string(req.UID),
	}
}

// ActionFor maps a kind and operation to the audit action enum.
func ActionFor(kind string, op admissionv1.Operation) (string, error) {
	switch kind {
	case "NetworkTap":
		switch op {
		case admissionv1.Create:
			return audit.ActionNetworkTapCreate, nil
		case admissionv1.Update:
			return audit.ActionNetworkTapUpdate, nil
		case admissionv1.Delete:
			return audit.ActionNetworkTapDelete, nil
		}
	case "CapturePolicy":
		switch op {
		case admissionv1.Create:
			return audit.ActionCapturePolicyCreate, nil
		case admissionv1.Update:
			return audit.ActionCapturePolicyUpdate, nil
		case admissionv1.Delete:
			return audit.ActionCapturePolicyDelete, nil
		}
	case "CaptureJob":
		if op == admissionv1.Create {
			return audit.ActionCaptureJobManualCreate, nil
		}
	}
	return "", fmt.Errorf("no audit action for %s %s", kind, op)
}

// CommitMutation durably records an admitted mutation before it is allowed.
//
// The ordering is the point of FR-036: the record is committed first, so a
// mutation that reaches etcd always has a durable record behind it. The reverse
// order would permit an unaudited change whenever the ledger failed in between.
func (g *Gate) CommitMutation(ctx context.Context, req admission.Request, decision, reason string) error {
	if g.Audit == nil {
		return ErrAuditUnavailable
	}

	action, err := ActionFor(req.Kind.Kind, req.Operation)
	if err != nil {
		return err
	}

	rec := audit.Record{
		Action:    action,
		Decision:  decision,
		Reason:    reason,
		Actor:     ActorFrom(req),
		Resource:  ResourceFrom(req),
		RequestID: string(req.UID),
		StableKey: audit.StableKeyForAdmission(string(req.UID), action, decision),
	}

	res, err := g.Audit.Commit(ctx, rec)
	if g.Metrics != nil {
		result := res.Result
		if result == "" {
			result = audit.ResultUnavailable
		}
		g.Metrics.AuditCommitTotal.WithLabelValues(decision, result).Inc()
		if result == audit.ResultConflict {
			g.Metrics.AuditConflictTotal.Inc()
		}
	}
	if err != nil {
		// The underlying error can name a storage endpoint, so callers get the
		// sentinel and operators get the detail in sanitized logs.
		return fmt.Errorf("%w: %w", ErrAuditUnavailable, sanitize.Error(err))
	}
	return nil
}
