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

package admission

import (
	"context"
	"fmt"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/audit"
	"trawl.cloud/trawl/internal/config"
	"trawl.cloud/trawl/internal/policy"
)

// Rate-limit bounds the CRD's schema enforces and this re-checks in Go, for the
// same reason the CaptureJob webhook re-checks its own: an object restored into
// etcd, or written before a rule existed, never passed through CEL.
const (
	minCapturesPerHour = 1
	maxCapturesPerHour = 100
	minCooldown        = time.Second
	maxCooldown        = time.Hour
)

// CapturePolicyWebhook validates and defaults CapturePolicy resources.
//
// The same division as the CaptureJob webhook: the schema owns shape and
// bounds, and this owns what the API server cannot know on its own -
//
//   - Namespace enforcement (FR-001).
//   - The filter template's placeholders, which are a contract between this
//     type and internal/policy rather than a property of the string.
//   - The installation's retention ceiling, which is configuration.
//   - The durable-audit gate (FR-036), including arming as its own action.
type CapturePolicyWebhook struct {
	Gate   *Gate
	Config *config.Config
}

// +kubebuilder:webhook:path=/mutate-trawl-cloud-v1alpha1-capturepolicy,mutating=true,failurePolicy=fail,sideEffects=None,groups=trawl.cloud,resources=capturepolicies,verbs=create;update,versions=v1alpha1,name=mcapturepolicy.trawl.cloud,admissionReviewVersions=v1
// +kubebuilder:webhook:path=/validate-trawl-cloud-v1alpha1-capturepolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=trawl.cloud,resources=capturepolicies,verbs=create;update;delete,versions=v1alpha1,name=vcapturepolicy.trawl.cloud,admissionReviewVersions=v1

// SetupWithManager registers the webhook. failurePolicy is Fail for the same
// reason as the others: an unavailable webhook must not become a bypass of the
// namespace and audit gates.
func (w *CapturePolicyWebhook) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &trawlv1alpha1.CapturePolicy{}).
		WithDefaulter(w).
		WithValidator(w).
		Complete()
}

var (
	_ admission.Defaulter[*trawlv1alpha1.CapturePolicy] = &CapturePolicyWebhook{}
	_ admission.Validator[*trawlv1alpha1.CapturePolicy] = &CapturePolicyWebhook{}
)

// Default clamps retention to the installation ceiling and records who asked.
//
// The API default is 30d, the contract maximum. An installation with a lower
// ceiling would otherwise reject every policy that left the field blank, so the
// default is clamped rather than refused.
func (w *CapturePolicyWebhook) Default(ctx context.Context, p *trawlv1alpha1.CapturePolicy) error {
	// Clamped whenever it exceeds the ceiling, not only when it is absent.
	//
	// "Absent" is a state this never sees. spec.retention carries a structural
	// schema default of 30d, and the API server applies structural defaults
	// while decoding the request - before any mutating webhook runs. So an
	// operator who omits the field arrives here asking for the contract
	// maximum, and on an installation with a lower ceiling the emptiness check
	// this replaces never fired and validation rejected the object: every
	// policy that left retention blank was refused, which is the exact outcome
	// the clamp exists to prevent.
	//
	// Clamping an explicit request rather than refusing it is the same bargain
	// the field's own documentation describes - "further capped by the
	// installation's captureRetentionCeiling". The stored value is the
	// authority, so an operator reads back what they will actually get.
	if ceiling := w.retentionCeiling(); p.Spec.Retention == "" || retentionExceeds(p.Spec.Retention, ceiling) {
		p.Spec.Retention = formatRetention(ceiling)
	}

	if req, err := admission.RequestFromContext(ctx); err == nil &&
		req.Operation == admissionv1.Create && p.Annotations[trawlv1alpha1.AnnotationRequester] == "" {
		if p.Annotations == nil {
			p.Annotations = map[string]string{}
		}
		p.Annotations[trawlv1alpha1.AnnotationRequester] = req.UserInfo.Username
	}
	return nil
}

// ValidateCreate validates a new CapturePolicy and records the request.
func (w *CapturePolicyWebhook) ValidateCreate(ctx context.Context, p *trawlv1alpha1.CapturePolicy) (admission.Warnings, error) {
	if err := w.Gate.CheckNamespace(p.Namespace); err != nil {
		return nil, err
	}
	if errs := ValidateCapturePolicySpec(&p.Spec, w.retentionCeiling()); len(errs) > 0 {
		return nil, apierrors.NewInvalid(p.GroupVersionKind().GroupKind(), p.Name, errs)
	}

	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		// Not a real admission call; nothing to authorize or audit.
		return nil, nil
	}

	// A policy created already armed is an arming event as well as a creation.
	// Recording only the creation would leave the moment collection started
	// absent from the ledger.
	action := audit.ActionCapturePolicyCreate
	if p.Spec.Armed {
		action = audit.ActionCapturePolicyArm
	}
	return nil, w.Gate.CommitMutationAs(ctx, req, action, audit.DecisionAllowed, "Accepted")
}

// ValidateUpdate revalidates the spec and records arming separately.
func (w *CapturePolicyWebhook) ValidateUpdate(ctx context.Context, old, updated *trawlv1alpha1.CapturePolicy) (admission.Warnings, error) {
	if err := w.Gate.CheckNamespace(updated.Namespace); err != nil {
		return nil, err
	}
	if errs := ValidateCapturePolicySpec(&updated.Spec, w.retentionCeiling()); len(errs) > 0 {
		return nil, apierrors.NewInvalid(updated.GroupVersionKind().GroupKind(), updated.Name, errs)
	}

	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		return nil, nil
	}

	// The requester annotation is provenance, stamped once on create. A later
	// change would misattribute the policy to whoever edited it last.
	if old.Annotations[trawlv1alpha1.AnnotationRequester] != updated.Annotations[trawlv1alpha1.AnnotationRequester] {
		return nil, apierrors.NewInvalid(updated.GroupVersionKind().GroupKind(), updated.Name, field.ErrorList{
			field.Forbidden(field.NewPath("metadata", "annotations", trawlv1alpha1.AnnotationRequester),
				"the requester annotation is set on create and cannot be changed"),
		})
	}

	// Arming and disarming are the operationally significant edits: one starts
	// automatic collection, the other stops it. Both are recorded under their
	// own action so the ledger answers "when did this begin capturing" without
	// diffing every update.
	action := audit.ActionCapturePolicyUpdate
	switch {
	case !old.Spec.Armed && updated.Spec.Armed:
		action = audit.ActionCapturePolicyArm
	case old.Spec.Armed && !updated.Spec.Armed:
		action = audit.ActionCapturePolicyDisarm
	}
	return nil, w.Gate.CommitMutationAs(ctx, req, action, audit.DecisionAllowed, "Accepted")
}

// ValidateDelete records the deletion.
//
// Deleting a policy stops future evaluation and touches no evidence: the
// CaptureJobs it created carry no ownerReference back to it, precisely so that
// removing a rule never garbage-collects the packets it collected.
func (w *CapturePolicyWebhook) ValidateDelete(ctx context.Context, p *trawlv1alpha1.CapturePolicy) (admission.Warnings, error) {
	if err := w.Gate.CheckNamespace(p.Namespace); err != nil {
		return nil, err
	}
	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		return nil, nil
	}
	return nil, w.Gate.CommitMutationAs(ctx, req, audit.ActionCapturePolicyDelete, audit.DecisionAllowed, "Accepted")
}

func (w *CapturePolicyWebhook) retentionCeiling() time.Duration {
	if w.Config == nil || w.Config.CaptureRetentionCeiling <= 0 {
		// The shared constant, not a literal of the same value. Two webhooks
		// deciding the same installation's ceiling from two sources would
		// agree today and diverge the first time the constant moves.
		return config.DefaultCaptureRetentionCeiling
	}
	return w.Config.CaptureRetentionCeiling.Duration()
}

// retentionExceeds reports whether a retention string asks for longer than the
// ceiling allows.
//
// An unparseable value is not "too long" - it is invalid, and saying so is
// ValidateCapturePolicySpec's job. Clamping it here would replace a value the
// operator can see is wrong with one that looks deliberate.
func retentionExceeds(retention string, ceiling time.Duration) bool {
	d, err := config.ParseDuration(retention)
	if err != nil {
		return false
	}
	return d > ceiling
}

// ValidateCapturePolicySpec checks bounds the schema also enforces, plus the
// filter template, which the schema cannot check.
//
// Exported so the event worker can re-check a stored policy before rendering a
// filter from it. Values are not echoed: a template names internal addresses.
func ValidateCapturePolicySpec(spec *trawlv1alpha1.CapturePolicySpec, retentionCeiling time.Duration) field.ErrorList {
	var errs field.ErrorList
	specPath := field.NewPath("spec")

	// The template is the reason this function exists. Its placeholders are a
	// contract between this type and internal/policy, and no schema rule can
	// express "one of these five names": a regex would have to be kept in step
	// with the renderer by hand, which is the drift the shared validator
	// avoids.
	if err := policy.ValidateFilterTemplate(spec.Capture.FilterTemplate); err != nil {
		errs = append(errs, field.Invalid(specPath.Child("capture", "filterTemplate"), "", err.Error()))
	}

	if d, err := time.ParseDuration(spec.Capture.Duration); err != nil {
		errs = append(errs, field.Invalid(specPath.Child("capture", "duration"), spec.Capture.Duration,
			"must be a duration such as 30s or 5m"))
	} else if d < minCaptureDuration || d > maxCaptureDuration {
		errs = append(errs, field.Invalid(specPath.Child("capture", "duration"), spec.Capture.Duration,
			"must be between 1s and 1h"))
	}

	if spec.Capture.Snaplen != 0 && (spec.Capture.Snaplen < minSnaplen || spec.Capture.Snaplen > maxSnaplen) {
		errs = append(errs, field.Invalid(specPath.Child("capture", "snaplen"), spec.Capture.Snaplen,
			"must be 0 or between 64 and 262144"))
	}

	if spec.Capture.MaxSize.Cmp(minCaptureSize) < 0 || spec.Capture.MaxSize.Cmp(maxCaptureSize) > 0 {
		errs = append(errs, field.Invalid(specPath.Child("capture", "maxSize"), spec.Capture.MaxSize.String(),
			"must be between 1Mi and 1Gi"))
	}

	if r, err := config.ParseDuration(spec.Retention); err != nil {
		errs = append(errs, field.Invalid(specPath.Child("retention"), spec.Retention,
			"must be a duration such as 12h or 7d"))
	} else if r < minRetention || r > retentionCeiling {
		errs = append(errs, field.Invalid(specPath.Child("retention"), spec.Retention,
			fmt.Sprintf("must be between 1h and the installation ceiling of %s", formatRetention(retentionCeiling))))
	}

	if n := spec.RateLimit.MaxCapturesPerHour; n < minCapturesPerHour || n > maxCapturesPerHour {
		errs = append(errs, field.Invalid(specPath.Child("rateLimit", "maxCapturesPerHour"), n,
			"must be between 1 and 100"))
	}

	if d := spec.RateLimit.Cooldown.Duration; d < minCooldown || d > maxCooldown {
		errs = append(errs, field.Invalid(specPath.Child("rateLimit", "cooldown"), d.String(),
			"must be between 1s and 1h"))
	}

	return errs
}
