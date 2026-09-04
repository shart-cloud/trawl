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
	"slices"
	"strings"
	"time"
	"unicode"

	admissionv1 "k8s.io/api/admission/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/audit"
	"trawl.cloud/trawl/internal/config"
)

// Bounds the CRD's CEL rules enforce and the webhook re-checks in Go, for
// objects that never passed through CEL (restored into etcd, or written
// before a rule existed).
const (
	minCaptureDuration = time.Second
	maxCaptureDuration = time.Hour
	minSnaplen         = 64
	maxSnaplen         = 262144
	minRetention       = time.Hour
	maxFilterBytes     = 1024
)

var (
	minCaptureSize = resource.MustParse("1Mi")
	maxCaptureSize = resource.MustParse("1Gi")
)

// CaptureJobWebhook validates and defaults CaptureJob resources.
//
// The schema (CEL) owns shape, bounds and immutability. What is left is what
// the API server cannot know on its own:
//
//   - Namespace enforcement (FR-001).
//   - Who is asking. Policy-typed jobs may only come from the event worker,
//     and retention may only be changed by a retention admin. Identity is the
//     API server's authenticated user info, never a field on the object.
//   - The installation's retention ceiling, which is configuration.
//   - The durable-audit gate (FR-036).
type CaptureJobWebhook struct {
	Gate   *Gate
	Config *config.Config
}

// +kubebuilder:webhook:path=/mutate-trawl-cloud-v1alpha1-capturejob,mutating=true,failurePolicy=fail,sideEffects=None,groups=trawl.cloud,resources=capturejobs,verbs=create;update,versions=v1alpha1,name=mcapturejob.trawl.cloud,admissionReviewVersions=v1
// +kubebuilder:webhook:path=/validate-trawl-cloud-v1alpha1-capturejob,mutating=false,failurePolicy=fail,sideEffects=None,groups=trawl.cloud,resources=capturejobs,verbs=create;update;delete,versions=v1alpha1,name=vcapturejob.trawl.cloud,admissionReviewVersions=v1

// SetupWithManager registers the webhook. failurePolicy is Fail for the same
// reason as the NetworkTap webhook: an unavailable webhook must not become a
// bypass of the identity and audit gates.
func (w *CaptureJobWebhook) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &trawlv1alpha1.CaptureJob{}).
		WithDefaulter(w).
		WithValidator(w).
		Complete()
}

var (
	_ admission.Defaulter[*trawlv1alpha1.CaptureJob] = &CaptureJobWebhook{}
	_ admission.Validator[*trawlv1alpha1.CaptureJob] = &CaptureJobWebhook{}
)

// Default fills the request type, clamps retention to the installation
// ceiling, and records who asked.
//
// The API default for retention is 30d, the contract maximum. An installation
// with a lower ceiling would otherwise reject every request that left the
// field blank, so the default is clamped rather than refused.
func (w *CaptureJobWebhook) Default(ctx context.Context, job *trawlv1alpha1.CaptureJob) error {
	if job.Spec.RequestType == "" {
		job.Spec.RequestType = trawlv1alpha1.CaptureRequestManual
	}
	if job.Spec.Retention == "" {
		job.Spec.Retention = formatRetention(w.retentionCeiling())
	}

	// The requester is stamped once, on create, from the authenticated
	// identity. ValidateUpdate refuses later changes.
	if req, err := admission.RequestFromContext(ctx); err == nil &&
		req.Operation == admissionv1.Create && job.Annotations[trawlv1alpha1.AnnotationRequester] == "" {
		if job.Annotations == nil {
			job.Annotations = map[string]string{}
		}
		job.Annotations[trawlv1alpha1.AnnotationRequester] = req.UserInfo.Username
	}
	return nil
}

// ValidateCreate validates a new CaptureJob and records the request.
func (w *CaptureJobWebhook) ValidateCreate(ctx context.Context, job *trawlv1alpha1.CaptureJob) (admission.Warnings, error) {
	if err := w.Gate.CheckNamespace(job.Namespace); err != nil {
		return nil, err
	}
	if errs := ValidateCaptureJobSpec(&job.Spec, w.retentionCeiling()); len(errs) > 0 {
		return nil, apierrors.NewInvalid(job.GroupVersionKind().GroupKind(), job.Name, errs)
	}

	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		// Not a real admission call; nothing to authorize or audit.
		return nil, nil
	}

	action := audit.ActionCaptureJobManualCreate
	if job.Spec.RequestType == trawlv1alpha1.CaptureRequestPolicy {
		// A policy-typed job carries a trigger snapshot the controller trusts
		// as provenance. Only the component that observed the trigger may
		// assert one.
		if req.UserInfo.Username != w.eventWorkerIdentity() {
			return nil, apierrors.NewInvalid(job.GroupVersionKind().GroupKind(), job.Name, field.ErrorList{
				field.Forbidden(field.NewPath("spec", "requestType"),
					"requestType Policy may only be set by the event worker"),
			})
		}
		action = audit.ActionCaptureJobPolicyCreate
	}
	return nil, w.Gate.CommitMutationAs(ctx, req, action, audit.DecisionAllowed, "Accepted")
}

// ValidateUpdate admits metadata changes freely and retention changes only
// from a retention admin, before the deadline. Everything else in spec is
// immutable by CEL, so it never reaches here.
func (w *CaptureJobWebhook) ValidateUpdate(ctx context.Context, old, updated *trawlv1alpha1.CaptureJob) (admission.Warnings, error) {
	if err := w.Gate.CheckNamespace(updated.Namespace); err != nil {
		return nil, err
	}
	kind := updated.GroupVersionKind().GroupKind()

	if old.Annotations[trawlv1alpha1.AnnotationRequester] != updated.Annotations[trawlv1alpha1.AnnotationRequester] {
		return nil, apierrors.NewInvalid(kind, updated.Name, field.ErrorList{
			field.Forbidden(field.NewPath("metadata", "annotations").Key(trawlv1alpha1.AnnotationRequester),
				"the requester is recorded at creation and cannot be changed"),
		})
	}

	if old.Spec.Retention == updated.Spec.Retention {
		// Status, labels, finalizers: not a retention change, so neither the
		// admin role nor an audit record applies.
		return nil, nil
	}

	if errs := ValidateCaptureJobSpec(&updated.Spec, w.retentionCeiling()); len(errs) > 0 {
		return nil, apierrors.NewInvalid(kind, updated.Name, errs)
	}

	retentionPath := field.NewPath("spec", "retention")
	if old.Status.Phase == trawlv1alpha1.CapturePhaseExpired {
		return nil, apierrors.NewInvalid(kind, updated.Name, field.ErrorList{
			field.Forbidden(retentionPath, "the artifact has expired; retention can no longer change"),
		})
	}
	if d := old.Status.RetentionDeadline; d != nil && !time.Now().Before(d.Time) {
		return nil, apierrors.NewInvalid(kind, updated.Name, field.ErrorList{
			field.Forbidden(retentionPath, "the retention deadline has passed; retention can no longer change"),
		})
	}

	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		return nil, nil
	}
	if !w.isRetentionAdmin(req) {
		return nil, apierrors.NewForbidden(
			trawlv1alpha1.GroupVersion.WithResource("capturejobs").GroupResource(), updated.Name,
			fmt.Errorf("retention may only be changed by a retention admin"))
	}
	return nil, w.Gate.CommitMutationAs(ctx, req, audit.ActionRetentionChange, audit.DecisionAllowed, "Accepted")
}

// ValidateDelete only enforces the namespace. The controller's finalizer
// records the deletion as artifact.expire records carrying the outcome, which
// admission cannot know yet.
func (w *CaptureJobWebhook) ValidateDelete(_ context.Context, job *trawlv1alpha1.CaptureJob) (admission.Warnings, error) {
	return nil, w.Gate.CheckNamespace(job.Namespace)
}

func (w *CaptureJobWebhook) retentionCeiling() time.Duration {
	if w.Config == nil || w.Config.CaptureRetentionCeiling <= 0 {
		return config.DefaultCaptureRetentionCeiling
	}
	return w.Config.CaptureRetentionCeiling.Duration()
}

// eventWorkerIdentity is the API server username of the event worker's
// service account. The namespace is part of it: the same account name
// elsewhere is somebody else.
func (w *CaptureJobWebhook) eventWorkerIdentity() string {
	sa := config.DefaultEventWorkerServiceAccount
	if w.Config != nil && w.Config.Capture.EventWorkerServiceAccount != "" {
		sa = w.Config.Capture.EventWorkerServiceAccount
	}
	return "system:serviceaccount:" + w.Gate.SystemNamespace + ":" + sa
}

func (w *CaptureJobWebhook) isRetentionAdmin(req admission.Request) bool {
	if w.Config == nil {
		return false
	}
	if slices.Contains(w.Config.Capture.RetentionAdminUsers, req.UserInfo.Username) {
		return true
	}
	return slices.ContainsFunc(req.UserInfo.Groups, func(g string) bool {
		return slices.Contains(w.Config.Capture.RetentionAdminGroups, g)
	})
}

// ValidateCaptureJobSpec applies the rules the schema cannot, and re-applies
// the bounds it can.
//
// Exported so the reconciler can re-check a stored object before rendering a
// privileged runner for it. Values are not echoed: a filter names internal
// addresses.
func ValidateCaptureJobSpec(spec *trawlv1alpha1.CaptureJobSpec, retentionCeiling time.Duration) field.ErrorList {
	var errs field.ErrorList
	specPath := field.NewPath("spec")

	if len(spec.Filter) > maxFilterBytes {
		errs = append(errs, field.TooLong(specPath.Child("filter"), "", maxFilterBytes))
	} else if strings.ContainsFunc(spec.Filter, func(r rune) bool { return r > unicode.MaxASCII || !unicode.IsPrint(r) }) {
		// dumpcap receives the filter as an argument. Control characters and
		// non-ASCII are not part of any BPF expression, and a NUL would
		// truncate what dumpcap sees relative to what the status records.
		errs = append(errs, field.Invalid(specPath.Child("filter"), "",
			"filter must be printable ASCII"))
	}

	if d, err := time.ParseDuration(spec.Duration); err != nil {
		errs = append(errs, field.Invalid(specPath.Child("duration"), spec.Duration, "must be a duration such as 30s or 5m"))
	} else if d < minCaptureDuration || d > maxCaptureDuration {
		errs = append(errs, field.Invalid(specPath.Child("duration"), spec.Duration, "must be between 1s and 1h"))
	}

	if spec.Snaplen != 0 && (spec.Snaplen < minSnaplen || spec.Snaplen > maxSnaplen) {
		errs = append(errs, field.Invalid(specPath.Child("snaplen"), spec.Snaplen, "must be 0 or between 64 and 262144"))
	}

	if spec.MaxSize.Cmp(minCaptureSize) < 0 || spec.MaxSize.Cmp(maxCaptureSize) > 0 {
		errs = append(errs, field.Invalid(specPath.Child("maxSize"), spec.MaxSize.String(), "must be between 1Mi and 1Gi"))
	}

	if r, err := config.ParseDuration(spec.Retention); err != nil {
		errs = append(errs, field.Invalid(specPath.Child("retention"), spec.Retention, "must be a duration such as 12h or 7d"))
	} else if r < minRetention || r > retentionCeiling {
		errs = append(errs, field.Invalid(specPath.Child("retention"), spec.Retention,
			fmt.Sprintf("must be between 1h and the installation ceiling of %s", formatRetention(retentionCeiling))))
	}

	return errs
}

// formatRetention writes a duration the way the API accepts it: whole days
// as Nd, anything else as a Go duration.
func formatRetention(d time.Duration) string {
	if d > 0 && d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", int(d/(24*time.Hour)))
	}
	return d.String()
}
