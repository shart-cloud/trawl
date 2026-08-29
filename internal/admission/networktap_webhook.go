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

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/audit"
	"trawl.cloud/trawl/internal/content"
)

// NetworkTapWebhook validates and defaults NetworkTap resources.
//
// It carries the rules the CRD schema cannot express. CEL handles the closed
// source union and analyzer requirements; three things remain here:
//
//   - Namespace enforcement, which no CRD can express (FR-001).
//   - Semantic checks over values the schema only shape-checks — an empty
//     selector, requests exceeding limits.
//   - The durable-audit gate, which requires a network call (FR-036).
type NetworkTapWebhook struct {
	Gate *Gate
}

// +kubebuilder:webhook:path=/mutate-trawl-cloud-v1alpha1-networktap,mutating=true,failurePolicy=fail,sideEffects=None,groups=trawl.cloud,resources=networktaps,verbs=create;update,versions=v1alpha1,name=mnetworktap.trawl.cloud,admissionReviewVersions=v1
// +kubebuilder:webhook:path=/validate-trawl-cloud-v1alpha1-networktap,mutating=false,failurePolicy=fail,sideEffects=None,groups=trawl.cloud,resources=networktaps,verbs=create;update;delete,versions=v1alpha1,name=vnetworktap.trawl.cloud,admissionReviewVersions=v1

// SetupWithManager registers the webhook.
//
// failurePolicy is Fail, not Ignore. An Ignore policy would let every rule here
// be bypassed by making the webhook unavailable, which for the namespace and
// audit gates means bypassing a security control by causing an outage.
func (w *NetworkTapWebhook) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &trawlv1alpha1.NetworkTap{}).
		WithDefaulter(w).
		WithValidator(w).
		Complete()
}

var (
	_ admission.Defaulter[*trawlv1alpha1.NetworkTap] = &NetworkTapWebhook{}
	_ admission.Validator[*trawlv1alpha1.NetworkTap] = &NetworkTapWebhook{}
)

// Default applies defaults the schema cannot express.
func (w *NetworkTapWebhook) Default(_ context.Context, tap *trawlv1alpha1.NetworkTap) error {
	if tap.Spec.Mode == "" {
		tap.Spec.Mode = trawlv1alpha1.TapModePassive
	}
	// A mirror port receives frames addressed to other hosts, so without
	// promiscuous mode the NIC drops exactly the traffic the tap exists to see.
	// Defaulting it on for mirror sources removes a silent misconfiguration
	// whose only symptom is an empty dashboard.
	if tap.Spec.Type == trawlv1alpha1.TapSourceMirrorInterface && tap.Spec.MirrorInterface != nil {
		tap.Spec.MirrorInterface.Promiscuous = true
	}
	return nil
}

// ValidateCreate validates a new NetworkTap and records the mutation.
func (w *NetworkTapWebhook) ValidateCreate(ctx context.Context, tap *trawlv1alpha1.NetworkTap) (admission.Warnings, error) {
	return w.validate(ctx, tap, nil)
}

// ValidateUpdate validates a change to an existing NetworkTap.
func (w *NetworkTapWebhook) ValidateUpdate(ctx context.Context, old, updated *trawlv1alpha1.NetworkTap) (admission.Warnings, error) {
	return w.validate(ctx, updated, old)
}

// ValidateDelete records the deletion. Deleting a tap stops monitoring, which is
// a security-relevant action: it is how an attacker would blind the sensor.
func (w *NetworkTapWebhook) ValidateDelete(ctx context.Context, tap *trawlv1alpha1.NetworkTap) (admission.Warnings, error) {
	if err := w.Gate.CheckNamespace(tap.Namespace); err != nil {
		return nil, err
	}
	return nil, w.commit(ctx)
}

func (w *NetworkTapWebhook) validate(ctx context.Context, tap *trawlv1alpha1.NetworkTap, old *trawlv1alpha1.NetworkTap) (admission.Warnings, error) {
	if err := w.Gate.CheckNamespace(tap.Namespace); err != nil {
		return nil, err
	}

	if errs := ValidateNetworkTapSpec(&tap.Spec); len(errs) > 0 {
		return nil, apierrors.NewInvalid(
			tap.GroupVersionKind().GroupKind(), tap.Name, errs)
	}

	if old != nil {
		if errs := validateImmutableFields(old, tap); len(errs) > 0 {
			return nil, apierrors.NewInvalid(
				tap.GroupVersionKind().GroupKind(), tap.Name, errs)
		}
	}

	return nil, w.commit(ctx)
}

// commit records the mutation before it is admitted (FR-036).
//
// When the ledger is unavailable this returns an error and the mutation is
// refused. That is the intended trade: an unaudited change to what the sensor
// watches is worse than a failed kubectl apply, and refusing it does not touch
// monitored traffic.
func (w *NetworkTapWebhook) commit(ctx context.Context) error {
	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		// No admission request in context means this is not a real admission
		// call, so there is nothing to audit.
		return nil
	}
	return w.Gate.CommitMutation(ctx, req, audit.DecisionAllowed, "Accepted")
}

// ValidateNetworkTapSpec applies the semantic rules the schema cannot.
//
// Exported so the reconciler can re-check a stored object: a tap written before
// a rule existed, or restored directly into etcd, has never passed through this
// webhook.
func ValidateNetworkTapSpec(spec *trawlv1alpha1.NetworkTapSpec) field.ErrorList {
	var errs field.ErrorList
	specPath := field.NewPath("spec")

	if spec.Mode != trawlv1alpha1.TapModePassive {
		errs = append(errs, field.NotSupported(specPath.Child("mode"),
			spec.Mode, []string{string(trawlv1alpha1.TapModePassive)}))
	}

	source, sourcePath := activeSource(spec, specPath)
	if source != nil {
		errs = append(errs, validateInterfaceSource(source, sourcePath)...)
	}

	errs = append(errs, validateAnalyzer(&spec.Analyzers.Suricata,
		specPath.Child("analyzers", "suricata"))...)
	errs = append(errs, validateAnalyzer(&spec.Analyzers.Zeek,
		specPath.Child("analyzers", "zeek"))...)

	return errs
}

func activeSource(spec *trawlv1alpha1.NetworkTapSpec, specPath *field.Path) (*trawlv1alpha1.InterfaceSource, *field.Path) {
	switch spec.Type {
	case trawlv1alpha1.TapSourceMirrorInterface:
		return spec.MirrorInterface, specPath.Child("mirrorInterface")
	case trawlv1alpha1.TapSourceNodeInterface:
		return spec.NodeInterface, specPath.Child("nodeInterface")
	default:
		return nil, specPath
	}
}

func validateInterfaceSource(src *trawlv1alpha1.InterfaceSource, path *field.Path) field.ErrorList {
	var errs field.ErrorList

	// An empty selector matches every node. The schema cannot express
	// "non-empty" for a LabelSelector, so it is checked here: for a mirror
	// source an empty selector would open capture sockets cluster-wide rather
	// than on the one node wired to the SPAN port.
	if len(src.NodeSelector.MatchLabels) == 0 && len(src.NodeSelector.MatchExpressions) == 0 {
		errs = append(errs, field.Required(path.Child("nodeSelector"),
			"a non-empty node selector is required; an empty selector would match every node"))
	}
	return errs
}

func validateAnalyzer(cfg *trawlv1alpha1.AnalyzerConfig, path *field.Path) field.ErrorList {
	var errs field.ErrorList
	if !cfg.Enabled {
		// A disabled analyzer's configuration is inert; validating it would
		// reject specs that are harmless.
		return errs
	}

	if cfg.Resources == nil {
		errs = append(errs, field.Required(path.Child("resources"),
			"an enabled analyzer requires resource requests and limits"))
		return errs
	}

	for _, name := range []string{"cpu", "memory"} {
		request, hasRequest := cfg.Resources.Requests[resourceName(name)]
		limit, hasLimit := cfg.Resources.Limits[resourceName(name)]

		if !hasRequest {
			errs = append(errs, field.Required(path.Child("resources", "requests", name),
				"an enabled analyzer requires a "+name+" request"))
		}
		if !hasLimit {
			errs = append(errs, field.Required(path.Child("resources", "limits", name),
				"an enabled analyzer requires a "+name+" limit"))
		}
		// A request above its limit is unschedulable. Rejecting it here turns a
		// pod that never schedules into an immediate, explicable error.
		if hasRequest && hasLimit && request.Cmp(limit) > 0 {
			errs = append(errs, field.Invalid(path.Child("resources", "requests", name),
				request.String(), "request must not exceed limit"))
		}
	}

	if cfg.CustomContent != nil {
		if _, err := content.ParseReference(cfg.CustomContent.Reference); err != nil {
			errs = append(errs, field.Invalid(path.Child("customContent", "reference"),
				// The reference is a repository path, not a secret, but it is
				// bounded before being echoed.
				truncate(cfg.CustomContent.Reference, 128),
				"custom content must be digest-pinned (repository@sha256:...)"))
		}
	}
	return errs
}

// validateImmutableFields rejects changes that would silently repoint a tap.
//
// Changing the source type or interface in place would keep the same object and
// history while observing entirely different traffic, so stored observations
// would be attributed to a tap that no longer describes them.
func validateImmutableFields(old, updated *trawlv1alpha1.NetworkTap) field.ErrorList {
	var errs field.ErrorList
	specPath := field.NewPath("spec")

	if old.Spec.Type != updated.Spec.Type {
		errs = append(errs, field.Forbidden(specPath.Child("type"),
			"source type is immutable; create a new NetworkTap instead"))
	}

	oldSrc, _ := activeSource(&old.Spec, specPath)
	newSrc, path := activeSource(&updated.Spec, specPath)
	if oldSrc != nil && newSrc != nil && oldSrc.Interface != newSrc.Interface {
		errs = append(errs, field.Forbidden(path.Child("interface"),
			"interface is immutable; create a new NetworkTap instead"))
	}
	return errs
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func resourceName(s string) corev1.ResourceName { return corev1.ResourceName(s) }
