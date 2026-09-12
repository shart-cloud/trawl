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
	"slices"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/audit"
)

// PortMirrorWebhook validates PortMirror resources.
//
// PortMirror shipped without one, which made it the only Trawl kind the CRD
// contract's promise was untrue of: "all resources are accepted only in the
// installation-configured system namespace; the validating webhook rejects
// off-namespace resources". The controller declines to act on an off-namespace
// mirror, but the API server accepted it, so the object existed and read as
// configuration that had taken effect. The other three kinds refuse it outright
// and this one now does too.
//
// There is no defaulting counterpart. Every PortMirror default the type wants -
// `direction: Both` - is a structural schema default the API server applies
// while decoding, so a mutating webhook would have nothing left to do and would
// only add a second failurePolicy=Fail call to every create.
type PortMirrorWebhook struct {
	Gate *Gate
}

// +kubebuilder:webhook:path=/validate-trawl-cloud-v1alpha1-portmirror,mutating=false,failurePolicy=fail,sideEffects=None,groups=trawl.cloud,resources=portmirrors,verbs=create;update;delete,versions=v1alpha1,name=vportmirror.trawl.cloud,admissionReviewVersions=v1

// SetupWithManager registers the webhook.
//
// failurePolicy is Fail, as on the other three kinds: an Ignore policy would
// make every rule here bypassable by making the webhook unavailable, which for
// the namespace and audit gates means bypassing a security control by causing
// an outage. For this kind in particular the bypass would end at a switch.
func (w *PortMirrorWebhook) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &trawlv1alpha1.PortMirror{}).
		WithValidator(w).
		Complete()
}

var _ admission.Validator[*trawlv1alpha1.PortMirror] = &PortMirrorWebhook{}

// ValidateCreate validates a new PortMirror and records the mutation.
func (w *PortMirrorWebhook) ValidateCreate(ctx context.Context, mirror *trawlv1alpha1.PortMirror) (admission.Warnings, error) {
	return w.validate(ctx, mirror, nil)
}

// ValidateUpdate validates a change to an existing PortMirror.
func (w *PortMirrorWebhook) ValidateUpdate(ctx context.Context, old, updated *trawlv1alpha1.PortMirror) (admission.Warnings, error) {
	return w.validate(ctx, updated, old)
}

// ValidateDelete records the deletion.
//
// Deleting a PortMirror is how mirroring stops, so it is recorded for the same
// reason deleting a NetworkTap is: it is the action that blinds a sensor. The
// device-side `portmirror.revert` the controller writes afterwards is a
// different event with a different actor, and a delete that never reaches the
// device - an unreachable switch holds the finalizer - produces this record and
// no revert, which is precisely the state an operator needs to be able to find.
func (w *PortMirrorWebhook) ValidateDelete(ctx context.Context, mirror *trawlv1alpha1.PortMirror) (admission.Warnings, error) {
	if err := w.Gate.CheckNamespace(mirror.Namespace); err != nil {
		return nil, err
	}
	return nil, w.commit(ctx)
}

func (w *PortMirrorWebhook) validate(ctx context.Context, mirror, old *trawlv1alpha1.PortMirror) (admission.Warnings, error) {
	if err := w.Gate.CheckNamespace(mirror.Namespace); err != nil {
		return nil, err
	}

	if errs := ValidatePortMirrorSpec(&mirror.Spec); len(errs) > 0 {
		return nil, apierrors.NewInvalid(
			mirror.GroupVersionKind().GroupKind(), mirror.Name, errs)
	}

	if old != nil {
		if errs := validateImmutableMirrorFields(old, mirror); len(errs) > 0 {
			return nil, apierrors.NewInvalid(
				mirror.GroupVersionKind().GroupKind(), mirror.Name, errs)
		}
	}

	return nil, w.commit(ctx)
}

// commit records the mutation before it is admitted (FR-036).
func (w *PortMirrorWebhook) commit(ctx context.Context) error {
	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		// Not a real admission call, so there is nothing to audit.
		return nil
	}
	return w.Gate.CommitMutation(ctx, req, audit.DecisionAllowed, "Accepted")
}

// ValidatePortMirrorSpec applies the semantic rules the schema cannot.
//
// Most of what this re-checks the CRD also enforces, through enums, item
// patterns, MinItems and a CEL rule for the target/source overlap. It is
// repeated here for the reason the other kinds repeat theirs: CEL and structural
// validation run on write, so an object stored before a rule existed, or
// restored straight into etcd from a backup, has never been through them. The
// consequence of letting one past is not a Kubernetes error but a device
// change - a mirror configured from a spec nothing ever checked.
//
// Exported so the reconciler can re-check a stored object before touching
// hardware, as the NetworkTap and CaptureJob reconcilers do.
func ValidatePortMirrorSpec(spec *trawlv1alpha1.PortMirrorSpec) field.ErrorList {
	var errs field.ErrorList
	specPath := field.NewPath("spec")

	if spec.Provider != trawlv1alpha1.MirrorProviderMikroTikRouterOS7 {
		// A provider the binary has no driver for is not an inert typo: it
		// names the vendor whose command set is about to be sent to hardware.
		errs = append(errs, field.NotSupported(specPath.Child("provider"), spec.Provider,
			[]string{string(trawlv1alpha1.MirrorProviderMikroTikRouterOS7)}))
	}

	// LocalObjectReference carries an optional name, so "deviceRef: {}" is a
	// structurally valid reference to nothing. Without a Secret there is no
	// address and no credential, and the only symptom would be a mirror stuck
	// reporting a missing Secret named "".
	if spec.DeviceRef.Name == "" {
		errs = append(errs, field.Required(specPath.Child("deviceRef", "name"),
			"a device Secret name is required; the mirror has no address or credential without it"))
	}

	sourcesPath := specPath.Child("sources")
	if len(spec.Sources) == 0 {
		errs = append(errs, field.Required(sourcesPath,
			"at least one source port is required; a mirror with no sources copies nothing"))
	}
	for i, src := range spec.Sources {
		if src == "" {
			errs = append(errs, field.Required(sourcesPath.Index(i), "a port name is required"))
			continue
		}
		// listType=set makes the API server reject duplicates, so a stored
		// object carrying them predates the marker. Left alone they are not
		// merely redundant: the MikroTik driver resolves each name to a port id
		// and writes it, so a duplicate is a second write to the same port, and
		// Observe returns the device's single copy - which then never matches
		// what was asked for, and a correctly configured mirror reports
		// Degraded forever.
		if slices.Index(spec.Sources, src) != i {
			errs = append(errs, field.Duplicate(sourcesPath.Index(i), truncate(src, 64)))
		}
	}

	targetPath := specPath.Child("target")
	if spec.Target == "" {
		errs = append(errs, field.Required(targetPath,
			"a target port is required; the copies have nowhere to go without it"))
	} else if slices.Contains(spec.Sources, spec.Target) {
		// A port that mirrors itself is a loop the switch will configure
		// without complaint. The CRD's CEL rule says so too; this is the
		// stored-object path.
		errs = append(errs, field.Invalid(targetPath, truncate(spec.Target, 64),
			"target must not also be a source"))
	}

	if spec.Direction != "" && !knownMirrorDirection(spec.Direction) {
		errs = append(errs, field.NotSupported(specPath.Child("direction"), spec.Direction,
			[]string{
				string(trawlv1alpha1.MirrorDirectionBoth),
				string(trawlv1alpha1.MirrorDirectionIngress),
				string(trawlv1alpha1.MirrorDirectionEgress),
			}))
	}

	return errs
}

func knownMirrorDirection(d trawlv1alpha1.MirrorDirection) bool {
	return d == trawlv1alpha1.MirrorDirectionBoth ||
		d == trawlv1alpha1.MirrorDirectionIngress ||
		d == trawlv1alpha1.MirrorDirectionEgress
}

// validateImmutableMirrorFields rejects changes that would orphan a mirror on a
// device nothing in the cluster still refers to.
//
// `provider` and `deviceRef` together name the switch this resource has
// configured. Revert follows the *current* spec: the finalizer resolves
// deviceRef at deletion time and un-configures whatever it points at then. So
// repointing a live PortMirror from switch A to switch B configures B, and the
// eventual delete reverts B, while A goes on copying traffic to a port with
// nothing in the cluster recording that it does. That is the exact leftover the
// finalizer exists to prevent, reachable by an edit rather than a crash, and on
// hardware where no `kubectl get` will ever show it.
//
// Sources, target and direction stay mutable: changing them is reconfiguring
// the same device, which the controller handles by rewriting the mirror it
// already owns.
func validateImmutableMirrorFields(old, updated *trawlv1alpha1.PortMirror) field.ErrorList {
	var errs field.ErrorList
	specPath := field.NewPath("spec")

	if old.Spec.Provider != updated.Spec.Provider {
		errs = append(errs, field.Forbidden(specPath.Child("provider"),
			"provider is immutable; delete this PortMirror so its device is reverted, "+
				"then create one for the new device"))
	}
	if old.Spec.DeviceRef.Name != updated.Spec.DeviceRef.Name {
		errs = append(errs, field.Forbidden(specPath.Child("deviceRef", "name"),
			"deviceRef is immutable; repointing it would leave the previous device mirroring "+
				"with nothing in the cluster recording it. Delete this PortMirror so the device "+
				"is reverted, then create one for the new device"))
	}
	return errs
}
