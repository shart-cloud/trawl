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
	"regexp"
	"slices"

	admissionv1 "k8s.io/api/admission/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/audit"
)

// Bounds the CRD's schema also enforces, re-checked here for the reason the
// other webhooks re-check theirs: CEL runs on write, so an object restored
// straight into etcd or written before a rule existed never passed through it.
const (
	maxMirrorSources = 48
	maxMirrorPortLen = 64
)

// mirrorPortRE matches the device port names the schema accepts. A port name is
// interpolated into a request to switch hardware, so the set of characters that
// can reach a device is closed here as well as in the schema.
var mirrorPortRE = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

// PortMirrorWebhook validates and defaults PortMirror resources.
//
// This kind went without a webhook until well after the others had one, and the
// gap was not visible: a comment in the reconciler asserted that admission
// rejected off-namespace mirrors, so the namespace check there read as defence
// in depth when it was in fact the only gate. Two things were actually missing.
//
// The first is provenance. The controller audits every device write under its
// own workload identity, so the ledger recorded what was done to a switch and
// never who asked for it. For the one resource that reconfigures hardware
// outside the cluster, that is the wrong field to be missing, and it is the one
// thing only admission can supply: the authenticated user exists in the request
// and nowhere in the stored object.
//
// The second is deviceRef immutability, below.
//
// What stays out of here is contention. Whether two mirrors claim one device
// depends on what else is stored at the moment they are compared, and this sees
// one object; a pair created concurrently would both pass. checkDeviceConflict
// settles that at reconcile time, and this does not attempt to duplicate it.
type PortMirrorWebhook struct {
	Gate *Gate
}

// +kubebuilder:webhook:path=/mutate-trawl-cloud-v1alpha1-portmirror,mutating=true,failurePolicy=fail,sideEffects=None,groups=trawl.cloud,resources=portmirrors,verbs=create;update,versions=v1alpha1,name=mportmirror.trawl.cloud,admissionReviewVersions=v1
// +kubebuilder:webhook:path=/validate-trawl-cloud-v1alpha1-portmirror,mutating=false,failurePolicy=fail,sideEffects=None,groups=trawl.cloud,resources=portmirrors,verbs=create;update;delete,versions=v1alpha1,name=vportmirror.trawl.cloud,admissionReviewVersions=v1

// SetupWithManager registers the webhook. failurePolicy is Fail for the same
// reason as the others: an unavailable webhook must not become a bypass of the
// namespace and audit gates.
func (w *PortMirrorWebhook) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &trawlv1alpha1.PortMirror{}).
		WithDefaulter(w).
		WithValidator(w).
		Complete()
}

var (
	_ admission.Defaulter[*trawlv1alpha1.PortMirror] = &PortMirrorWebhook{}
	_ admission.Validator[*trawlv1alpha1.PortMirror] = &PortMirrorWebhook{}
)

// Default records who asked for the mirror.
//
// Stamped on create only, from the API server's user info rather than anything
// the object claims about itself. This is the field the ledger was missing: the
// controller's own records name the controller.
func (w *PortMirrorWebhook) Default(ctx context.Context, m *trawlv1alpha1.PortMirror) error {
	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		return nil
	}
	if req.Operation == admissionv1.Create && m.Annotations[trawlv1alpha1.AnnotationRequester] == "" {
		if m.Annotations == nil {
			m.Annotations = map[string]string{}
		}
		m.Annotations[trawlv1alpha1.AnnotationRequester] = req.UserInfo.Username
	}
	return nil
}

// ValidateCreate validates a new PortMirror and records the request.
func (w *PortMirrorWebhook) ValidateCreate(ctx context.Context, m *trawlv1alpha1.PortMirror) (admission.Warnings, error) {
	if err := w.Gate.CheckNamespace(m.Namespace); err != nil {
		return nil, err
	}
	if errs := ValidatePortMirrorSpec(&m.Spec); len(errs) > 0 {
		return nil, apierrors.NewInvalid(m.GroupVersionKind().GroupKind(), m.Name, errs)
	}

	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		// Not a real admission call; nothing to authorize or audit.
		return nil, nil
	}
	return nil, w.Gate.CommitMutationAs(ctx, req,
		audit.ActionPortMirrorCreate, audit.DecisionAllowed, "Accepted")
}

// ValidateUpdate revalidates the spec and freezes the two fields that must not
// move under a live mirror.
func (w *PortMirrorWebhook) ValidateUpdate(
	ctx context.Context, old, updated *trawlv1alpha1.PortMirror,
) (admission.Warnings, error) {
	if err := w.Gate.CheckNamespace(updated.Namespace); err != nil {
		return nil, err
	}
	if errs := ValidatePortMirrorSpec(&updated.Spec); len(errs) > 0 {
		return nil, apierrors.NewInvalid(updated.GroupVersionKind().GroupKind(), updated.Name, errs)
	}

	var errs field.ErrorList

	// deviceRef is immutable, and this is the rule that matters most here.
	//
	// The revert finalizer un-configures the device on deletion, and deletion
	// is the only thing that triggers it. Repointing deviceRef at another
	// Secret therefore does not revert the first device: the controller
	// configures the new one and walks away from the old, which keeps mirroring
	// to a port nobody is watching, with no resource left naming it and nothing
	// that will ever clean it up. The mirror outlives every record of why it
	// exists.
	//
	// Nothing detects that afterwards, because Trawl only looks at devices it
	// is told about. A new mirror is the honest way to move to another device:
	// deleting the old one reverts it.
	if old.Spec.DeviceRef.Name != updated.Spec.DeviceRef.Name {
		errs = append(errs, field.Forbidden(field.NewPath("spec", "deviceRef"),
			"deviceRef is immutable; the revert finalizer runs only on deletion, so repointing "+
				"this at another device would leave the current one mirroring with nothing to "+
				"un-configure it. Delete this PortMirror and create one for the new device."))
	}

	// Provider is immutable for a narrower version of the same reason: it
	// selects the driver that would have to speak to the existing device in
	// order to revert it.
	if old.Spec.Provider != updated.Spec.Provider {
		errs = append(errs, field.Forbidden(field.NewPath("spec", "provider"),
			"provider is immutable; the driver that configured a device is the one that must revert it"))
	}

	// The requester annotation is provenance, stamped once on create. A later
	// change would misattribute the mirror to whoever edited it last.
	if old.Annotations[trawlv1alpha1.AnnotationRequester] != updated.Annotations[trawlv1alpha1.AnnotationRequester] {
		errs = append(errs, field.Forbidden(
			field.NewPath("metadata", "annotations", trawlv1alpha1.AnnotationRequester),
			"the requester annotation is set on create and cannot be changed"))
	}

	if len(errs) > 0 {
		return nil, apierrors.NewInvalid(updated.GroupVersionKind().GroupKind(), updated.Name, errs)
	}

	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		return nil, nil
	}
	return nil, w.Gate.CommitMutationAs(ctx, req,
		audit.ActionPortMirrorUpdate, audit.DecisionAllowed, "Accepted")
}

// ValidateDelete records the deletion.
//
// Deletion is how a mirror is meant to be removed, and it is the only thing
// that reverts the device. The record is committed before the delete is
// admitted, so the intent to stop mirroring is durable even if the revert then
// fails against an unreachable switch - which is the case where the ledger and
// the hardware disagree and someone has to be told which.
func (w *PortMirrorWebhook) ValidateDelete(
	ctx context.Context, m *trawlv1alpha1.PortMirror,
) (admission.Warnings, error) {
	if err := w.Gate.CheckNamespace(m.Namespace); err != nil {
		return nil, err
	}
	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		return nil, nil
	}
	return nil, w.Gate.CommitMutationAs(ctx, req,
		audit.ActionPortMirrorDelete, audit.DecisionAllowed, "Accepted")
}

// ValidatePortMirrorSpec checks what the schema also enforces.
//
// Exported so the reconciler can re-check a stored object, as the other three
// kinds do. Port names are echoed in errors: they are device port identifiers
// such as ether7, already present in the spec the caller just submitted, and
// naming the offending one is the difference between a usable message and a
// guess. The credential they sit beside is in a Secret and never comes near
// this function.
func ValidatePortMirrorSpec(spec *trawlv1alpha1.PortMirrorSpec) field.ErrorList {
	var errs field.ErrorList
	specPath := field.NewPath("spec")

	if spec.Provider != trawlv1alpha1.MirrorProviderMikroTikRouterOS7 {
		errs = append(errs, field.NotSupported(specPath.Child("provider"), spec.Provider,
			[]string{string(trawlv1alpha1.MirrorProviderMikroTikRouterOS7)}))
	}

	if spec.DeviceRef.Name == "" {
		errs = append(errs, field.Required(specPath.Child("deviceRef", "name"),
			"a Secret holding the device address and credentials is required"))
	}

	switch {
	case len(spec.Sources) == 0:
		errs = append(errs, field.Required(specPath.Child("sources"), "at least one source port is required"))
	case len(spec.Sources) > maxMirrorSources:
		errs = append(errs, field.TooMany(specPath.Child("sources"), len(spec.Sources), maxMirrorSources))
	}

	seen := make(map[string]struct{}, len(spec.Sources))
	for i, src := range spec.Sources {
		errs = append(errs, validateMirrorPort(specPath.Child("sources").Index(i), src)...)
		if _, dup := seen[src]; dup {
			errs = append(errs, field.Duplicate(specPath.Child("sources").Index(i), src))
		}
		seen[src] = struct{}{}
	}

	errs = append(errs, validateMirrorPort(specPath.Child("target"), spec.Target)...)

	// The CEL rule on the type says the same thing. It is repeated because a
	// mirror whose target is also a source is a loop the switch will configure
	// without complaint, and this function is what the reconciler can call on
	// an object that never met CEL.
	if spec.Target != "" && slices.Contains(spec.Sources, spec.Target) {
		errs = append(errs, field.Invalid(specPath.Child("target"), spec.Target,
			"target must not also be a source"))
	}

	switch spec.Direction {
	case "", trawlv1alpha1.MirrorDirectionBoth,
		trawlv1alpha1.MirrorDirectionIngress, trawlv1alpha1.MirrorDirectionEgress:
	default:
		errs = append(errs, field.NotSupported(specPath.Child("direction"), spec.Direction,
			[]string{
				string(trawlv1alpha1.MirrorDirectionBoth),
				string(trawlv1alpha1.MirrorDirectionIngress),
				string(trawlv1alpha1.MirrorDirectionEgress),
			}))
	}

	return errs
}

func validateMirrorPort(path *field.Path, port string) field.ErrorList {
	switch {
	case port == "":
		return field.ErrorList{field.Required(path, "a device port name is required")}
	case len(port) > maxMirrorPortLen:
		return field.ErrorList{field.TooLongCharacters(path, port, maxMirrorPortLen)}
	case !mirrorPortRE.MatchString(port):
		return field.ErrorList{field.Invalid(path, port,
			"must contain only letters, digits, and the characters . _ / -")}
	}
	return nil
}
