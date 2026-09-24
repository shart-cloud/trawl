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

package integration

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/audit"
	"trawl.cloud/trawl/internal/controller"
	"trawl.cloud/trawl/internal/fabric"
	"trawl.cloud/trawl/internal/status"
)

// deviceSecretName is the credential every spec here points its PortMirror at.
const deviceSecretName = "switch-credential"

// fakeDevice stands in for a switch. It records what it was asked to do and can
// be told to fail, drift, or lie about what it holds.
type fakeDevice struct {
	state        fabric.State
	configures   int
	reverts      int
	observes     int
	configureErr error
	partialState *fabric.State
	observeErr   error
	revertErr    error

	// applied is what Configure was last given, so a test can tell "wrote the
	// right thing" from "wrote anything at all".
	applied fabric.Mirror
}

func (f *fakeDevice) Name() string { return "MikroTikRouterOS7" }

func (f *fakeDevice) Observe(context.Context, fabric.Device) (fabric.State, error) {
	f.observes++
	if f.observeErr != nil {
		return fabric.State{}, f.observeErr
	}
	return f.state, nil
}

func (f *fakeDevice) Configure(_ context.Context, _ fabric.Device, m fabric.Mirror) error {
	f.configures++
	if f.configureErr != nil {
		if f.partialState != nil {
			f.state = *f.partialState
		}
		return f.configureErr
	}
	f.applied = m
	directions := make(map[string]fabric.Direction, len(m.Sources))
	for _, source := range m.Sources {
		directions[source] = m.Direction
	}
	f.state = fabric.State{
		Sources: m.Sources, Target: m.Target,
		Direction: m.Direction, SourceDirections: directions, Identity: "FakeSwitch 1.0",
	}
	return nil
}

func (f *fakeDevice) Revert(context.Context, fabric.Device) error {
	f.reverts++
	if f.revertErr != nil {
		return f.revertErr
	}
	f.state = fabric.State{Identity: "FakeSwitch 1.0"}
	return nil
}

// mirrorHarness wires a reconciler to a fake device and a recording committer.
type mirrorHarness struct {
	r      *controller.PortMirrorReconciler
	device *fakeDevice
	audit  *fakeCommitter
}

func mirrorReconcilerFor(t *testing.T, ns string) *mirrorHarness {
	t.Helper()
	dev := &fakeDevice{state: fabric.State{Identity: "FakeSwitch 1.0"}}
	reg, err := fabric.NewRegistry(dev)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	committer := &fakeCommitter{}
	return &mirrorHarness{
		device: dev,
		audit:  committer,
		r: &controller.PortMirrorReconciler{
			Client:          Client(),
			Providers:       reg,
			Audit:           committer,
			SystemNamespace: ns,
			Actor: func() audit.Actor {
				return audit.Actor{Username: "system:serviceaccount:trawl-system:trawl-controller-manager"}
			},
		},
	}
}

func deviceSecret(t *testing.T, ns string, data map[string]string) {
	t.Helper()
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: deviceSecretName, Namespace: ns},
		StringData: data,
	}
	if err := Client().Create(context.Background(), secret); err != nil {
		t.Fatalf("creating the device Secret: %v", err)
	}
}

func newMirror(t *testing.T, ns, name string) *trawlv1alpha1.PortMirror {
	t.Helper()
	m := &trawlv1alpha1.PortMirror{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: trawlv1alpha1.PortMirrorSpec{
			Provider:  trawlv1alpha1.MirrorProviderMikroTikRouterOS7,
			DeviceRef: corev1.LocalObjectReference{Name: deviceSecretName},
			Sources:   []string{"ether1", "ether2"},
			Target:    "ether24",
			Direction: trawlv1alpha1.MirrorDirectionBoth,
		},
	}
	if err := Client().Create(context.Background(), m); err != nil {
		t.Fatalf("creating the PortMirror: %v", err)
	}
	return m
}

func reconcileMirror(t *testing.T, r *controller.PortMirrorReconciler, m *trawlv1alpha1.PortMirror) {
	t.Helper()
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: client.ObjectKeyFromObject(m),
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
}

func reloadMirror(t *testing.T, m *trawlv1alpha1.PortMirror) *trawlv1alpha1.PortMirror {
	t.Helper()
	var out trawlv1alpha1.PortMirror
	if err := Client().Get(context.Background(), client.ObjectKeyFromObject(m), &out); err != nil {
		t.Fatalf("reloading the PortMirror: %v", err)
	}
	return &out
}

func TestAPortMirrorConfiguresTheDeviceAndReportsActive(t *testing.T) {
	ns := NewNamespace(t)
	h := mirrorReconcilerFor(t, ns)
	deviceSecret(t, ns, map[string]string{
		"address": "192.0.2.10", "username": "trawl", "password": "secret",
	})
	m := newMirror(t, ns, "lab-mirror")

	reconcileMirror(t, h.r, m)

	if h.device.configures != 1 {
		t.Errorf("Configure called %d times, want 1", h.device.configures)
	}
	if h.device.applied.Target != "ether24" {
		t.Errorf("applied target = %q, want ether24", h.device.applied.Target)
	}

	after := reloadMirror(t, m)
	if after.Status.Phase != trawlv1alpha1.PortMirrorActive {
		t.Errorf("phase = %q, want Active", after.Status.Phase)
	}
	if after.Status.ObservedTarget != "ether24" {
		t.Errorf("observedTarget = %q; status should record what the device said",
			after.Status.ObservedTarget)
	}
	for _, source := range m.Spec.Sources {
		if got := after.Status.ObservedDirections[source]; got != trawlv1alpha1.MirrorDirectionBoth {
			t.Errorf("observedDirections[%q] = %q, want Both", source, got)
		}
	}
	if after.Status.DeviceIdentity == "" {
		t.Error("status records no device identity, so an incident cannot tell which device this was")
	}
	if after.Status.LastVerifiedTime == nil {
		t.Error("status records no verification time")
	}
}

func TestAMirrorThatIsAlreadyCorrectIsNotRewritten(t *testing.T) {
	// A controller resyncs on a timer because nothing watches a switch. If it
	// rewrote every time, it would produce a configuration-change event on the
	// device every five minutes forever - filling somebody else's audit log
	// with our reconcile loop.
	ns := NewNamespace(t)
	h := mirrorReconcilerFor(t, ns)
	deviceSecret(t, ns, map[string]string{
		"address": "192.0.2.10", "username": "trawl", "password": "secret",
	})
	m := newMirror(t, ns, "steady")

	reconcileMirror(t, h.r, m)
	first := h.device.configures
	reconcileMirror(t, h.r, m)

	if h.device.configures != first {
		t.Errorf("Configure was called again on an already-correct device (%d -> %d)",
			first, h.device.configures)
	}
}

func TestADriftedDeviceIsReportedDegradedWithWhatItActuallyHas(t *testing.T) {
	// Somebody logged into the switch. The resource must say so, and must say
	// what they changed it to - a bare Degraded sends an operator to the
	// device to find out what this field could have told them.
	ns := NewNamespace(t)
	h := mirrorReconcilerFor(t, ns)
	deviceSecret(t, ns, map[string]string{
		"address": "192.0.2.10", "username": "trawl", "password": "secret",
	})
	m := newMirror(t, ns, "drifted")
	reconcileMirror(t, h.r, m)

	// The device now reports something else, and keeps reporting it: this is a
	// hand edit, not a transient.
	h.device.state = fabric.State{
		Sources: []string{"ether7"}, Target: "sfp1", Identity: "FakeSwitch 1.0",
	}
	h.device.configureErr = errors.New("the device refuses further changes")

	reconcileMirror(t, h.r, m)

	after := reloadMirror(t, m)
	if after.Status.Phase == trawlv1alpha1.PortMirrorActive {
		t.Error("a device reporting a different mirror was still reported Active")
	}
	found := false
	for _, c := range after.Status.Conditions {
		if c.Type == status.TypeMirrorConfigured && c.Status == metav1.ConditionFalse {
			found = true
			if !contains(c.Message, "sfp1") {
				t.Errorf("the condition does not say what the device actually has: %q", c.Message)
			}
		}
	}
	if !found {
		t.Error("no MirrorConfigured=False condition on a drifted device")
	}
}

func TestAFailedMirrorWriteReportsThePartialDeviceState(t *testing.T) {
	ns := NewNamespace(t)
	h := mirrorReconcilerFor(t, ns)
	deviceSecret(t, ns, map[string]string{
		"address": "192.0.2.10", "username": "trawl", "password": "secret",
	})
	m := newMirror(t, ns, "partial")
	h.device.configureErr = errors.New("second port write failed")
	h.device.partialState = &fabric.State{
		Sources: []string{"ether1"}, Target: "ether24",
		Direction:        fabric.DirectionIngress,
		SourceDirections: map[string]fabric.Direction{"ether1": fabric.DirectionIngress},
		Identity:         "FakeSwitch 1.0",
	}

	reconcileMirror(t, h.r, m)

	after := reloadMirror(t, m)
	if after.Status.Phase != trawlv1alpha1.PortMirrorError {
		t.Errorf("phase = %q, want Error", after.Status.Phase)
	}
	if got := after.Status.ObservedDirections["ether1"]; got != trawlv1alpha1.MirrorDirectionIngress {
		t.Errorf("observedDirections[ether1] = %q, want Ingress", got)
	}
	if len(after.Status.ObservedSources) != 1 || after.Status.ObservedSources[0] != "ether1" {
		t.Errorf("observedSources = %v, want [ether1]", after.Status.ObservedSources)
	}
	if h.device.observes < 2 {
		t.Error("failed write was not followed by a readback")
	}
}
func TestAnUnreachableDeviceIsNeverReportedActive(t *testing.T) {
	// The whole reason Observe is mandatory. A controller that trusted its own
	// writes would report coverage that stopped existing, and the captures
	// taken under it would be empty for a reason nobody could see.
	ns := NewNamespace(t)
	h := mirrorReconcilerFor(t, ns)
	deviceSecret(t, ns, map[string]string{
		"address": "192.0.2.10", "username": "trawl", "password": "secret",
	})
	m := newMirror(t, ns, "unreachable")
	h.device.observeErr = errors.New("dial tcp 192.0.2.10:443: connect: no route to host")

	reconcileMirror(t, h.r, m)

	after := reloadMirror(t, m)
	if after.Status.Phase == trawlv1alpha1.PortMirrorActive {
		t.Error("a device that could not be reached was reported Active")
	}
	if h.device.configures != 0 {
		t.Error("it tried to configure a device it could not read first")
	}
}

func TestAMissingDeviceSecretSaysWhichOne(t *testing.T) {
	ns := NewNamespace(t)
	h := mirrorReconcilerFor(t, ns)
	m := newMirror(t, ns, "no-secret") // no Secret created

	reconcileMirror(t, h.r, m)

	after := reloadMirror(t, m)
	if after.Status.Phase != trawlv1alpha1.PortMirrorError {
		t.Errorf("phase = %q, want Error", after.Status.Phase)
	}
	if h.device.configures != 0 {
		t.Error("it contacted a device without a credential")
	}
}

func TestEveryDeviceChangeIsAudited(t *testing.T) {
	// Trawl changing hardware it does not own is the most physically
	// consequential thing it does. An intent and an outcome, like every other
	// fallible action in the system.
	ns := NewNamespace(t)
	h := mirrorReconcilerFor(t, ns)
	deviceSecret(t, ns, map[string]string{
		"address": "192.0.2.10", "username": "trawl", "password": "secret",
	})
	m := newMirror(t, ns, "audited")

	reconcileMirror(t, h.r, m)

	var allowed, succeeded int
	for _, rec := range h.audit.records {
		if rec.Action != audit.ActionPortMirrorConfigure {
			continue
		}
		switch rec.Decision {
		case audit.DecisionAllowed:
			allowed++
		case audit.DecisionSucceeded:
			succeeded++
		}
		if rec.Resource.Kind != "PortMirror" || rec.Resource.Name != "audited" {
			t.Errorf("the record does not name the resource: %+v", rec.Resource)
		}
	}
	if allowed != 1 || succeeded != 1 {
		t.Errorf("configure audited allowed=%d succeeded=%d, want 1 and 1", allowed, succeeded)
	}
}

func TestDeletingAMirrorRevertsTheDeviceBeforeReleasingTheResource(t *testing.T) {
	ns := NewNamespace(t)
	h := mirrorReconcilerFor(t, ns)
	deviceSecret(t, ns, map[string]string{
		"address": "192.0.2.10", "username": "trawl", "password": "secret",
	})
	m := newMirror(t, ns, "reverted")
	reconcileMirror(t, h.r, m)

	if err := Client().Delete(context.Background(), m); err != nil {
		t.Fatalf("deleting: %v", err)
	}
	reconcileMirror(t, h.r, m)

	if h.device.reverts != 1 {
		t.Errorf("Revert called %d times, want 1", h.device.reverts)
	}
	var gone trawlv1alpha1.PortMirror
	err := Client().Get(context.Background(), client.ObjectKeyFromObject(m), &gone)
	if err == nil {
		t.Errorf("the PortMirror still exists after its finalizer ran (finalizers=%v)", gone.Finalizers)
	}
}

func TestAMirrorWhoseDeviceCannotBeRevertedIsKept(t *testing.T) {
	// The sharp case. Releasing the finalizer here would delete the only
	// record that this switch is still mirroring, leaving traffic copied to a
	// port with nothing in the cluster explaining why - and an operator with no
	// way to find it short of logging into the device.
	ns := NewNamespace(t)
	h := mirrorReconcilerFor(t, ns)
	deviceSecret(t, ns, map[string]string{
		"address": "192.0.2.10", "username": "trawl", "password": "secret",
	})
	m := newMirror(t, ns, "stuck")
	reconcileMirror(t, h.r, m)

	h.device.revertErr = errors.New("the device stopped answering")
	if err := Client().Delete(context.Background(), m); err != nil {
		t.Fatalf("deleting: %v", err)
	}
	reconcileMirror(t, h.r, m)

	after := reloadMirror(t, m) // must still exist
	if after.Status.Phase != trawlv1alpha1.PortMirrorError {
		t.Errorf("phase = %q, want Error while the device is still mirroring", after.Status.Phase)
	}

	// And it recovers once the device answers again.
	h.device.revertErr = nil
	reconcileMirror(t, h.r, m)
	var gone trawlv1alpha1.PortMirror
	if err := Client().Get(context.Background(), client.ObjectKeyFromObject(m), &gone); err == nil {
		t.Error("the PortMirror was not released once the device could be reverted")
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) &&
		(haystack == needle || len(needle) == 0 ||
			indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

func TestAnOffNamespacePortMirrorTouchesNoDeviceAndSaysWhy(t *testing.T) {
	// Admission refuses these now, so one that exists reached etcd another way -
	// a restore, or a webhook that was unavailable before this one existed. The
	// controller is the second line, and what it reports matters: this said
	// Accepted, the reason an *accepted* resource carries, so the status claimed
	// the opposite of what had happened.
	ns := NewNamespace(t)
	elsewhere := NewNamespace(t)
	h := mirrorReconcilerFor(t, ns)
	deviceSecret(t, elsewhere, map[string]string{
		"address": "192.0.2.10", "username": "trawl", "password": "secret",
	})
	m := newMirror(t, elsewhere, "off-namespace")

	reconcileMirror(t, h.r, m)

	if h.device.configures != 0 || h.device.observes != 0 {
		t.Errorf("an off-namespace mirror reached the device: %d configures, %d observes",
			h.device.configures, h.device.observes)
	}

	after := reloadMirror(t, m)
	if after.Status.Phase != trawlv1alpha1.PortMirrorError {
		t.Errorf("phase = %q, want Error", after.Status.Phase)
	}
	cond := findCondition(after.Status.Conditions, status.TypeMirrorConfigured)
	if cond == nil {
		t.Fatalf("no MirrorConfigured condition; conditions = %v", after.Status.Conditions)
	}
	if cond.Reason != status.ReasonWrongNamespace {
		t.Errorf("reason = %q, want %q", cond.Reason, status.ReasonWrongNamespace)
	}
	// Nothing was asked of the device, so claiming it is unreachable would send
	// an operator to the switch for a problem in the resource.
	if reachable := findCondition(after.Status.Conditions, status.TypeDeviceReachable); reachable != nil &&
		reachable.Status == metav1.ConditionFalse {
		t.Error("it reported DeviceReachable=False about a device it never contacted")
	}
}

func TestAnInvalidStoredSpecIsRefusedBeforeTheDeviceIsTouched(t *testing.T) {
	// A spec that never passed admission - restored from a backup predating a
	// rule - must not become a configuration change on a switch. deviceRef's
	// name is optional in LocalObjectReference, so "deviceRef: {}" satisfies the
	// structural schema and refers to nothing.
	ns := NewNamespace(t)
	h := mirrorReconcilerFor(t, ns)
	deviceSecret(t, ns, map[string]string{
		"address": "192.0.2.10", "username": "trawl", "password": "secret",
	})

	m := &trawlv1alpha1.PortMirror{
		ObjectMeta: metav1.ObjectMeta{Name: "nameless-device", Namespace: ns},
		Spec: trawlv1alpha1.PortMirrorSpec{
			Provider:  trawlv1alpha1.MirrorProviderMikroTikRouterOS7,
			DeviceRef: corev1.LocalObjectReference{},
			Sources:   []string{"ether1"},
			Target:    "ether24",
			Direction: trawlv1alpha1.MirrorDirectionBoth,
		},
	}
	if err := Client().Create(context.Background(), m); err != nil {
		t.Fatalf("creating the PortMirror: %v", err)
	}

	reconcileMirror(t, h.r, m)

	if h.device.configures != 0 || h.device.observes != 0 {
		t.Errorf("an unvalidated spec reached the device: %d configures, %d observes",
			h.device.configures, h.device.observes)
	}

	after := reloadMirror(t, m)
	cond := findCondition(after.Status.Conditions, status.TypeMirrorConfigured)
	if cond == nil {
		t.Fatalf("no MirrorConfigured condition; conditions = %v", after.Status.Conditions)
	}
	if cond.Reason != status.ReasonInvalidSpec {
		t.Errorf("reason = %q, want %q", cond.Reason, status.ReasonInvalidSpec)
	}
	if !strings.Contains(cond.Message, "deviceRef") {
		t.Errorf("message does not name the field: %q", cond.Message)
	}
}
