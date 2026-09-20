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

package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/fabric"
	"trawl.cloud/trawl/internal/status"
)

// Two PortMirrors naming one deviceRef describe one switch and disagree about
// it. A RouterOS device has a single global mirror-target, so without a rule
// the two rewrite each other indefinitely - a device log full of configuration
// changes and a write-once ledger full of records that cannot be pruned.
//
// These tests pin the rule: the older claim keeps the device, the younger one
// says so in status and touches nothing.

const (
	contendedDevice    = "lab-switch"
	testDeviceUsername = "trawl"
)

// countingProvider records whether the controller spoke to the device at all.
//
// The assertion that matters most in this file is a negative one - a contended
// mirror must make no device calls - and a provider that counts is the only way
// to state it directly rather than inferring it from status.
type countingProvider struct {
	observes   int
	configures int
	reverts    int
	state      fabric.State
}

func (p *countingProvider) Name() string {
	return string(trawlv1alpha1.MirrorProviderMikroTikRouterOS7)
}

func (p *countingProvider) Observe(context.Context, fabric.Device) (fabric.State, error) {
	p.observes++
	return p.state, nil
}

func (p *countingProvider) Configure(_ context.Context, _ fabric.Device, m fabric.Mirror) error {
	p.configures++
	p.state = fabric.State{Sources: m.Sources, Target: m.Target, Identity: "CRS310"}
	return nil
}

func (p *countingProvider) Revert(context.Context, fabric.Device) error {
	p.reverts++
	p.state = fabric.State{}
	return nil
}

func (p *countingProvider) calls() int { return p.observes + p.configures + p.reverts }

// mirrorAt builds a PortMirror created at the given time, naming the contended
// device unless another is given.
func mirrorAt(name string, created time.Time, device string) *trawlv1alpha1.PortMirror {
	if device == "" {
		device = contendedDevice
	}
	return &trawlv1alpha1.PortMirror{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         testNamespace,
			UID:               types.UID("uid-" + name),
			CreationTimestamp: metav1.NewTime(created),
		},
		Spec: trawlv1alpha1.PortMirrorSpec{
			Provider:  trawlv1alpha1.MirrorProviderMikroTikRouterOS7,
			DeviceRef: corev1.LocalObjectReference{Name: device},
			Sources:   []string{"ether1"},
			Target:    "ether24",
			Direction: trawlv1alpha1.MirrorDirectionBoth,
		},
	}
}

// deviceSecret is the credential the device() lookup needs to get as far as
// talking to hardware, so that a test asserting no device calls is asserting
// the conflict rule stopped it rather than a missing Secret.
func deviceSecret(name string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
		Data: map[string][]byte{
			"address":            []byte("192.0.2.10"),
			"username":           []byte(testDeviceUsername),
			"password":           []byte("secret"),
			"insecureSkipVerify": []byte("true"),
		},
	}
}

type mirrorFixture struct {
	reconciler *PortMirrorReconciler
	client     client.Client
	provider   *countingProvider
	ledger     *recordingCommitter
}

func newMirrorFixture(t *testing.T, objs ...client.Object) *mirrorFixture {
	t.Helper()
	c := fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithObjects(objs...).
		WithStatusSubresource(&trawlv1alpha1.PortMirror{}).
		Build()

	provider := &countingProvider{}
	registry, err := fabric.NewRegistry(provider)
	if err != nil {
		t.Fatalf("building provider registry: %v", err)
	}
	ledger := &recordingCommitter{}

	return &mirrorFixture{
		client:   c,
		provider: provider,
		ledger:   ledger,
		reconciler: &PortMirrorReconciler{
			Client:          c,
			Providers:       registry,
			Audit:           ledger,
			SystemNamespace: testNamespace,
		},
	}
}

func TestDeviceCredentialUsesTheUncachedAPIReader(t *testing.T) {
	// The manager's ordinary client caches each kind it reads. Using it for a
	// named Secret therefore starts a cluster-wide Secret list/watch and turns
	// one get permission into three. Keep the Secret out of Client and only in
	// APIReader so this fails if device() ever returns to the cached path.
	cached := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()
	direct := fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithObjects(deviceSecret(contendedDevice)).
		Build()
	reconciler := &PortMirrorReconciler{Client: cached, APIReader: direct}

	device, err := reconciler.device(context.Background(), mirrorAt("mirror", time.Now(), ""))
	if err != nil {
		t.Fatalf("resolving device credential: %v", err)
	}
	if device.Address != "192.0.2.10" || device.Username != testDeviceUsername || device.Password != "secret" {
		t.Fatalf("device = %+v, want the credential read through APIReader", device)
	}
}

func (f *mirrorFixture) reconcile(t *testing.T, name string) {
	t.Helper()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: testNamespace, Name: name}}
	if _, err := f.reconciler.Reconcile(context.Background(), req); err != nil {
		t.Fatalf("reconciling %s: %v", name, err)
	}
}

func (f *mirrorFixture) read(t *testing.T, name string) trawlv1alpha1.PortMirror {
	t.Helper()
	var m trawlv1alpha1.PortMirror
	key := types.NamespacedName{Namespace: testNamespace, Name: name}
	if err := f.client.Get(context.Background(), key, &m); err != nil {
		t.Fatalf("reading PortMirror %s: %v", name, err)
	}
	return m
}

func condition(t *testing.T, m trawlv1alpha1.PortMirror, want string) metav1.Condition {
	t.Helper()
	for _, c := range m.Status.Conditions {
		if c.Type == want {
			return c
		}
	}
	t.Fatalf("PortMirror %s has no %s condition; has %+v", m.Name, want, m.Status.Conditions)
	return metav1.Condition{}
}

func TestYoungerMirrorYieldsTheContendedDevice(t *testing.T) {
	older := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	f := newMirrorFixture(t,
		deviceSecret(contendedDevice),
		mirrorAt("incumbent", older, ""),
		mirrorAt("challenger", older.Add(time.Hour), ""),
	)

	f.reconcile(t, "challenger")

	challenger := f.read(t, "challenger")
	if challenger.Status.Phase != trawlv1alpha1.PortMirrorError {
		t.Errorf("challenger phase = %q, want %q", challenger.Status.Phase, trawlv1alpha1.PortMirrorError)
	}
	c := condition(t, challenger, status.TypeMirrorConfigured)
	if c.Reason != status.ReasonDeviceConflict {
		t.Errorf("challenger reason = %q, want %q", c.Reason, status.ReasonDeviceConflict)
	}
	if c.Status != metav1.ConditionFalse {
		t.Errorf("challenger MirrorConfigured = %q, want False", c.Status)
	}
	// The message must name the incumbent. An operator reading only "conflict"
	// has to go looking for the other resource themselves.
	if !strings.Contains(c.Message, "incumbent") {
		t.Errorf("challenger message does not name the incumbent: %q", c.Message)
	}
}

func TestContendedMirrorMakesNoDeviceCalls(t *testing.T) {
	// The whole point. Flapping is not merely untidy: each lap writes to the
	// device log and to a ledger that cannot be pruned.
	older := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	f := newMirrorFixture(t,
		deviceSecret(contendedDevice),
		mirrorAt("incumbent", older, ""),
		mirrorAt("challenger", older.Add(time.Hour), ""),
	)

	for range 5 {
		f.reconcile(t, "challenger")
	}

	if f.provider.calls() != 0 {
		t.Errorf("contended mirror made %d device calls (observe=%d configure=%d revert=%d), want 0",
			f.provider.calls(), f.provider.observes, f.provider.configures, f.provider.reverts)
	}
	// And nothing reached the ledger. The ledger is write-once, so records a
	// flapping reconcile produced could never be removed again.
	if n := len(f.ledger.records); n != 0 {
		t.Errorf("contended mirror wrote %d ledger records, want 0", n)
	}
}

func TestContendedMirrorTakesNoFinalizer(t *testing.T) {
	// A finalizer exists to revert the device on deletion. On a resource that
	// never configured anything it would, on deletion, revert the mirror the
	// incumbent owns - turning a harmless cleanup into an outage.
	older := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	f := newMirrorFixture(t,
		deviceSecret(contendedDevice),
		mirrorAt("incumbent", older, ""),
		mirrorAt("challenger", older.Add(time.Hour), ""),
	)

	f.reconcile(t, "challenger")

	challenger := f.read(t, "challenger")
	for _, fin := range challenger.Finalizers {
		if fin == portMirrorFinalizer {
			t.Fatal("contended mirror took the revert finalizer; deleting it would tear down the incumbent's mirror")
		}
	}
}

func TestIncumbentKeepsTheDevice(t *testing.T) {
	older := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	f := newMirrorFixture(t,
		deviceSecret(contendedDevice),
		mirrorAt("incumbent", older, ""),
		mirrorAt("challenger", older.Add(time.Hour), ""),
	)

	f.reconcile(t, "incumbent")

	incumbent := f.read(t, "incumbent")
	if incumbent.Status.Phase != trawlv1alpha1.PortMirrorActive {
		t.Errorf("incumbent phase = %q, want %q", incumbent.Status.Phase, trawlv1alpha1.PortMirrorActive)
	}
	if f.provider.configures != 1 {
		t.Errorf("incumbent configured the device %d times, want 1", f.provider.configures)
	}
}

func TestContentionIsSettledTheSameWayFromBothSides(t *testing.T) {
	// Each resource reconciles independently, so the two must reach the same
	// verdict about which of them yields. A rule they could read differently
	// would leave the device unconfigured or claimed twice.
	older := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	f := newMirrorFixture(t,
		deviceSecret(contendedDevice),
		mirrorAt("incumbent", older, ""),
		mirrorAt("challenger", older.Add(time.Hour), ""),
	)

	f.reconcile(t, "challenger")
	f.reconcile(t, "incumbent")
	f.reconcile(t, "challenger")

	if got := f.read(t, "incumbent").Status.Phase; got != trawlv1alpha1.PortMirrorActive {
		t.Errorf("incumbent phase = %q, want Active", got)
	}
	if got := f.read(t, "challenger").Status.Phase; got != trawlv1alpha1.PortMirrorError {
		t.Errorf("challenger phase = %q, want Error", got)
	}
	if f.provider.configures != 1 {
		t.Errorf("device configured %d times across interleaved reconciles, want 1", f.provider.configures)
	}
}

func TestSameInstantContentionIsBrokenByUID(t *testing.T) {
	// Two resources created in the same instant still have to agree. Without a
	// tie-break both would consider the other younger and both would yield,
	// leaving the device configured by nobody.
	same := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	f := newMirrorFixture(t,
		deviceSecret(contendedDevice),
		mirrorAt("alpha", same, ""),
		mirrorAt("beta", same, ""),
	)

	f.reconcile(t, "alpha")
	f.reconcile(t, "beta")

	alpha := f.read(t, "alpha")
	beta := f.read(t, "beta")
	active := 0
	for _, m := range []trawlv1alpha1.PortMirror{alpha, beta} {
		if m.Status.Phase == trawlv1alpha1.PortMirrorActive {
			active++
		}
	}
	if active != 1 {
		t.Errorf("%d of 2 same-instant mirrors are Active, want exactly 1 (alpha=%q beta=%q)",
			active, alpha.Status.Phase, beta.Status.Phase)
	}
	// uid-alpha sorts before uid-beta, so alpha is the one that holds it.
	if alpha.Status.Phase != trawlv1alpha1.PortMirrorActive {
		t.Errorf("expected the lower UID to hold the device, got alpha=%q", alpha.Status.Phase)
	}
}

func TestDifferentDevicesDoNotContend(t *testing.T) {
	older := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	f := newMirrorFixture(t,
		deviceSecret(contendedDevice),
		deviceSecret("other-switch"),
		mirrorAt("first", older, ""),
		mirrorAt("second", older.Add(time.Hour), "other-switch"),
	)

	f.reconcile(t, "second")

	second := f.read(t, "second")
	if second.Status.Phase != trawlv1alpha1.PortMirrorActive {
		t.Errorf("mirror on a different device = %q, want Active; two devices do not contend",
			second.Status.Phase)
	}
}

func TestDeletedIncumbentReleasesTheDevice(t *testing.T) {
	// Contention must resolve on its own once the incumbent goes away,
	// otherwise the fix for a conflict is to delete both and start again.
	older := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	incumbent := mirrorAt("incumbent", older, "")
	deleted := metav1.NewTime(older.Add(2 * time.Hour))
	incumbent.DeletionTimestamp = &deleted
	incumbent.Finalizers = []string{portMirrorFinalizer}

	f := newMirrorFixture(t,
		deviceSecret(contendedDevice),
		incumbent,
		mirrorAt("challenger", older.Add(time.Hour), ""),
	)

	f.reconcile(t, "challenger")

	challenger := f.read(t, "challenger")
	if challenger.Status.Phase != trawlv1alpha1.PortMirrorActive {
		t.Errorf("challenger phase = %q, want Active once the incumbent is being deleted",
			challenger.Status.Phase)
	}
}
