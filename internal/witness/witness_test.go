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

package witness

import (
	"context"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const namespace = "trawl-system"

var renewedAt = time.Date(2026, 9, 9, 14, 0, 5, 0, time.UTC)

func newHeartbeat(t *testing.T, objs ...client.Object) (*Heartbeat, client.Client) {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatalf("adding client-go scheme: %v", err)
	}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(objs...).Build()
	return &Heartbeat{
		Client:    c,
		Namespace: namespace,
		Identity:  "trawl-event-worker-0",
		Now:       func() time.Time { return renewedAt },
	}, c
}

func read(t *testing.T, c client.Client) coordinationv1.Lease {
	t.Helper()
	var lease coordinationv1.Lease
	key := types.NamespacedName{Namespace: namespace, Name: LeaseName}
	if err := c.Get(context.Background(), key, &lease); err != nil {
		t.Fatalf("reading the lease: %v", err)
	}
	return lease
}

func TestTheFirstRenewalCreatesTheLease(t *testing.T) {
	// The worker creates it on its first successful flush, so before that
	// there is nothing for a reader to find - which is the state a policy
	// created while the worker is down has to be reported from.
	h, c := newHeartbeat(t)
	if err := h.Renew(context.Background()); err != nil {
		t.Fatalf("Renew: %v", err)
	}

	got := read(t, c)
	if got.Spec.RenewTime == nil || !got.Spec.RenewTime.Time.Equal(renewedAt) {
		t.Errorf("renewTime = %v, want %v", got.Spec.RenewTime, renewedAt)
	}
	if got.Spec.HolderIdentity == nil || *got.Spec.HolderIdentity != "trawl-event-worker-0" {
		t.Errorf("holderIdentity = %v, want the pod name", got.Spec.HolderIdentity)
	}
}

func TestRenewingAdvancesAnExistingLease(t *testing.T) {
	stale := metav1.NewMicroTime(renewedAt.Add(-10 * time.Minute))
	holder := "trawl-event-worker-1"
	existing := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: LeaseName},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity: &holder,
			AcquireTime:    &stale,
			RenewTime:      &stale,
		},
	}

	h, c := newHeartbeat(t, existing)
	if err := h.Renew(context.Background()); err != nil {
		t.Fatalf("Renew: %v", err)
	}

	got := read(t, c)
	if !got.Spec.RenewTime.Time.Equal(renewedAt) {
		t.Errorf("renewTime = %v, want it advanced to %v", got.Spec.RenewTime, renewedAt)
	}
	// A handoff replaces the holder and keeps the original acquisition: the
	// lease records when the heartbeat began, not when this replica took over.
	if !got.Spec.AcquireTime.Time.Equal(stale.Time) {
		t.Errorf("acquireTime = %v, want the original %v", got.Spec.AcquireTime, stale.Time)
	}
}

func TestFreshnessIsDecidedByTheWindowNotTheHolder(t *testing.T) {
	// A renewal from a different replica is still a renewal. Requiring a
	// matching identity would report an outage across every leader handoff.
	holder := "some-other-replica"
	lease := &coordinationv1.Lease{
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity: &holder,
			RenewTime:      ptr(metav1.NewMicroTime(renewedAt.Add(-time.Second))),
		},
	}
	if !Fresh(lease, renewedAt) {
		t.Error("a lease renewed a second ago by another replica was not fresh")
	}
}

func TestAbsenceIsNotFreshness(t *testing.T) {
	if Fresh(nil, renewedAt) {
		t.Error("a missing lease reported fresh")
	}
	if Fresh(&coordinationv1.Lease{}, renewedAt) {
		t.Error("a lease with no renewTime reported fresh")
	}
}

func TestTheWindowBoundary(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lag   time.Duration
		fresh bool
	}{
		{"just inside", Stale - time.Second, true},
		{"exactly at the window", Stale, true},
		{"just outside", Stale + time.Second, false},
		// Clock skew between two processes is not something either can
		// resolve, and the conservative reading of an uncertain heartbeat is
		// the one that does not raise an outage nobody can act on.
		{"ahead of us", -time.Minute, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lease := &coordinationv1.Lease{
				Spec: coordinationv1.LeaseSpec{
					RenewTime: ptr(metav1.NewMicroTime(renewedAt.Add(-tc.lag))),
				},
			}
			if got := Fresh(lease, renewedAt); got != tc.fresh {
				t.Errorf("Fresh with lag %v = %v, want %v", tc.lag, got, tc.fresh)
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }
