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

// Package witness carries the event worker's liveness where something other
// than the event worker can read it.
//
// CapturePolicy status is written entirely by the worker, including the
// condition that reports a trigger source as disconnected. That arrangement has
// one failure it cannot describe: when the worker itself is gone, nothing
// writes anything, and every armed policy keeps the last status it was given.
// Armed is what an analyst reads as a claim of detection coverage, and six
// weeks later there is no way to tell an armed policy that was watching from
// one that was not.
//
// Every other status field in Trawl is built on the rule that absence of
// evidence is not evidence of coverage. The staleness check that would report
// the outage lived inside the component whose outage it describes, which is the
// one place it cannot run.
//
// So the worker publishes a heartbeat that outlives it, and the controller
// manager - a separate process, which is the whole point - reads it and speaks
// for the policies when it has gone quiet.
package witness

import (
	"context"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"trawl.cloud/trawl/internal/capture"
	"trawl.cloud/trawl/internal/sanitize"
)

// LeaseName is the heartbeat the worker renews and the controller reads.
//
// Deliberately not the worker's leader-election lease, which already exists and
// would have cost nothing to read. That lease says the process holds
// leadership, which is a weaker claim than the one status depends on: a worker
// holding the lease whose status loop is wedged renews it perfectly while every
// policy's status stands still - the same silence, now with a liveness signal
// attesting to it. This one is renewed by the status loop itself, after a flush
// that succeeded, so it means what the reader needs it to mean.
//
// Created by the worker at runtime rather than by kustomize, so its name
// carries the install prefix literally, as the leader-election lease does.
const LeaseName = "trawl-event-worker-status"

// Stale is how long the heartbeat may lag before the worker is treated as gone.
//
// The sensor heartbeat window, reused rather than reinvented: both answer the
// same question about a component that reports on a short interval, and a
// second threshold would drift from this one and then have to be reconciled by
// whoever next read both. At the default status interval it is six missed
// flushes, which is an outage rather than a busy moment.
const Stale = capture.StaleHeartbeat

// Heartbeat renews the worker's lease.
type Heartbeat struct {
	// Client writes the lease.
	Client client.Client

	// Namespace is the configured Trawl namespace.
	Namespace string

	// Identity names the process holding the lease, for an operator reading it
	// during a handoff. It is not used to decide freshness: a renewal from a
	// different replica is still a renewal, and requiring a matching identity
	// would report an outage across every leader handoff.
	Identity string

	// Now is time.Now unless a test replaced it.
	Now func() time.Time
}

// Renew records that the status loop completed a pass just now.
//
// Called after a successful flush, never before one. A heartbeat renewed at the
// top of the loop would attest to a loop that is running rather than one that
// is working, which is the distinction this whole mechanism exists to draw.
func (h *Heartbeat) Renew(ctx context.Context) error {
	now := metav1.NewMicroTime(h.now())
	seconds := int32(Stale.Seconds())

	var lease coordinationv1.Lease
	key := types.NamespacedName{Namespace: h.Namespace, Name: LeaseName}
	err := h.Client.Get(ctx, key, &lease)
	switch {
	case apierrors.IsNotFound(err):
		lease = coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{Name: LeaseName, Namespace: h.Namespace},
			Spec: coordinationv1.LeaseSpec{
				HolderIdentity:       &h.Identity,
				LeaseDurationSeconds: &seconds,
				AcquireTime:          &now,
				RenewTime:            &now,
			},
		}
		if err := h.Client.Create(ctx, &lease); err != nil {
			return sanitize.Errorf("creating the worker heartbeat lease: %v", err)
		}
		return nil
	case err != nil:
		return sanitize.Errorf("reading the worker heartbeat lease: %v", err)
	}

	lease.Spec.HolderIdentity = &h.Identity
	lease.Spec.LeaseDurationSeconds = &seconds
	lease.Spec.RenewTime = &now
	if lease.Spec.AcquireTime == nil {
		lease.Spec.AcquireTime = &now
	}
	if err := h.Client.Update(ctx, &lease); err != nil {
		return sanitize.Errorf("renewing the worker heartbeat lease: %v", err)
	}
	return nil
}

func (h *Heartbeat) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// Fresh reports whether the heartbeat says a worker is flushing status.
//
// A nil lease is not fresh. The worker creates it on its first successful
// flush, so its absence means no flush has ever completed - which is exactly
// the state a policy created while the worker is down would otherwise report
// as armed.
func Fresh(lease *coordinationv1.Lease, now time.Time) bool {
	if lease == nil || lease.Spec.RenewTime == nil {
		return false
	}
	// A renewTime in the future is treated as fresh rather than corrected.
	// Clock skew between the worker and this process is not something either
	// can resolve, and the conservative reading of an uncertain heartbeat is
	// the one that does not raise an outage nobody can act on.
	return now.Sub(lease.Spec.RenewTime.Time) <= Stale
}
