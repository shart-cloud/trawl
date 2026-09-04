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
	"testing"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/capture"
)

// persist is the one place a phase change is committed, and the guard there
// is what keeps a derivation bug from writing a capture's history backwards.
// Nothing Reconcile can observe should reach it, which is exactly why it is
// called directly here: a lifecycle rule with no caller is the defect this
// repository keeps finding, and the matrix test alone would not notice if the
// call went away again.
//
// The reconciler is deliberately left with no client and no audit sink. Every
// path through persist other than refusing needs one of them, so a guard that
// stopped running would panic rather than quietly pass.
func TestPersistRefusesToMoveACaptureBackwards(t *testing.T) {
	job := &trawlv1alpha1.CaptureJob{}
	job.Status.Phase = trawlv1alpha1.CapturePhaseStoring

	r := &CaptureJobReconciler{}
	backwards := capture.Outcome{Phase: trawlv1alpha1.CapturePhaseCapturing}

	if err := r.persist(context.Background(), job, capture.Observation{}, backwards, nil); err != nil {
		t.Fatalf("persist returned %v, want nil: the pass is dropped, not retried", err)
	}
	if job.Status.Phase != trawlv1alpha1.CapturePhaseStoring {
		t.Errorf("phase is %q, want it left at Storing", job.Status.Phase)
	}
}

// Leaving a terminal phase is the same class of error: a Completed capture
// that reverts has an artifact the ledger says was already handed over.
func TestPersistRefusesToLeaveATerminalPhase(t *testing.T) {
	job := &trawlv1alpha1.CaptureJob{}
	job.Status.Phase = trawlv1alpha1.CapturePhaseCompleted

	r := &CaptureJobReconciler{}
	back := capture.Outcome{Phase: trawlv1alpha1.CapturePhaseStoring}

	if err := r.persist(context.Background(), job, capture.Observation{}, back, nil); err != nil {
		t.Fatalf("persist returned %v, want nil", err)
	}
	if job.Status.Phase != trawlv1alpha1.CapturePhaseCompleted {
		t.Errorf("phase is %q, want it left at Completed", job.Status.Phase)
	}
}
