//go:build acceptance

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

// T127: retention enforced against a cluster, on a period nobody wants to wait
// out honestly.
//
// Most of what T127 asks for is already asserted next door in
// manual_capture_test.go and is not repeated here:
//
//   - exact deadline, deletion, HTTP 410 refusal, preserved metadata and the
//     ledger record   TestAnExpiredCaptureIsDeletedAndRefused
//   - a shortened deadline is measured from completion, not from now
//     TestShorteningRetentionMovesTheDeadlineFromCompletion
//
// What neither covers is the join between them. The shortening spec asserts the
// deadline *field* moves and that the capture stays downloadable while the new
// deadline is still ahead - it stops there. Nothing asserts that a shortened
// deadline is then actually enforced. A controller that recorded the new date
// and swept on the old one would satisfy every existing assertion and keep
// evidence for twenty-three hours longer than the person who shortened it
// asked, which is a retention policy that silently does not hold.
//
// That is also the only honest way to validate a twenty-four hour retention
// without waiting twenty-four hours. The CRD's floor is one hour and there is
// no clock hook, so the acceleration is a real operator action rather than a
// test seam: collect under the long period, shorten it the way a retention
// admin would, and hold the installation to the shorter one.
package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
)

func TestAShortenedRetentionIsEnforcedAndNotMerelyRecorded(t *testing.T) {
	a := requireAcceptanceCluster(t)
	if os.Getenv("TRAWL_E2E_EXPIRY") != "1" {
		t.Skip("set TRAWL_E2E_EXPIRY=1 to run this; it waits out a real retention deadline")
	}
	a.requireReachableObjectStore(t)

	name := a.captureName(t, "shorten-expiry")
	cursor := a.ledgerCursor(t)

	// Collected under a day-long retention, which is the period actually being
	// validated. Waiting it out would make this a test nobody runs.
	opts := a.defaultCaptureOptions()
	opts.retention = "24h"
	a.applyCapture(t, name, opts)

	completed := a.waitForCapture(t, name, captureCompleteTimeout, "complete",
		capturePhaseIs(trawlv1alpha1.CapturePhaseCompleted))
	if completed.Artifact == nil {
		t.Fatal("a completed capture has no artifact, so there is nothing for retention to act on")
	}
	if completed.CompletedAt == nil {
		t.Fatal("a completed capture has no completion time, so the shortened deadline has no origin")
	}
	key := completed.Artifact.Key
	completedAt := completed.CompletedAt.Time

	// Present before, or its later absence proves nothing.
	if !a.artifactExists(t, key) {
		t.Fatalf("the artifact %s is not in the bucket before expiry", key)
	}

	// The long deadline is what the installation is holding to right now.
	longDeadline := completedAt.Add(24 * time.Hour)
	if completed.RetentionDeadline == nil || !completed.RetentionDeadline.Time.Equal(longDeadline) {
		t.Fatalf("deadline = %v, want %s (completedAt + 24h); this spec's premise is that the "+
			"installation is holding the long period before it is shortened",
			completed.RetentionDeadline, longDeadline)
	}

	// The operator action. One hour is the CRD's floor, so this is the largest
	// acceleration the API permits: 24x.
	a.patchRetentionAsAdmin(t, name, "1h")

	shortDeadline := completedAt.Add(time.Hour)
	shortened := a.waitForCapture(t, name, settleTimeout, "record the shortened deadline",
		func(s trawlv1alpha1.CaptureJobStatus) bool {
			return s.RetentionDeadline != nil && s.RetentionDeadline.Time.Equal(shortDeadline)
		})
	if got := shortened.RetentionDeadline.Time; !got.Equal(shortDeadline) {
		t.Fatalf("shortened deadline = %s, want %s", got, shortDeadline)
	}
	t.Logf("retention shortened 24h -> 1h; deadline moved from %s to %s",
		longDeadline.Format(time.RFC3339), shortDeadline.Format(time.RFC3339))

	// The assertion this file exists for: the sweeper honours the new deadline.
	// Everything above is satisfied by a controller that writes the date and
	// sweeps on the old one.
	expired := a.waitForExpiry(t, name, shortDeadline)

	if a.artifactExists(t, key) {
		t.Errorf("the artifact %s is still in the bucket after the shortened deadline passed; "+
			"the new retention was recorded and not enforced, and the evidence outlives what the "+
			"retention admin asked for", key)
	}
	if conditionTrue(expired.Conditions, "Downloadable") {
		t.Error("a capture past its shortened deadline is still downloadable")
	}
	if !conditionTrue(expired.Conditions, "RetentionEnforced") {
		t.Errorf("RetentionEnforced is not True after the shortened deadline:\n%s",
			formatConditions(expired.Conditions))
	}

	// The record survives the bytes. This is what lets an investigation say
	// what was collected and why it is gone, after it is gone.
	if expired.SHA256 == "" || expired.CompletedAt == nil {
		t.Errorf("expiry lost the capture record: sha=%q completedAt=%v",
			expired.SHA256, expired.CompletedAt)
	}
	if expired.RetentionDeadline == nil || !expired.RetentionDeadline.Time.Equal(shortDeadline) {
		t.Errorf("the expired capture no longer records the deadline it was held to: %v",
			expired.RetentionDeadline)
	}

	// And the refusal is the gateway's, not a transport failure that would
	// satisfy "the download did not work" while proving nothing about
	// retention. 410 rather than 404 for the reason the sibling spec gives: an
	// analyst told "no such capture" hunts for a typo instead of reading the
	// retention policy.
	output := filepath.Join(t.TempDir(), "expired.pcapng")
	out, err := a.download(t, name, analystSA, output)
	if err == nil {
		t.Errorf("a capture past its shortened deadline was still served:\n%s", out)
	} else if !strings.Contains(out, "HTTP 410") {
		t.Errorf("the refusal is not the gateway's HTTP 410, so it proves nothing about retention:\n%s", out)
	}

	assertLedgerHasExpiry(t, a, cursor, name)
}
