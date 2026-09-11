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

// T120: audit completeness and durability.
//
// The mechanics of committing were already well covered before this file
// existed, in internal/audit's unit tests and in audit_ledger_test.go beside
// it: conditional write, verification, idempotent retry, conflicting content
// for one key, fail-closed on an unavailable ledger, write-once retention,
// replay, cursor overlap and backlog. None of that is repeated here.
//
// What none of it asks is whether the ledger is *complete*. Every one of those
// tests starts from a record that a test constructed, so all of them would keep
// passing if a mutating code path stopped committing one - or never committed
// one to begin with. An audit ledger that faithfully records thirteen of the
// fourteen things it is required to record is not thirteen-fourteenths of a
// ledger; it is a ledger nobody can rely on, because its silence about an
// action no longer distinguishes "did not happen" from "not recorded".
//
// So this file asks two questions the others cannot:
//
//   - is every declared action actually written by some code path?
//   - does a fallible action leave both of its records, or does the outcome
//     collapse into the intent and erase whether the work happened?
package integration

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trawl.cloud/trawl/internal/audit"
	"trawl.cloud/trawl/test/integration/harness"
)

// requiredActions is the audit surface FR-036 obliges Trawl to record, paired
// with the constant each is declared as.
//
// Written out rather than derived from audit's own validActions slice on
// purpose. Deriving it would make the list agree with the code by construction,
// which is exactly the agreement under test: an action deleted from both the
// enum and its emitter would then delete itself from the requirement too, and
// the check would pass while the operation went unrecorded.
var requiredActions = []struct {
	constant string
	value    string
	fallible bool
}{
	{"ActionNetworkTapCreate", audit.ActionNetworkTapCreate, true},
	{"ActionNetworkTapUpdate", audit.ActionNetworkTapUpdate, true},
	{"ActionNetworkTapDelete", audit.ActionNetworkTapDelete, true},
	{"ActionCapturePolicyCreate", audit.ActionCapturePolicyCreate, true},
	{"ActionCapturePolicyUpdate", audit.ActionCapturePolicyUpdate, true},
	{"ActionCapturePolicyDelete", audit.ActionCapturePolicyDelete, true},
	{"ActionCapturePolicyArm", audit.ActionCapturePolicyArm, true},
	{"ActionCapturePolicyDisarm", audit.ActionCapturePolicyDisarm, true},
	{"ActionCaptureJobManualCreate", audit.ActionCaptureJobManualCreate, true},
	{"ActionCaptureJobPolicyCreate", audit.ActionCaptureJobPolicyCreate, true},
	{"ActionCaptureJobTransition", audit.ActionCaptureJobTransition, false},
	{"ActionArtifactDownload", audit.ActionArtifactDownload, true},
	{"ActionRetentionChange", audit.ActionRetentionChange, true},
	{"ActionArtifactExpire", audit.ActionArtifactExpire, true},
	{"ActionPortMirrorConfigure", audit.ActionPortMirrorConfigure, true},
	{"ActionPortMirrorRevert", audit.ActionPortMirrorRevert, true},
}

func TestEveryRequiredActionIsWrittenBySomeCodePath(t *testing.T) {
	// The completeness check, and the only one in the suite that can fail
	// because of something a developer did *not* write.
	//
	// An action constant that no production file mentions is an operation
	// happening with no record of it. That is invisible from every other angle:
	// the enum validates, the telemetry contract lists it, the sink would commit
	// it happily if anyone asked - and nobody ever asks. The ledger then holds
	// no entry for the action, which reads exactly like the action never
	// occurring.
	//
	// Scanning source text is a blunt instrument and deliberately so. A
	// stronger check would drive each operation and watch the ledger, which is
	// what the acceptance suites do for the paths a cluster can reach; this one
	// covers all fourteen on every `make test`, including the three an
	// acceptance run cannot easily provoke.
	roots := []string{
		filepath.Join("..", "..", "internal"),
		filepath.Join("..", "..", "cmd"),
	}

	mentions := map[string][]string{}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			// audit/model.go is where the constants are declared. A mention
			// there is the declaration, not a use of it, so counting it would
			// make every action look emitted.
			if filepath.ToSlash(path) == "../../internal/audit/model.go" {
				return nil
			}
			body, readErr := os.ReadFile(path) //nolint:gosec // G304: a path from walking the repository.
			if readErr != nil {
				return readErr
			}
			text := string(body)
			for _, want := range requiredActions {
				if strings.Contains(text, "audit."+want.constant) {
					mentions[want.constant] = append(mentions[want.constant], path)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", root, err)
		}
	}

	for _, want := range requiredActions {
		if len(mentions[want.constant]) == 0 {
			t.Errorf("no production file commits audit.%s (%q). The operation it names either does not "+
				"record itself, or the constant outlived the code that used it - and the ledger's silence "+
				"about it cannot be told apart from the operation never happening.",
				want.constant, want.value)
		}
	}
}

func TestEveryRequiredActionSurvivesTheLedgerRoundTrip(t *testing.T) {
	// Every action, committed to a real object-locked bucket and read back.
	//
	// The unit tests commit one representative record; this commits all
	// fourteen, because the shape differs between them - an expiry names no
	// human actor, a policy-created capture carries InitiatedBy, a transition
	// carries neither - and a record the ledger cannot hold is a record that is
	// lost precisely when it is needed.
	m := harness.RequireMinIO(t)
	sink := newLedgerSink(t, m)
	ctx := context.Background()

	for _, want := range requiredActions {
		t.Run(want.value, func(t *testing.T) {
			rec := recordFor(want.value, audit.DecisionAllowed, "roundtrip")
			if err := rec.Validate(); err != nil {
				t.Fatalf("the record this test builds is not valid: %v", err)
			}

			result, err := sink.Commit(ctx, rec)
			if err != nil {
				t.Fatalf("committing %s: %v", want.value, err)
			}
			if result.LedgerKey == "" {
				t.Fatal("the committed record carries no ledger key, so nothing can find it again")
			}
			if result.CommittedAt.IsZero() {
				t.Error("the committed record carries no commit time")
			}

			// Read back through the ledger rather than trusting the return
			// value: the point of the ledger is what it holds afterwards.
			var found *audit.Record
			if _, err := sink.Replay(ctx, "", func(_ context.Context, r audit.Record) error {
				if r.StableKey == rec.StableKey {
					copied := r
					found = &copied
				}
				return nil
			}); err != nil {
				t.Fatalf("replaying: %v", err)
			}
			if found == nil {
				t.Fatalf("%s was committed and is not in the ledger", want.value)
			}
			if found.Action != want.value {
				t.Errorf("stored action = %q, want %q", found.Action, want.value)
			}
			if found.Actor.Username != rec.Actor.Username {
				t.Errorf("stored actor = %q, want %q", found.Actor.Username, rec.Actor.Username)
			}
			if found.Resource.UID != rec.Resource.UID {
				t.Errorf("stored resource UID = %q, want %q", found.Resource.UID, rec.Resource.UID)
			}
		})
	}
}

func TestAFallibleActionLeavesBothItsIntentAndItsOutcome(t *testing.T) {
	// FR-036's intent/outcome pair, against a real ledger.
	//
	// A fallible action commits twice: `allowed` before the work and
	// `succeeded` or `failed` after it. The two must not collapse, and what
	// keeps them apart is Decision being part of the stable key. Drop it and
	// the outcome is written to the key the intent already holds - where,
	// because the content differs, the ledger refuses it as a conflict. The
	// operation then completes with the ledger saying only that it was
	// authorized, and nothing saying whether it happened.
	//
	// That is the failure this project cares most about: for a system whose
	// output is evidence, "authorized and then silence" is indistinguishable
	// from "authorized and then failed", and an investigator cannot tell a
	// capture that never ran from one whose record was lost.
	m := harness.RequireMinIO(t)
	sink := newLedgerSink(t, m)
	ctx := context.Background()

	for _, want := range requiredActions {
		if !want.fallible {
			continue
		}
		t.Run(want.value, func(t *testing.T) {
			admissionUID := "adm-" + strings.ReplaceAll(want.value, ".", "-")

			intent := recordFor(want.value, audit.DecisionAllowed, "")
			intent.StableKey = audit.StableKeyForAdmission(admissionUID, want.value, audit.DecisionAllowed)
			outcome := recordFor(want.value, audit.DecisionSucceeded, "")
			outcome.StableKey = audit.StableKeyForAdmission(admissionUID, want.value, audit.DecisionSucceeded)

			if intent.StableKey == outcome.StableKey {
				t.Fatalf("the intent and the outcome of one request share stable key %q, so committing "+
					"the second overwrites or conflicts with the first and the ledger loses whether the "+
					"work happened", intent.StableKey)
			}

			if _, err := sink.Commit(ctx, intent); err != nil {
				t.Fatalf("committing the intent: %v", err)
			}
			if _, err := sink.Commit(ctx, outcome); err != nil {
				t.Fatalf("committing the outcome after the intent: %v", err)
			}

			seen := map[string]bool{}
			if _, err := sink.Replay(ctx, "", func(_ context.Context, r audit.Record) error {
				if r.StableKey == intent.StableKey || r.StableKey == outcome.StableKey {
					seen[r.Decision] = true
				}
				return nil
			}); err != nil {
				t.Fatalf("replaying: %v", err)
			}

			if !seen[audit.DecisionAllowed] {
				t.Error("the ledger holds no intent record; the authorization decision was not preserved")
			}
			if !seen[audit.DecisionSucceeded] {
				t.Error("the ledger holds no outcome record; nothing says whether the authorized work happened")
			}
		})
	}
}

func TestAFailedOutcomeDoesNotEraseItsIntent(t *testing.T) {
	// The other half of the pair, and the half that matters when something goes
	// wrong. A failure has to be additive: the record that the action was
	// authorized must still stand beside the record that it did not complete.
	//
	// If a failed outcome replaced its intent, the ledger would show an action
	// that failed with no trace of who authorized it - which is the single
	// question an incident review asks first.
	m := harness.RequireMinIO(t)
	sink := newLedgerSink(t, m)
	ctx := context.Background()

	admissionUID := "adm-failure-path"
	intent := recordFor(audit.ActionCaptureJobManualCreate, audit.DecisionAllowed, "")
	intent.StableKey = audit.StableKeyForAdmission(admissionUID, audit.ActionCaptureJobManualCreate, audit.DecisionAllowed)

	failure := recordFor(audit.ActionCaptureJobManualCreate, audit.DecisionFailed, "")
	failure.StableKey = audit.StableKeyForAdmission(admissionUID, audit.ActionCaptureJobManualCreate, audit.DecisionFailed)
	failure.Message = "the runner could not bind the interface"

	if _, err := sink.Commit(ctx, intent); err != nil {
		t.Fatalf("committing the intent: %v", err)
	}
	if _, err := sink.Commit(ctx, failure); err != nil {
		t.Fatalf("committing the failure: %v", err)
	}

	var intentSeen, failureSeen bool
	var failureMessage string
	if _, err := sink.Replay(ctx, "", func(_ context.Context, r audit.Record) error {
		switch r.StableKey {
		case intent.StableKey:
			intentSeen = true
		case failure.StableKey:
			failureSeen = true
			failureMessage = r.Message
		}
		return nil
	}); err != nil {
		t.Fatalf("replaying: %v", err)
	}

	if !intentSeen {
		t.Error("the failure erased its intent record, so the ledger no longer says who authorized the action")
	}
	if !failureSeen {
		t.Error("the failure was not recorded at all")
	}
	if failureSeen && failureMessage == "" {
		t.Error("the failure record carries no message, so it says an action failed without saying why")
	}
}

// newLedgerSink builds a sink over a real object-locked bucket.
func newLedgerSink(t *testing.T, m *harness.MinIO) *audit.Sink {
	t.Helper()
	sink, err := audit.NewSink(audit.Options{
		Store:     m.AuditStore(t),
		Prefix:    audit.DefaultPrefix,
		Retention: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	return sink
}

// recordFor builds a valid record for one action.
//
// The actor differs by action deliberately. An expiry is the sweeper's own act
// with no human behind it, a policy-created capture is the worker acting on a
// rule's behalf, and the rest are people - and a record shape that only works
// for one of those is a record shape that loses the other two.
func recordFor(action, decision, keySuffix string) audit.Record {
	rec := audit.Record{
		Action:   action,
		Decision: decision,
		Reason:   "Accepted",
		Actor:    audit.Actor{Username: "alice@example.test", UID: "u-1"},
		Resource: audit.Resource{
			Group:     "trawl.cloud",
			Kind:      "CaptureJob",
			Namespace: "trawl-system",
			Name:      "subject",
			UID:       "uid-" + action,
		},
	}

	switch action {
	case audit.ActionArtifactExpire:
		rec.Actor = audit.Actor{Username: "system:serviceaccount:trawl-system:trawl-controller-manager"}
	case audit.ActionCaptureJobPolicyCreate:
		rec.Actor = audit.Actor{Username: "system:serviceaccount:trawl-system:trawl-event-worker"}
		rec.InitiatedBy = "trawl-system/on-alert"
	case audit.ActionCaptureJobTransition:
		rec.Actor = audit.Actor{Username: "system:serviceaccount:trawl-system:trawl-controller-manager"}
	case audit.ActionNetworkTapCreate, audit.ActionNetworkTapUpdate, audit.ActionNetworkTapDelete:
		rec.Resource.Kind = "NetworkTap"
	case audit.ActionCapturePolicyCreate, audit.ActionCapturePolicyUpdate, audit.ActionCapturePolicyDelete,
		audit.ActionCapturePolicyArm, audit.ActionCapturePolicyDisarm:
		rec.Resource.Kind = "CapturePolicy"
	}

	if keySuffix != "" {
		rec.StableKey = audit.StableKeyForAutomatic(action, rec.Resource.UID, keySuffix)
	}
	return rec
}
