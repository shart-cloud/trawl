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

package audit

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"trawl.cloud/trawl/internal/storage"
)

func testRecord() Record {
	return Record{
		Action:   ActionNetworkTapCreate,
		Decision: DecisionAllowed,
		Reason:   "Accepted",
		Actor: Actor{
			Username: "alice",
			UID:      "u-1",
			Groups:   []string{"trawl-operators"},
		},
		Resource: Resource{
			Group: "trawl.cloud", Kind: "NetworkTap",
			Namespace: "trawl-system", Name: "mirror-0", UID: "nt-1",
		},
		RequestID: "req-1",
		StableKey: "admission/abc-123",
	}
}

func newTestSink(t *testing.T, store *storage.Fake) *Sink {
	t.Helper()
	s, err := NewSink(Options{
		Store:     store,
		Prefix:    DefaultPrefix,
		Retention: 365 * 24 * time.Hour,
		Now:       func() time.Time { return time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	return s
}

// FR-036: a security-sensitive action commits durably to the ledger before it is
// reported as done, and a user-initiated action fails closed when it cannot.

func TestCommitWritesConditionallyAndVerifies(t *testing.T) {
	store := storage.NewFake()
	sink := newTestSink(t, store)

	res, err := sink.Commit(t.Context(), testRecord())
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if res.Result != ResultSuccess {
		t.Errorf("result = %q, want %q", res.Result, ResultSuccess)
	}
	if res.LedgerKey == "" {
		t.Error("Commit returned an empty ledger key")
	}
	if !strings.HasPrefix(res.LedgerKey, DefaultPrefix) {
		t.Errorf("ledger key %q is not under %q", res.LedgerKey, DefaultPrefix)
	}
	if res.CommittedAt.IsZero() {
		t.Error("Commit did not record a durable commit time")
	}

	// Exclusivity comes from the conditional claim on the stable-key index;
	// the record itself is then written under the claimed key and verified.
	// Acknowledging a write that was never durable is the failure this guards.
	indexKey := sink.indexKeyFor(testRecord().Sanitized())
	if !store.WasConditional(indexKey) {
		t.Error("the stable-key claim was not conditional on absence")
	}
	if got := store.PutCount(res.LedgerKey); got != 1 {
		t.Errorf("record put count = %d, want 1", got)
	}
	if got := store.HeadCount(res.LedgerKey); got < 1 {
		t.Error("Commit acknowledged without a HEAD verification")
	}
}

func TestIdenticalRetryIsSuccessfulAndNotDuplicated(t *testing.T) {
	// A controller retrying after a timeout must converge, not produce a second
	// record for one action.
	store := storage.NewFake()
	sink := newTestSink(t, store)
	rec := testRecord()

	first, err := sink.Commit(t.Context(), rec)
	if err != nil {
		t.Fatalf("first Commit: %v", err)
	}
	second, err := sink.Commit(t.Context(), rec)
	if err != nil {
		t.Fatalf("retry Commit: %v", err)
	}

	if second.Result != ResultRetry {
		t.Errorf("retry result = %q, want %q", second.Result, ResultRetry)
	}
	if first.LedgerKey != second.LedgerKey {
		t.Errorf("retry wrote a different key: %q vs %q", first.LedgerKey, second.LedgerKey)
	}
	// One index object and one record object; a retry adds neither.
	if got := store.ObjectCount(); got != 2 {
		t.Errorf("object count = %d, want 2 (one index, one record)", got)
	}
}

func TestConflictingContentForSameKeyIsRejected(t *testing.T) {
	// Same stable key, different content means two different actions claimed
	// one identity. That is an integrity error, not a retry.
	store := storage.NewFake()
	sink := newTestSink(t, store)

	rec := testRecord()
	if _, err := sink.Commit(t.Context(), rec); err != nil {
		t.Fatalf("first Commit: %v", err)
	}

	conflicting := rec
	conflicting.Decision = DecisionDenied

	res, err := sink.Commit(t.Context(), conflicting)
	if err == nil {
		t.Fatal("Commit accepted conflicting content for an existing stable key")
	}
	if res.Result != ResultConflict {
		t.Errorf("result = %q, want %q", res.Result, ResultConflict)
	}
	if got := store.ObjectCount(); got != 2 {
		t.Errorf("conflict wrote to the ledger: object count = %d, want 2 (the original index and record)", got)
	}
}

func TestCommitFailsClosedWhenLedgerUnavailable(t *testing.T) {
	// The whole point of FR-036: no durable record, no completed user action.
	store := storage.NewFake()
	store.FailPut(errors.New("connection refused"))
	sink := newTestSink(t, store)

	res, err := sink.Commit(t.Context(), testRecord())
	if err == nil {
		t.Fatal("Commit succeeded while the ledger was unavailable")
	}
	if res.Result != ResultUnavailable {
		t.Errorf("result = %q, want %q", res.Result, ResultUnavailable)
	}
}

func TestCommitFailsWhenVerificationCannotConfirmTheObject(t *testing.T) {
	// A put that reports success but leaves nothing behind must not be
	// acknowledged. Constitution II: nothing is Completed until it is verified.
	store := storage.NewFake()
	store.SwallowPuts(true)
	sink := newTestSink(t, store)

	if _, err := sink.Commit(t.Context(), testRecord()); err == nil {
		t.Fatal("Commit acknowledged a record that HEAD could not confirm")
	}
}

func TestRecordIsSanitizedBeforeCommit(t *testing.T) {
	store := storage.NewFake()
	sink := newTestSink(t, store)

	rec := testRecord()
	rec.Reason = "denied: token eyJhbGciOiJIUzI1NiJ9.abcd.efgh rejected"
	rec.Message = "upload to https://minio:9000/b/o?X-Amz-Signature=deadbeefcafe failed"

	res, err := sink.Commit(t.Context(), rec)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	body := string(store.Object(res.LedgerKey))
	for _, leak := range []string{"eyJhbGciOiJIUzI1NiJ9", "deadbeefcafe", "X-Amz-Signature"} {
		if strings.Contains(body, leak) {
			t.Errorf("committed record leaked %q:\n%s", leak, body)
		}
	}
}

func TestCommittedRecordCarriesSchemaVersionAndTimes(t *testing.T) {
	store := storage.NewFake()
	sink := newTestSink(t, store)

	res, err := sink.Commit(t.Context(), testRecord())
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	stored, err := Decode(store.Object(res.LedgerKey))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if stored.SchemaVersion != SchemaVersion {
		t.Errorf("schemaVersion = %q, want %q", stored.SchemaVersion, SchemaVersion)
	}
	if stored.RecordedAt.IsZero() {
		t.Error("recordedAt was not set")
	}
	if stored.StableKey == "" {
		t.Error("stableKey was not persisted")
	}
}

func TestRetentionIsAppliedToLedgerObjects(t *testing.T) {
	// data-model.md: write-once retention is enforced by the object store, not
	// by Trawl remembering not to delete things.
	store := storage.NewFake()
	sink := newTestSink(t, store)

	res, err := sink.Commit(t.Context(), testRecord())
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	retainUntil, ok := store.RetainUntil(res.LedgerKey)
	if !ok {
		t.Fatal("ledger object was written without a retention deadline")
	}
	want := res.CommittedAt.Add(365 * 24 * time.Hour)
	if !retainUntil.Equal(want) {
		t.Errorf("retainUntil = %v, want %v", retainUntil, want)
	}
}

func TestStableKeyIsDeterministicAndDistinct(t *testing.T) {
	// Idempotency depends entirely on this: the same action must key the same
	// way across processes and restarts, and different actions must not collide.
	a := StableKeyForAdmission("uid-1", ActionNetworkTapCreate, DecisionAllowed)
	b := StableKeyForAdmission("uid-1", ActionNetworkTapCreate, DecisionAllowed)
	if a != b {
		t.Errorf("admission stable key is not deterministic: %q vs %q", a, b)
	}

	// FR-036 requires distinct intent and outcome records for a fallible action.
	allowed := StableKeyForAdmission("uid-1", ActionCaptureJobManualCreate, DecisionAllowed)
	succeeded := StableKeyForAdmission("uid-1", ActionCaptureJobManualCreate, DecisionSucceeded)
	if allowed == succeeded {
		t.Error("intent and outcome records share a stable key")
	}

	for _, other := range []string{
		StableKeyForAdmission("uid-2", ActionNetworkTapCreate, DecisionAllowed),
		StableKeyForAdmission("uid-1", ActionNetworkTapDelete, DecisionAllowed),
	} {
		if a == other {
			t.Errorf("distinct actions produced the same stable key: %q", a)
		}
	}
}

func TestStableKeyForAutomaticActionIsContentDerived(t *testing.T) {
	// Automatic actions have no admission UID, so identity comes from the
	// action plus the object it concerns. Two evaluations of the same
	// transition must not produce two records.
	a := StableKeyForAutomatic(ActionCaptureJobTransition, "cj-uid-1", "Capturing")
	b := StableKeyForAutomatic(ActionCaptureJobTransition, "cj-uid-1", "Capturing")
	c := StableKeyForAutomatic(ActionCaptureJobTransition, "cj-uid-1", "Storing")

	if a != b {
		t.Errorf("automatic stable key is not deterministic: %q vs %q", a, b)
	}
	if a == c {
		t.Error("different transitions produced the same stable key")
	}
}

func TestValidateRejectsUnknownActionOrDecision(t *testing.T) {
	// Action and decision are indexed Loki labels; an arbitrary value would be
	// an unbounded label.
	rec := testRecord()
	rec.Action = "networktap.frobnicate"
	if err := rec.Validate(); err == nil {
		t.Error("Validate accepted an action outside the contract enum")
	}

	rec = testRecord()
	rec.Decision = "maybe"
	if err := rec.Validate(); err == nil {
		t.Error("Validate accepted a decision outside the contract enum")
	}
}

func TestValidateRequiresStableKey(t *testing.T) {
	rec := testRecord()
	rec.StableKey = ""
	if err := rec.Validate(); err == nil {
		t.Error("Validate accepted a record with no stable key")
	}
}

func TestReplayForwardsFromCursorWithOverlap(t *testing.T) {
	// Replay must not skip records after an outage, and must not duplicate them
	// endlessly either. Overlap plus stable_key collapse is the contract.
	store := storage.NewFake()
	sink := newTestSink(t, store)

	names := []string{"tap-a", "tap-b", "tap-c"}
	keys := make([]string, 0, len(names))
	for i, name := range names {
		rec := testRecord()
		rec.Resource.Name = name
		rec.StableKey = "admission/key-" + name
		rec.RequestID = "req-" + name
		res, err := sink.Commit(t.Context(), rec)
		if err != nil {
			t.Fatalf("Commit %d: %v", i, err)
		}
		keys = append(keys, res.LedgerKey)
	}

	var forwarded []Record
	n, err := sink.Replay(t.Context(), "", func(_ context.Context, r Record) error {
		forwarded = append(forwarded, r)
		return nil
	})
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if n != len(keys) {
		t.Errorf("replayed %d records, want %d", n, len(keys))
	}

	// Resuming from the second key must re-deliver it (overlap), not skip it.
	forwarded = nil
	if _, err := sink.Replay(t.Context(), keys[1], func(_ context.Context, r Record) error {
		forwarded = append(forwarded, r)
		return nil
	}); err != nil {
		t.Fatalf("Replay from cursor: %v", err)
	}
	if len(forwarded) == 0 {
		t.Fatal("replay from a cursor delivered nothing")
	}
	if forwarded[0].StableKey != "admission/key-tap-b" {
		t.Errorf("overlap did not re-deliver the cursor record, got %q", forwarded[0].StableKey)
	}
}

func TestReplayReportsBacklog(t *testing.T) {
	store := storage.NewFake()
	sink := newTestSink(t, store)

	for _, name := range []string{"a", "b", "c"} {
		rec := testRecord()
		rec.StableKey = "admission/key-" + name
		rec.Resource.Name = name
		if _, err := sink.Commit(t.Context(), rec); err != nil {
			t.Fatalf("Commit: %v", err)
		}
	}

	backlog, oldest, err := sink.Backlog(t.Context(), "")
	if err != nil {
		t.Fatalf("Backlog: %v", err)
	}
	if backlog != 3 {
		t.Errorf("backlog = %d, want 3", backlog)
	}
	if oldest.IsZero() {
		t.Error("Backlog did not report the oldest unforwarded record time")
	}
}

func TestBacklogExcludesTheCursorRecordItself(t *testing.T) {
	// Replay's cursor is inclusive, so a drained ledger still lists the cursor's
	// own object. Counting it as backlog would leave the gauge stuck at 1 and
	// make an idle pipeline indistinguishable from one record behind - and the
	// metric's own name is "objects not yet covered by the persisted replay
	// cursor", which the cursor's object is not.
	store := storage.NewFake()
	sink := newTestSink(t, store)

	var last string
	for _, name := range []string{"a", "b", "c"} {
		rec := testRecord()
		rec.StableKey = "admission/key-" + name
		rec.Resource.Name = name
		res, err := sink.Commit(t.Context(), rec)
		if err != nil {
			t.Fatalf("Commit: %v", err)
		}
		last = res.LedgerKey
	}

	backlog, oldest, err := sink.Backlog(t.Context(), last)
	if err != nil {
		t.Fatalf("Backlog: %v", err)
	}
	if backlog != 0 {
		t.Errorf("backlog = %d with everything forwarded, want 0", backlog)
	}
	if !oldest.IsZero() {
		t.Error("Backlog reported an oldest-unforwarded time with nothing unforwarded")
	}
}

func TestReplayStopsOnDeliveryFailure(t *testing.T) {
	// Advancing the cursor past a record that was never delivered would lose it
	// permanently, so delivery failure must halt replay where it stands.
	store := storage.NewFake()
	sink := newTestSink(t, store)

	for _, name := range []string{"a", "b", "c"} {
		rec := testRecord()
		rec.StableKey = "admission/key-" + name
		rec.Resource.Name = name
		if _, err := sink.Commit(t.Context(), rec); err != nil {
			t.Fatalf("Commit: %v", err)
		}
	}

	delivered := 0
	n, err := sink.Replay(t.Context(), "", func(_ context.Context, _ Record) error {
		delivered++
		if delivered == 2 {
			return errors.New("loki unavailable")
		}
		return nil
	})
	if err == nil {
		t.Fatal("Replay reported success despite a delivery failure")
	}
	if n != 1 {
		t.Errorf("replay counted %d successful deliveries, want 1", n)
	}
}

func TestIdempotencyHoldsUnderARealClock(t *testing.T) {
	// Regression: the ledger key once embedded RecordedAt, so two commits of the
	// same stable key produced different keys and never collided. Every unit
	// test passed because they all injected a fixed clock; under time.Now every
	// retry silently wrote a duplicate record.
	//
	// This test deliberately uses a moving clock, which is what the original
	// design could not survive.
	store := storage.NewFake()
	sink, err := NewSink(Options{
		Store:     store,
		Prefix:    DefaultPrefix,
		Retention: 365 * 24 * time.Hour,
		Now:       time.Now, // moving, not pinned
	})
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}

	rec := testRecord()
	first, err := sink.Commit(t.Context(), rec)
	if err != nil {
		t.Fatalf("first Commit: %v", err)
	}
	second, err := sink.Commit(t.Context(), rec)
	if err != nil {
		t.Fatalf("retry Commit: %v", err)
	}

	if second.Result != ResultRetry {
		t.Errorf("retry result = %q, want %q", second.Result, ResultRetry)
	}
	if first.LedgerKey != second.LedgerKey {
		t.Errorf("retry wrote a different record key: %q vs %q", first.LedgerKey, second.LedgerKey)
	}

	// One index object and one record object, not two of each.
	if got := store.ObjectCount(); got != 2 {
		t.Errorf("object count = %d, want 2 (one index, one record)", got)
	}
}

func TestDanglingClaimIsCompletedByRetry(t *testing.T) {
	// A crash between claiming the stable key and writing the record leaves a
	// claim pointing at nothing. A retry must complete that record rather than
	// treat the claim as proof the record exists.
	store := storage.NewFake()
	sink := newTestSink(t, store)
	rec := testRecord()

	// Claim the key by hand, simulating the interrupted commit.
	indexKey := sink.indexKeyFor(rec.Sanitized())
	recordKey := sink.recordKeyFor(withCommitFields(rec, sink))
	if _, err := store.Put(t.Context(), indexKey, []byte(recordKey), storage.PutOptions{IfNotExists: true}); err != nil {
		t.Fatalf("seeding dangling claim: %v", err)
	}

	res, err := sink.Commit(t.Context(), rec)
	if err != nil {
		t.Fatalf("Commit over a dangling claim: %v", err)
	}
	if res.Result != ResultSuccess {
		t.Errorf("result = %q, want %q", res.Result, ResultSuccess)
	}
	if res.LedgerKey != recordKey {
		t.Errorf("completed record key = %q, want the claimed key %q", res.LedgerKey, recordKey)
	}
	if len(store.Object(recordKey)) == 0 {
		t.Error("the claimed record key still holds no record")
	}
}

// withCommitFields mirrors what Commit stamps before deriving the record key,
// so the test can predict that key.
func withCommitFields(rec Record, s *Sink) Record {
	out := rec.Sanitized()
	out.SchemaVersion = SchemaVersion
	if out.RecordedAt.IsZero() {
		out.RecordedAt = s.now().UTC()
	}
	return out
}
