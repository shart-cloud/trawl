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

package loki_test

import (
	"encoding/json"
	"testing"
	"time"

	"trawl.cloud/trawl/internal/events/loki"
)

func TestTheCursorResumesBeforeTheLastRecordItSaw(t *testing.T) {
	// Loki orders by the pipeline's timestamp, which is event_time - the
	// producer's clock, not ingestion order. A record can therefore be written
	// with a timestamp slightly older than one already returned, and resuming
	// exactly at the last timestamp would step over it. Resuming a little
	// earlier and suppressing what was already handled trades duplicate work,
	// which is cheap, for missed alerts, which are not recoverable.
	at := time.Date(2026, 9, 9, 21, 37, 59, 0, time.UTC)

	var cursor loki.Cursor
	cursor.Advance(at, "4125e22fe6fad350aa771423a45c643e")

	start := cursor.QueryStart(30 * time.Second)

	if !start.Equal(at.Add(-30 * time.Second)) {
		t.Errorf("query start = %s, want %s", start, at.Add(-30*time.Second))
	}
}

func TestTheOverlapSuppressesDuplicatesButNotLateArrivals(t *testing.T) {
	// These two pull in opposite directions and are the whole reason the cursor
	// tracks identities rather than just a high-water mark.
	//
	// Re-querying the overlap returns records already handled; delivering them
	// again would re-trigger their policies. But the reason the overlap exists
	// is that a record with an older event_time can be written after one with a
	// newer one, so "older than the cursor" cannot mean "already handled" -
	// that rule would discard exactly the alerts the overlap is there to catch.
	//
	// Identity is what separates them: suppress what was seen, deliver what was
	// not, regardless of which side of the timestamp it falls on.
	at := time.Date(2026, 9, 9, 21, 37, 59, 0, time.UTC)
	overlap := 30 * time.Second

	var cursor loki.Cursor
	cursor.Advance(at, "alert-a")

	if !cursor.Handled("alert-a") {
		t.Error("a record already handled was not recognised on re-delivery")
	}

	// Written late, with an event time inside the overlap but behind the
	// cursor. Never seen, so it must be delivered.
	if cursor.Handled("alert-late") {
		t.Error("a record never handled was suppressed as a duplicate")
	}
	cursor.Advance(at.Add(-10*time.Second), "alert-late")
	if !cursor.Handled("alert-late") {
		t.Error("the late record was not recorded as handled once processed")
	}

	// A late record must not drag the resume point backwards, or every
	// subsequent poll re-reads a widening window.
	if got := cursor.QueryStart(overlap); !got.Equal(at.Add(-overlap)) {
		t.Errorf("query start moved to %s after a late record; want %s", got, at.Add(-overlap))
	}
}

func TestTimestampTiesAreDistinguishedByIdentity(t *testing.T) {
	// Suricata writes several alerts with identical event times routinely - the
	// live stream shows pairs to the microsecond. A cursor keyed on time alone
	// either replays the whole tie or steps over the ones it had not reached.
	at := time.Date(2026, 9, 9, 21, 37, 59, 0, time.UTC)

	var cursor loki.Cursor
	cursor.Advance(at, "tie-1")

	if cursor.Handled("tie-2") {
		t.Error("a second alert at the same timestamp was treated as already handled")
	}
	cursor.Advance(at, "tie-2")
	if !cursor.Handled("tie-1") || !cursor.Handled("tie-2") {
		t.Error("both alerts at the tied timestamp should be recorded as handled")
	}
}

func TestALostCursorResumesWithinABoundedLookbackAndReportsTheGap(t *testing.T) {
	// The cursor lives in a ConfigMap. If it is lost - first start, a wiped
	// namespace, a failed read - the zero value's timestamp is the zero time,
	// and querying from there asks Loki for every record since year one. That
	// is refused or ruinous depending on the deployment, and neither is a
	// useful way to start.
	//
	// The honest behavior is to resume a bounded distance back and say that
	// anything before that was not examined. Silently starting at "now" would
	// look identical to a healthy worker while alerts went unevaluated.
	now := time.Date(2026, 9, 9, 22, 0, 0, 0, time.UTC)
	lookback := 15 * time.Minute

	var cursor loki.Cursor
	start, gap := cursor.Resume(now, 30*time.Second, lookback)

	if !start.Equal(now.Add(-lookback)) {
		t.Errorf("lost cursor resumed at %s, want %s", start, now.Add(-lookback))
	}
	if !gap {
		t.Error("a lost cursor did not report a gap; the unexamined window would be invisible")
	}
}

func TestAnIntactCursorResumesFromItsOverlapAndReportsNoGap(t *testing.T) {
	now := time.Date(2026, 9, 9, 22, 0, 0, 0, time.UTC)
	at := now.Add(-20 * time.Second)

	var cursor loki.Cursor
	cursor.Advance(at, "alert-a")

	start, gap := cursor.Resume(now, 30*time.Second, 15*time.Minute)

	if !start.Equal(at.Add(-30 * time.Second)) {
		t.Errorf("resumed at %s, want %s", start, at.Add(-30*time.Second))
	}
	if gap {
		t.Error("an intact cursor reported a gap")
	}
}

func TestACursorOlderThanTheLookbackReportsAGap(t *testing.T) {
	// Loki retention is finite. A worker down longer than the lookback cannot
	// read what it missed, and resuming from the stale cursor would silently
	// query a window Loki has already dropped - returning nothing and looking
	// like quiet traffic rather than lost coverage.
	now := time.Date(2026, 9, 9, 22, 0, 0, 0, time.UTC)

	var cursor loki.Cursor
	cursor.Advance(now.Add(-3*time.Hour), "alert-old")

	start, gap := cursor.Resume(now, 30*time.Second, 15*time.Minute)

	if !gap {
		t.Error("a cursor older than the lookback did not report a gap")
	}
	if start.Before(now.Add(-15 * time.Minute)) {
		t.Errorf("resumed at %s, before the %s lookback bound", start, now.Add(-15*time.Minute))
	}
}

func TestPruningBoundsTheIdentitySet(t *testing.T) {
	// The set is only useful for what the next query can return. Left unpruned
	// it grows for as long as the worker runs, which on a busy sensor is a leak
	// with a slow fuse - and the cursor is serialized into a ConfigMap, which
	// has a size limit the worker would eventually hit.
	at := time.Date(2026, 9, 9, 22, 0, 0, 0, time.UTC)
	overlap := 30 * time.Second

	var cursor loki.Cursor
	cursor.Advance(at.Add(-5*time.Minute), "ancient")
	cursor.Advance(at, "current")

	cursor.Prune(overlap)

	if cursor.Handled("ancient") {
		t.Error("an identity far outside the overlap survived pruning")
	}
	if !cursor.Handled("current") {
		t.Error("pruning dropped an identity still inside the overlap")
	}
}

func TestTheCursorSurvivesASerializationRoundTrip(t *testing.T) {
	// The cursor is persisted to a ConfigMap and read back after a restart or a
	// leader handoff. If the handled identities do not survive that, the
	// overlap on the first poll after every restart re-delivers records already
	// processed - and each one re-triggers its policy. Restarting the worker
	// would create duplicate captures, which is the exact failure the cursor
	// exists to prevent.
	at := time.Date(2026, 9, 9, 21, 37, 59, 123456789, time.UTC)

	var cursor loki.Cursor
	cursor.Advance(at, "alert-a")
	cursor.Advance(at, "alert-tie")
	cursor.Advance(at.Add(-5*time.Second), "alert-late")

	encoded, err := json.Marshal(cursor)
	if err != nil {
		t.Fatalf("marshalling cursor: %v", err)
	}

	var restored loki.Cursor
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatalf("unmarshalling cursor: %v", err)
	}

	if !restored.Timestamp.Equal(cursor.Timestamp) {
		t.Errorf("timestamp = %s, want %s", restored.Timestamp, cursor.Timestamp)
	}
	for _, id := range []string{"alert-a", "alert-tie", "alert-late"} {
		if !restored.Handled(id) {
			t.Errorf("identity %q did not survive the round trip; a restart would re-trigger it", id)
		}
	}
}

func TestLagIsMeasuredFromTheNewestRecordHandled(t *testing.T) {
	// Lag is how far behind the alert stream the worker is running. It is the
	// signal that distinguishes "keeping up with quiet traffic" from "falling
	// behind and not noticing", which otherwise look the same from the outside.
	now := time.Date(2026, 9, 9, 22, 0, 0, 0, time.UTC)

	var cursor loki.Cursor
	cursor.Advance(now.Add(-90*time.Second), "alert-a")

	if got := cursor.Lag(now); got != 90*time.Second {
		t.Errorf("lag = %s, want 90s", got)
	}
}
