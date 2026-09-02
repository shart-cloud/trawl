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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"trawl.cloud/trawl/internal/storage"
	"trawl.cloud/trawl/internal/telemetry"
)

// memoryCursor is a CursorStore that keeps the cursor in memory.
type memoryCursor struct {
	value   string
	loadErr error
	saveErr error
	saves   int
	loads   int
}

func (c *memoryCursor) Load(context.Context) (string, error) {
	c.loads++
	return c.value, c.loadErr
}

func (c *memoryCursor) Save(_ context.Context, v string) error {
	c.saves++
	if c.saveErr != nil {
		return c.saveErr
	}
	c.value = v
	return nil
}

// commitN writes n records to the ledger, one per second so the time-ordered
// record keys sort in commit order, and returns their ledger keys in order.
func commitN(t *testing.T, store *storage.Fake, n int) (*Sink, []string) {
	t.Helper()
	base := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	at := base
	s, err := NewSink(Options{
		Store:     store,
		Prefix:    DefaultPrefix,
		Retention: 365 * 24 * time.Hour,
		Now:       func() time.Time { return at },
	})
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}

	keys := make([]string, 0, n)
	for i := range n {
		at = base.Add(time.Duration(i) * time.Second)
		rec := testRecord()
		rec.StableKey = fmt.Sprintf("admission/rec-%d", i)
		res, err := s.Commit(context.Background(), rec)
		if err != nil {
			t.Fatalf("committing record %d: %v", i, err)
		}
		keys = append(keys, res.LedgerKey)
	}
	return s, keys
}

func newTestReplayer(t *testing.T, sink *Sink, cursor CursorStore, out *bytes.Buffer, m *telemetry.Metrics) *Replayer {
	t.Helper()
	r, err := NewReplayer(ReplayOptions{
		Sink:    sink,
		Cursor:  cursor,
		Out:     out,
		Metrics: m,
	})
	if err != nil {
		t.Fatalf("NewReplayer: %v", err)
	}
	return r
}

// lines returns the non-empty stream lines decoded as records.
func lines(t *testing.T, out *bytes.Buffer) []Record {
	t.Helper()
	var recs []Record
	for l := range strings.SplitSeq(strings.TrimSpace(out.String()), "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		var rec Record
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			t.Fatalf("stream line is not a JSON record: %v\n%s", err, l)
		}
		recs = append(recs, rec)
	}
	return recs
}

func TestReplayerForwardsCommittedRecordsToTheStream(t *testing.T) {
	// The ledger is the durable copy; this stream is the searchable one. Until
	// something writes it, the Alloy audit pipeline collects nothing and an
	// audit query returns an empty result with no error anywhere.
	store := storage.NewFake()
	sink, keys := commitN(t, store, 3)

	var out bytes.Buffer
	r := newTestReplayer(t, sink, &memoryCursor{}, &out, nil)
	if err := r.ReplayOnce(context.Background()); err != nil {
		t.Fatalf("ReplayOnce: %v", err)
	}

	got := lines(t, &out)
	if len(got) != len(keys) {
		t.Fatalf("forwarded %d records, want %d", len(got), len(keys))
	}
	for i, rec := range got {
		if rec.LedgerKey != keys[i] {
			t.Errorf("record %d is %q, want %q; replay is not in ledger order", i, rec.LedgerKey, keys[i])
		}
		if rec.SchemaVersion != SchemaVersion {
			t.Errorf("record %d carries schema version %q, want %q; the Alloy pipeline "+
				"drops every line that does not", i, rec.SchemaVersion, SchemaVersion)
		}
	}
}

func TestReplayerPersistsItsCursorAndResumesFromIt(t *testing.T) {
	// A restart that resumed from nothing would re-forward the whole ledger
	// every time; one that resumed past the end would lose whatever arrived
	// while it was down.
	store := storage.NewFake()
	sink, keys := commitN(t, store, 2)

	cursor := &memoryCursor{}
	var first bytes.Buffer
	r := newTestReplayer(t, sink, cursor, &first, nil)
	if err := r.ReplayOnce(context.Background()); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	if cursor.value != keys[len(keys)-1] {
		t.Fatalf("cursor is %q after the first pass, want the last forwarded key %q",
			cursor.value, keys[len(keys)-1])
	}

	// A record committed after the first pass.
	third := testRecord()
	third.StableKey = "admission/rec-late"
	third.RecordedAt = time.Date(2026, 8, 29, 12, 0, 30, 0, time.UTC)
	res, err := sink.Commit(context.Background(), third)
	if err != nil {
		t.Fatalf("committing the late record: %v", err)
	}

	var second bytes.Buffer
	r2 := newTestReplayer(t, sink, cursor, &second, nil)
	if err := r2.ReplayOnce(context.Background()); err != nil {
		t.Fatalf("second pass: %v", err)
	}

	got := lines(t, &second)
	// The cursor record is re-delivered: Replay is inclusive of its cursor, and
	// a duplicate collapses by stable key while a skip is invisible forever.
	want := []string{keys[len(keys)-1], res.LedgerKey}
	if len(got) != len(want) {
		t.Fatalf("second pass forwarded %d records, want %d (the cursor record and the new one)",
			len(got), len(want))
	}
	for i, rec := range got {
		if rec.LedgerKey != want[i] {
			t.Errorf("second pass record %d is %q, want %q", i, rec.LedgerKey, want[i])
		}
	}
}

func TestReplayerDoesNotAdvanceThroughAFailedWrite(t *testing.T) {
	// Advancing past a record the stream never accepted would make it
	// permanently unsearchable while the ledger still claims it was forwarded.
	store := storage.NewFake()
	sink, keys := commitN(t, store, 3)

	cursor := &memoryCursor{}
	out := &failingWriter{failAfter: 2}
	r, err := NewReplayer(ReplayOptions{Sink: sink, Cursor: cursor, Out: out})
	if err != nil {
		t.Fatalf("NewReplayer: %v", err)
	}
	if err := r.ReplayOnce(context.Background()); err == nil {
		t.Fatal("ReplayOnce succeeded despite a stream write failure")
	}

	if cursor.value != keys[1] {
		t.Errorf("cursor is %q, want %q: it must name the last record actually written",
			cursor.value, keys[1])
	}
}

func TestReplayerReportsAnEmptyBacklogOnceDrained(t *testing.T) {
	// The cursor is inclusive, so the drained ledger still lists the cursor's
	// own object. Counting it would leave the backlog gauge stuck at 1 forever
	// and make a real one-record backlog indistinguishable from idle.
	store := storage.NewFake()
	sink, _ := commitN(t, store, 3)

	m := telemetry.NewMetrics()
	var out bytes.Buffer
	r := newTestReplayer(t, sink, &memoryCursor{}, &out, m)
	if err := r.ReplayOnce(context.Background()); err != nil {
		t.Fatalf("ReplayOnce: %v", err)
	}

	if got := testutil.ToFloat64(m.AuditBacklogObjects); got != 0 {
		t.Errorf("backlog gauge is %v after a full drain, want 0", got)
	}
	if got := testutil.ToFloat64(m.AuditOldestUnforwardedSecs); got != 0 {
		t.Errorf("oldest-unforwarded gauge is %v with nothing unforwarded, want 0", got)
	}
}

func TestReplayerReportsTheBacklogItHasNotForwarded(t *testing.T) {
	// The gauge is registered but was never set, so it read 0 - "nothing
	// unforwarded" - while the entire ledger was unforwarded.
	store := storage.NewFake()
	sink, _ := commitN(t, store, 3)

	m := telemetry.NewMetrics()
	cursor := &memoryCursor{}
	out := &failingWriter{failAfter: 1}
	r, err := NewReplayer(ReplayOptions{Sink: sink, Cursor: cursor, Out: out, Metrics: m})
	if err != nil {
		t.Fatalf("NewReplayer: %v", err)
	}
	if err := r.ReplayOnce(context.Background()); err == nil {
		t.Fatal("ReplayOnce succeeded despite a stream write failure")
	}

	if got := testutil.ToFloat64(m.AuditBacklogObjects); got != 2 {
		t.Errorf("backlog gauge is %v, want 2: one record was forwarded of three", got)
	}
}

func TestReplayerCountsForwardedRecords(t *testing.T) {
	store := storage.NewFake()
	sink, _ := commitN(t, store, 2)

	m := telemetry.NewMetrics()
	var out bytes.Buffer
	r := newTestReplayer(t, sink, &memoryCursor{}, &out, m)
	if err := r.ReplayOnce(context.Background()); err != nil {
		t.Fatalf("ReplayOnce: %v", err)
	}

	got := testutil.ToFloat64(m.AuditReplayTotal.WithLabelValues(telemetry.AuditResultSuccess))
	if got != 2 {
		t.Errorf("replay counter is %v, want 2", got)
	}
}

func TestReplayerTreatsALostCursorAsTheBeginning(t *testing.T) {
	// A cursor ConfigMap deleted by an operator, or absent on a fresh install,
	// must re-forward rather than skip: duplicates collapse by stable key, a
	// gap does not.
	store := storage.NewFake()
	sink, keys := commitN(t, store, 2)

	var out bytes.Buffer
	r := newTestReplayer(t, sink, &memoryCursor{}, &out, nil)
	if err := r.ReplayOnce(context.Background()); err != nil {
		t.Fatalf("ReplayOnce: %v", err)
	}
	if got := len(lines(t, &out)); got != len(keys) {
		t.Errorf("forwarded %d records from an empty cursor, want all %d", got, len(keys))
	}
}

func TestReplayerRefusesAnIncompleteConfiguration(t *testing.T) {
	// A replayer with no destination would report success while forwarding
	// nothing, which is the failure this whole path exists to make impossible.
	store := storage.NewFake()
	sink, _ := commitN(t, store, 1)

	for name, opts := range map[string]ReplayOptions{
		"no sink":   {Cursor: &memoryCursor{}, Out: &bytes.Buffer{}},
		"no cursor": {Sink: sink, Out: &bytes.Buffer{}},
		"no output": {Sink: sink, Cursor: &memoryCursor{}},
	} {
		if _, err := NewReplayer(opts); err == nil {
			t.Errorf("%s: NewReplayer accepted an incomplete configuration", name)
		}
	}
}

func TestReplayerRunsOnlyOnTheLeader(t *testing.T) {
	// Two replicas forwarding the same ledger would double every audit line
	// and fight over one cursor ConfigMap.
	store := storage.NewFake()
	sink, _ := commitN(t, store, 1)
	r := newTestReplayer(t, sink, &memoryCursor{}, &bytes.Buffer{}, nil)
	if !r.NeedLeaderElection() {
		t.Error("the replayer does not require leader election")
	}
}

// failingWriter accepts failAfter writes and then fails.
type failingWriter struct {
	failAfter int
	writes    int
}

func (w *failingWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes > w.failAfter {
		return 0, errors.New("stream unavailable")
	}
	return len(p), nil
}
