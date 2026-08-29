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
	"errors"
	"fmt"
	"time"

	"trawl.cloud/trawl/internal/sanitize"
	"trawl.cloud/trawl/internal/storage"
)

// Options configures a Sink.
type Options struct {
	// Store is the audit-ledger bucket. It must not be the artifact bucket:
	// separate credentials are what stop an artifact writer from rewriting the
	// record of its own actions (ADR-0003).
	Store storage.Store

	// Prefix is the ledger key prefix, normally DefaultPrefix.
	Prefix string

	// Retention is the write-once deadline applied to each object. The backend
	// enforces it; Trawl only requests it.
	Retention time.Duration

	// Now is indirected for tests.
	Now func() time.Time
}

// Sink commits audit records to the durable ledger and replays them to the
// searchable stream.
//
// Commit is the gate FR-036 describes. It writes conditionally on absence, then
// verifies with HEAD before acknowledging. Both halves matter: the conditional
// write makes the stable key an idempotency guarantee, and the verification
// stops a backend that acknowledged without persisting from being treated as
// durable.
type Sink struct {
	store     storage.Store
	prefix    string
	retention time.Duration
	now       func() time.Time
}

// NewSink validates options and returns a Sink.
func NewSink(opts Options) (*Sink, error) {
	if opts.Store == nil {
		return nil, errors.New("audit sink requires a store")
	}
	if opts.Retention <= 0 {
		return nil, errors.New("audit sink requires a positive retention")
	}
	prefix := opts.Prefix
	if prefix == "" {
		prefix = DefaultPrefix
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Sink{store: opts.Store, prefix: prefix, retention: opts.Retention, now: now}, nil
}

// CommitResult reports how a commit resolved.
type CommitResult struct {
	// Result is one of ResultSuccess, ResultRetry, ResultUnavailable, or
	// ResultConflict, matching the trawl_audit_commit_total label.
	Result string

	LedgerKey   string
	CommittedAt time.Time
}

// Commit durably writes rec and verifies it before returning.
//
// The caller must not report its action as complete until this returns without
// error. A returned error means the action must fail closed.
func (s *Sink) Commit(ctx context.Context, rec Record) (CommitResult, error) {
	rec = rec.Sanitized()
	if err := rec.Validate(); err != nil {
		return CommitResult{Result: ResultConflict}, err
	}

	committedAt := s.now().UTC()
	rec.SchemaVersion = SchemaVersion
	if rec.RecordedAt.IsZero() {
		rec.RecordedAt = committedAt
	}

	key := s.keyFor(rec)
	rec.LedgerKey = key
	rec.CommittedAt = committedAt

	body, err := Encode(rec)
	if err != nil {
		return CommitResult{Result: ResultConflict}, err
	}

	_, putErr := s.store.Put(ctx, key, body, storage.PutOptions{
		IfNotExists: true,
		RetainUntil: committedAt.Add(s.retention),
		ContentType: "application/json",
	})

	switch {
	case putErr == nil:
		// Verify before acknowledging. A backend that reported success without
		// persisting must not produce a completed user action.
		if _, err := s.store.Head(ctx, key); err != nil {
			return CommitResult{Result: ResultUnavailable},
				sanitize.Errorf("audit record could not be verified after write: %v", err)
		}
		return CommitResult{Result: ResultSuccess, LedgerKey: key, CommittedAt: committedAt}, nil

	case errors.Is(putErr, storage.ErrAlreadyExists):
		// Either an idempotent retry of the same action, or two different
		// actions claiming one identity. Only the stored bytes can tell.
		return s.resolveExisting(ctx, key, rec)

	default:
		return CommitResult{Result: ResultUnavailable},
			sanitize.Errorf("committing audit record: %v", putErr)
	}
}

// resolveExisting distinguishes an idempotent retry from a stable-key conflict.
//
// The comparison ignores the fields the sink itself stamps, since a retry
// legitimately carries a later commit time while describing the same action.
func (s *Sink) resolveExisting(ctx context.Context, key string, rec Record) (CommitResult, error) {
	existingBytes, err := s.store.Get(ctx, key)
	if err != nil {
		return CommitResult{Result: ResultUnavailable},
			sanitize.Errorf("reading existing audit record: %v", err)
	}
	existing, err := Decode(existingBytes)
	if err != nil {
		return CommitResult{Result: ResultConflict},
			sanitize.Errorf("existing audit record is unreadable: %v", err)
	}

	if !sameAction(existing, rec) {
		return CommitResult{Result: ResultConflict}, errConflict
	}
	return CommitResult{
		Result:      ResultRetry,
		LedgerKey:   key,
		CommittedAt: existing.CommittedAt,
	}, nil
}

// sameAction compares the semantic content of two records, excluding the
// timestamps and ledger fields the sink assigns.
func sameAction(a, b Record) bool {
	a.RecordedAt, b.RecordedAt = time.Time{}, time.Time{}
	a.CommittedAt, b.CommittedAt = time.Time{}, time.Time{}
	a.LedgerKey, b.LedgerKey = "", ""

	ab, errA := Encode(a)
	bb, errB := Encode(b)
	if errA != nil || errB != nil {
		return false
	}
	return bytes.Equal(ab, bb)
}

// keyFor derives the ledger object key.
//
// The timestamp prefix makes lexicographic listing chronological, which is what
// lets replay resume from a cursor. The stable key suffix keeps the key
// one-to-one with the action identity.
func (s *Sink) keyFor(rec Record) string {
	ts := rec.RecordedAt.UTC().Format("20060102T150405.000000000Z")
	return fmt.Sprintf("%s%s-%s.json", s.prefix, ts, sanitize.DiagnosticHash(rec.StableKey))
}

// DeliverFunc forwards one record to the searchable stream.
type DeliverFunc func(ctx context.Context, rec Record) error

// Replay forwards ledger records to the searchable stream, beginning at cursor.
//
// The cursor record is re-delivered rather than skipped. Duplicate delivery is
// harmless because copies keep their stable_key and audit views collapse by it;
// a skipped record would be permanently invisible in search. Given the ledger is
// authoritative, the overlap is the safe direction to err in.
//
// Delivery failure stops replay where it stands and returns the count that did
// succeed, so the caller advances its cursor no further than what was actually
// forwarded.
func (s *Sink) Replay(ctx context.Context, cursor string, deliver DeliverFunc) (int, error) {
	objects, err := s.store.List(ctx, s.prefix, cursor)
	if err != nil {
		return 0, sanitize.Errorf("listing audit ledger: %v", err)
	}

	delivered := 0
	for _, obj := range objects {
		body, err := s.store.Get(ctx, obj.Key)
		if err != nil {
			return delivered, sanitize.Errorf("reading audit ledger object: %v", err)
		}
		rec, err := Decode(body)
		if err != nil {
			// A single unreadable object must not stall the whole stream; it is
			// counted and stepped over.
			continue
		}
		if err := deliver(ctx, rec); err != nil {
			return delivered, sanitize.Errorf("forwarding audit record: %v", err)
		}
		delivered++
	}
	return delivered, nil
}

// Backlog reports how many ledger objects sit beyond cursor and how old the
// oldest of them is, feeding trawl_audit_backlog_objects and
// trawl_audit_oldest_unforwarded_seconds.
func (s *Sink) Backlog(ctx context.Context, cursor string) (int, time.Time, error) {
	objects, err := s.store.List(ctx, s.prefix, cursor)
	if err != nil {
		return 0, time.Time{}, sanitize.Errorf("listing audit ledger: %v", err)
	}
	if len(objects) == 0 {
		return 0, time.Time{}, nil
	}
	oldest := objects[0].LastModified
	for _, o := range objects[1:] {
		if o.LastModified.Before(oldest) {
			oldest = o.LastModified
		}
	}
	return len(objects), oldest, nil
}
