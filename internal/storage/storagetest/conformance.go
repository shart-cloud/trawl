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

// Package storagetest is the executable form of the storage.Store contract.
//
// The contract was prose, and prose does not run: storage.Fake listed
// inclusively of the cursor and S3Store listed exclusively of it, for the whole
// life of the project, while every test passed. The unit tests asserted the
// Fake's answer and the one test that used a real cursor asserted only that no
// key came back earlier than it - true under either reading. The divergence was
// invisible because nothing ever asked both implementations the same question.
//
// RunConformance is that question. Any Store must pass it, and a new one has a
// definition of done that is not "it compiles".
package storagetest

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"trawl.cloud/trawl/internal/storage"
)

// NewStore returns a Store to test and a key prefix that is unique to this
// subtest.
//
// The prefix exists because a real bucket outlives the test that writes to it:
// MinIO keeps what previous runs and neighbouring tests left behind, and a
// listing assertion that assumed an empty bucket would pass locally and fail in
// CI. Every key this suite writes lives under the prefix it is given.
type NewStore func(t *testing.T) (storage.Store, string)

// RunConformance asserts everything storage.Store promises.
//
// Each case is a subtest, so a failure names the clause of the contract that
// broke rather than "conformance failed".
func RunConformance(t *testing.T, newStore NewStore) {
	t.Helper()

	for name, run := range map[string]func(*testing.T, storage.Store, string){
		"PutThenGetReturnsWhatWasWritten":           putThenGet,
		"HeadReportsMetadataAndSize":                headReportsMetadata,
		"GetAndHeadOfAnAbsentKeyAreNotFound":        absentIsNotFound,
		"ConditionalPutRefusesAnExistingKey":        conditionalPut,
		"DeleteIsIdempotent":                        deleteIsIdempotent,
		"ListIsLexicographicAndHonoursThePrefix":    listOrderAndPrefix,
		"ListFromACursorIncludesTheCursorsOwnKey":   listIsInclusive,
		"ListFromAnAbsentCursorStartsAtTheNextKey":  listFromAbsentCursor,
		"ListWithNoCursorReturnsEverythingUnderIt":  listWithoutCursor,
		"ListOfAnEmptyPrefixReturnsNothingNotAnErr": listEmpty,
	} {
		t.Run(name, func(t *testing.T) {
			store, prefix := newStore(t)
			run(t, store, prefix)
		})
	}
}

func putThenGet(t *testing.T, store storage.Store, prefix string) {
	ctx := context.Background()
	key := prefix + "object.json"
	body := []byte(`{"observed":true}`)

	if _, err := store.Put(ctx, key, body, storage.PutOptions{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("get returned %s, want %s", got, body)
	}
}

func headReportsMetadata(t *testing.T, store storage.Store, prefix string) {
	ctx := context.Background()
	key := prefix + "described.json"
	body := []byte(`{"a":1}`)

	if _, err := store.Put(ctx, key, body, storage.PutOptions{
		ContentType: "application/json",
		Metadata:    map[string]string{"SHA256": "abc123"},
	}); err != nil {
		t.Fatalf("put: %v", err)
	}

	info, err := store.Head(ctx, key)
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	if info.Key != key {
		t.Errorf("head key = %q, want %q", info.Key, key)
	}
	if info.Size != int64(len(body)) {
		t.Errorf("head size = %d, want %d", info.Size, len(body))
	}
	// Metadata is guaranteed by Head and not by List; see the Store interface.
	//
	// The key goes in mixed case and must come back lowercased. S3 canonicalises
	// metadata keys - "sha256" written, "Sha256" read - so a store that returns
	// whatever spelling it was given sends every caller to find out for itself
	// which one its backend uses.
	if got := info.Metadata["sha256"]; got != "abc123" {
		t.Errorf("head metadata sha256 = %q, want the value recorded at upload under a lowercased key (got %v)",
			got, info.Metadata)
	}
}

func absentIsNotFound(t *testing.T, store storage.Store, prefix string) {
	ctx := context.Background()
	key := prefix + "never-written.json"

	if _, err := store.Get(ctx, key); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("get of an absent key = %v, want ErrNotFound", err)
	}
	if _, err := store.Head(ctx, key); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("head of an absent key = %v, want ErrNotFound", err)
	}
}

func conditionalPut(t *testing.T, store storage.Store, prefix string) {
	// This is what makes an audit stable key an idempotency guarantee rather
	// than a convention: a retry must be refused, not silently overwrite the
	// record already committed under that key.
	ctx := context.Background()
	key := prefix + "conditional.json"

	if _, err := store.Put(ctx, key, []byte(`{"n":1}`), storage.PutOptions{IfNotExists: true}); err != nil {
		t.Fatalf("first conditional put: %v", err)
	}
	if _, err := store.Put(ctx, key, []byte(`{"n":2}`), storage.PutOptions{IfNotExists: true}); !errors.Is(err, storage.ErrAlreadyExists) {
		t.Fatalf("second conditional put = %v, want ErrAlreadyExists", err)
	}

	body, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(body) != `{"n":1}` {
		t.Errorf("the refused write still landed: %s", body)
	}
}

func deleteIsIdempotent(t *testing.T, store storage.Store, prefix string) {
	// Retention cleanup retries after a partial failure, so deleting a key that
	// a previous pass already removed must converge rather than error.
	ctx := context.Background()
	key := prefix + "transient.json"

	if _, err := store.Put(ctx, key, []byte(`{}`), storage.PutOptions{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("first delete: %v", err)
	}
	if err := store.Delete(ctx, key); err != nil {
		t.Errorf("second delete of an already-absent key = %v, want nil", err)
	}
	if _, err := store.Get(ctx, key); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("get after delete = %v, want ErrNotFound", err)
	}
}

func listOrderAndPrefix(t *testing.T, store storage.Store, prefix string) {
	ctx := context.Background()
	seed(t, store, prefix, "a.json", "b.json", "c.json")
	// A neighbour outside the prefix, which must not appear. Prefix matching is
	// literal rather than path-aware, so the neighbour is a sibling of the
	// prefix string itself: "audit/v1-neighbour.json" does not begin with
	// "audit/v1/", while "audit/v1/../x" would.
	neighbour := strings.TrimSuffix(prefix, "/") + "-neighbour.json"
	if _, err := store.Put(ctx, neighbour, []byte(`{}`), storage.PutOptions{}); err != nil {
		t.Fatalf("put outside prefix: %v", err)
	}

	got, err := store.List(ctx, prefix, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	want := []string{prefix + "a.json", prefix + "b.json", prefix + "c.json"}
	assertKeys(t, got, want)
}

func listIsInclusive(t *testing.T, store storage.Store, prefix string) {
	// The clause that diverged. Sink.Replay resumes from the last key it
	// forwarded and re-delivers it deliberately: copies keep their stable_key
	// and audit views collapse by it, so an overlap costs nothing, while a
	// skipped record is permanently invisible in search. Given the ledger is
	// authoritative, over-delivery is the safe direction to err in - so the
	// cursor's own object is part of the answer.
	ctx := context.Background()
	seed(t, store, prefix, "a.json", "b.json", "c.json")

	got, err := store.List(ctx, prefix, prefix+"b.json")
	if err != nil {
		t.Fatalf("list from cursor: %v", err)
	}
	assertKeys(t, got, []string{prefix + "b.json", prefix + "c.json"})
}

func listFromAbsentCursor(t *testing.T, store storage.Store, prefix string) {
	// A cursor is a key the caller last saw, and that object may since have
	// been deleted by retention. Listing must resume at the next key rather
	// than fail or start over.
	ctx := context.Background()
	seed(t, store, prefix, "a.json", "c.json")

	got, err := store.List(ctx, prefix, prefix+"b.json")
	if err != nil {
		t.Fatalf("list from an absent cursor: %v", err)
	}
	assertKeys(t, got, []string{prefix + "c.json"})
}

func listWithoutCursor(t *testing.T, store storage.Store, prefix string) {
	ctx := context.Background()
	seed(t, store, prefix, "a.json", "b.json")

	got, err := store.List(ctx, prefix, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	assertKeys(t, got, []string{prefix + "a.json", prefix + "b.json"})
}

func listEmpty(t *testing.T, store storage.Store, prefix string) {
	// An empty ledger is a normal state - a fresh install has one - so it is an
	// empty result, not an error and not a nil-vs-empty distinction callers
	// have to know about.
	ctx := context.Background()

	got, err := store.List(ctx, prefix, "")
	if err != nil {
		t.Fatalf("list of an empty prefix: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("list of an empty prefix returned %d objects, want none", len(got))
	}
}

func seed(t *testing.T, store storage.Store, prefix string, names ...string) {
	t.Helper()
	for _, name := range names {
		if _, err := store.Put(context.Background(), prefix+name, []byte(`{}`), storage.PutOptions{}); err != nil {
			t.Fatalf("seeding %s: %v", name, err)
		}
	}
}

func assertKeys(t *testing.T, got []storage.ObjectInfo, want []string) {
	t.Helper()
	keys := make([]string, 0, len(got))
	for _, o := range got {
		keys = append(keys, o.Key)
	}
	if len(keys) != len(want) {
		t.Fatalf("listed %v, want %v", keys, want)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("listed %v, want %v", keys, want)
		}
	}
}
