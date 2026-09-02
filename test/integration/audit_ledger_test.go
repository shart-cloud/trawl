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

package integration

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"trawl.cloud/trawl/internal/audit"
	"trawl.cloud/trawl/internal/storage"
	"trawl.cloud/trawl/internal/storage/storagetest"
	"trawl.cloud/trawl/test/integration/harness"
)

// These assert against real MinIO what the unit tests assert against a fake.
// The unit tests prove the sink's logic; these prove the backend semantics that
// logic assumes — conditional creation and lexicographic listing — actually
// hold. A fake that models them incorrectly would let both suites pass while
// the ledger loses its idempotency guarantee in production.

func TestS3StoreConditionalPutIsExclusive(t *testing.T) {
	m := harness.RequireMinIO(t)
	store := m.AuditStore(t)
	ctx := t.Context()

	key := "audit/v1/conditional-test.json"
	if _, err := store.Put(ctx, key, []byte(`{"a":1}`), storage.PutOptions{IfNotExists: true}); err != nil {
		t.Fatalf("first conditional put: %v", err)
	}

	// The second write must be refused, not silently overwrite. This is the
	// property that makes an audit stable key an idempotency guarantee.
	_, err := store.Put(ctx, key, []byte(`{"a":2}`), storage.PutOptions{IfNotExists: true})
	if !errors.Is(err, storage.ErrAlreadyExists) {
		t.Fatalf("second conditional put error = %v, want ErrAlreadyExists", err)
	}

	body, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(body) != `{"a":1}` {
		t.Errorf("object was overwritten: %s", body)
	}
}

func TestS3StoreHeadAndGetReportNotFound(t *testing.T) {
	m := harness.RequireMinIO(t)
	store := m.AuditStore(t)
	ctx := t.Context()

	if _, err := store.Head(ctx, "audit/v1/absent.json"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Head on absent key = %v, want ErrNotFound", err)
	}
	if _, err := store.Get(ctx, "audit/v1/absent.json"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Get on absent key = %v, want ErrNotFound", err)
	}
}

func TestS3StoreDeleteIsIdempotent(t *testing.T) {
	// Retention cleanup retries after partial failure, so deleting an
	// already-deleted object must not be an error.
	m := harness.RequireMinIO(t)
	store := m.ArtifactStore(t)
	ctx := t.Context()

	key := "captures/idempotent-delete"
	if _, err := store.Put(ctx, key, []byte("x"), storage.PutOptions{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("first delete: %v", err)
	}
	if err := store.Delete(ctx, key); err != nil {
		t.Errorf("second delete on an absent key = %v, want nil", err)
	}
}

func TestS3StoreListIsLexicographicAndResumable(t *testing.T) {
	// Audit replay resumes from a cursor and relies on this ordering. If the
	// backend returned an arbitrary order, replay would skip records.
	m := harness.RequireMinIO(t)
	store := m.AuditStore(t)
	ctx := t.Context()

	keys := []string{"audit/v1/a.json", "audit/v1/b.json", "audit/v1/c.json"}
	for _, k := range keys {
		if _, err := store.Put(ctx, k, []byte(`{}`), storage.PutOptions{IfNotExists: true}); err != nil {
			t.Fatalf("put %s: %v", k, err)
		}
	}

	all, err := store.List(ctx, "audit/v1/", "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) < len(keys) {
		t.Fatalf("listed %d objects, want at least %d", len(all), len(keys))
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].Key > all[i].Key {
			t.Errorf("list is not lexicographic: %q before %q", all[i-1].Key, all[i].Key)
		}
	}

	// The cursor clause used to be asserted here as "no key earlier than the
	// cursor came back", which is true whether the cursor's own object is
	// included or skipped - so it read as coverage while the two Store
	// implementations disagreed about exactly that. It is now
	// TestS3StoreSatisfiesTheStoreContract's job, against the same suite the
	// Fake answers.
}

func TestAuditSinkCommitsAgainstRealLedger(t *testing.T) {
	// The full FR-036 path against a real object-locked bucket: commit, verify,
	// idempotent retry, and conflict refusal.
	m := harness.RequireMinIO(t)
	sink, err := audit.NewSink(audit.Options{
		Store:     m.AuditStore(t),
		Prefix:    audit.DefaultPrefix,
		Retention: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	ctx := t.Context()

	rec := audit.Record{
		Action:    audit.ActionNetworkTapCreate,
		Decision:  audit.DecisionAllowed,
		Reason:    "Accepted",
		Actor:     audit.Actor{Username: "alice", UID: "u-1"},
		Resource:  audit.Resource{Group: "trawl.cloud", Kind: "NetworkTap", Name: "mirror-0", UID: "nt-1"},
		StableKey: "admission/integration-1",
	}

	first, err := sink.Commit(ctx, rec)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if first.Result != audit.ResultSuccess {
		t.Errorf("result = %q, want %q", first.Result, audit.ResultSuccess)
	}

	retry, err := sink.Commit(ctx, rec)
	if err != nil {
		t.Fatalf("idempotent retry: %v", err)
	}
	if retry.Result != audit.ResultRetry {
		t.Errorf("retry result = %q, want %q", retry.Result, audit.ResultRetry)
	}

	conflicting := rec
	conflicting.Decision = audit.DecisionDenied
	if _, err := sink.Commit(ctx, conflicting); err == nil {
		t.Error("conflicting content for an existing stable key was accepted")
	}
}

func TestAuditLedgerAppliesWriteOnceRetention(t *testing.T) {
	// data-model.md requires the object store to enforce retention, so a
	// compromised writer cannot erase its own audit trail.
	//
	// The assertion is that the backend actually recorded the retention, read
	// back from the object lock. Asserting "delete fails" would not prove it:
	// the audit bucket is versioned, so a delete creates a marker that hides the
	// object while the locked version survives, and Head-after-delete cannot
	// tell enforcement from concealment.
	m := harness.RequireMinIO(t)
	store := m.AuditStore(t)
	ctx := t.Context()

	key := "audit/v1/records/retained.json"
	retainUntil := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	if _, err := store.Put(ctx, key, []byte(`{}`), storage.PutOptions{
		IfNotExists: true,
		RetainUntil: retainUntil,
	}); err != nil {
		t.Fatalf("put with retention: %v", err)
	}

	info, err := store.Head(ctx, key)
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	if info.RetainUntil.IsZero() {
		t.Fatal("the backend recorded no retention deadline on an audit object")
	}
	if diff := info.RetainUntil.Sub(retainUntil); diff > time.Minute || diff < -time.Minute {
		t.Errorf("RetainUntil = %v, want ~%v", info.RetainUntil, retainUntil)
	}
}

func TestArtifactBucketDoesNotApplyRetentionByDefault(t *testing.T) {
	// The artifact bucket must stay deletable: retention cleanup removes
	// expired captures on schedule (FR-025). Only the ledger is write-once.
	m := harness.RequireMinIO(t)
	store := m.ArtifactStore(t)
	ctx := t.Context()

	key := "captures/deletable"
	if _, err := store.Put(ctx, key, []byte("x"), storage.PutOptions{}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := store.Head(ctx, key); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("artifact remained after delete: %v", err)
	}
}

// The Store contract, asserted against MinIO exactly as it is asserted against
// the Fake in internal/storage. Running both against one suite is the point:
// the Fake listed inclusively of the cursor and S3Store exclusively for the
// life of the project, and every test passed, because nothing ever asked the
// two the same question.
func TestS3StoreSatisfiesTheStoreContract(t *testing.T) {
	m := harness.RequireMinIO(t)
	store := m.AuditStore(t)

	storagetest.RunConformance(t, func(t *testing.T) (storage.Store, string) {
		// A real bucket outlives the test that writes to it, so each case gets
		// a namespace of its own rather than assuming an empty ledger.
		// Named for the case, so a stray object in the bucket says which
		// assertion left it there.
		return store, fmt.Sprintf("audit/v1/conformance/%s-%d/",
			strings.ReplaceAll(t.Name(), "/", "-"), time.Now().UnixNano())
	})
}
