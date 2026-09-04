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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/rand/v2"
	"testing"
	"time"

	"trawl.cloud/trawl/internal/capture"
	"trawl.cloud/trawl/internal/storage"
	"trawl.cloud/trawl/test/integration/harness"
)

// The capture runner and controller rely on backend behaviour the unit tests
// only model: a conditional PUT of a large body is one atomic request, user
// metadata survives a round trip (lowercased), and a deleted artifact is
// gone from HEAD. One MinIO container serves every check to keep the suite
// fast; each subtest uses its own key.
func TestArtifactStorageSemantics(t *testing.T) {
	m := harness.RequireMinIO(t)
	store := m.ArtifactStore(t)
	for name, check := range map[string]func(*testing.T, storage.Store){
		"LargeConditionalPutIsExclusive":  checkLargeConditionalPut,
		"PutStreamRejectsAShortBody":      checkShortBody,
		"MetadataRoundTripsLowercased":    checkMetadataRoundTrip,
		"ManifestReadsBack":               checkManifestReadsBack,
		"DeleteIsIdempotentAndHeadSeesIt": checkDelete,
		"TimeoutIsHonoured":               checkTimeout,
	} {
		t.Run(name, func(t *testing.T) { check(t, store) })
	}
}

func checkLargeConditionalPut(t *testing.T, store storage.Store) {
	ctx := t.Context()
	// Above the SDK's multipart threshold (64 MiB): if PutStream fell
	// back to multipart, If-None-Match would not be honoured atomically.
	const size = 72 << 20
	body := randomBytes(t, size)
	sum := sha256.Sum256(body)
	key := capture.ObjectKey("trawl-system", "large-1")

	start := time.Now()
	info, err := store.PutStream(ctx, key, bytes.NewReader(body), size, storage.PutOptions{
		IfNotExists: true,
		ContentType: capture.ContentTypePcapng,
		Metadata:    map[string]string{capture.MetadataSHA256: hex.EncodeToString(sum[:])},
		Timeout:     2 * time.Minute,
	})
	if err != nil {
		t.Fatalf("first PutStream: %v", err)
	}
	t.Logf("uploaded %d bytes in %s", size, time.Since(start))
	if info.Size != size {
		t.Errorf("PutStream reported size %d, want %d", info.Size, size)
	}

	_, err = store.PutStream(ctx, key, bytes.NewReader(body[:1024]), 1024, storage.PutOptions{IfNotExists: true})
	if !errors.Is(err, storage.ErrAlreadyExists) {
		t.Fatalf("second PutStream error = %v, want ErrAlreadyExists", err)
	}

	head, err := store.Head(ctx, key)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if head.Size != size {
		t.Errorf("object was replaced: size %d, want %d", head.Size, size)
	}
	got, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if gotSum := sha256.Sum256(got); gotSum != sum {
		t.Errorf("stored bytes differ from uploaded bytes")
	}
}

func checkShortBody(t *testing.T, store storage.Store) {
	ctx := t.Context()
	// The runner passes the size it measured while hashing. A body that
	// ends early must not be stored as a truncated artifact.
	key := capture.ObjectKey("trawl-system", "short-1")
	body := io.LimitReader(bytes.NewReader(randomBytes(t, 4096)), 1000)
	_, err := store.PutStream(ctx, key, body, 4096, storage.PutOptions{IfNotExists: true})
	if err == nil {
		t.Fatal("short body accepted")
	}
	if _, err := store.Head(ctx, key); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Head after failed put = %v, want ErrNotFound", err)
	}
}

func checkMetadataRoundTrip(t *testing.T, store storage.Store) {
	ctx := t.Context()
	key := capture.ObjectKey("trawl-system", "meta-1")
	body := []byte("pcapng bytes")
	sum := sha256.Sum256(body)
	meta := map[string]string{
		capture.MetadataSHA256:        hex.EncodeToString(sum[:]),
		capture.MetadataCaptureJobUID: "meta-1",
		capture.MetadataPacketCount:   "3",
	}
	opts := storage.PutOptions{IfNotExists: true, ContentType: capture.ContentTypePcapng, Metadata: meta}
	if _, err := store.Put(ctx, key, body, opts); err != nil {
		t.Fatalf("Put: %v", err)
	}
	head, err := store.Head(ctx, key)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	for k, want := range meta {
		if head.Metadata[k] != want {
			t.Errorf("metadata[%q] = %q, want %q (all: %v)", k, head.Metadata[k], want, head.Metadata)
		}
	}
	// This is exactly what the controller does at Storing→Completed.
	m := &capture.Manifest{
		SchemaVersion: capture.ManifestSchemaVersion, CaptureJobUID: "meta-1", Namespace: "trawl-system", Name: "meta",
		Interface: "eno1", StartedAt: time.Now().UTC().Truncate(time.Second), EndedAt: time.Now().UTC().Truncate(time.Second),
		StopReason: "Duration", PacketCount: 3, SizeBytes: int64(len(body)), SHA256: hex.EncodeToString(sum[:]),
	}
	if err := capture.VerifyArtifact(m, "meta-1", head.Size, head.Metadata); err != nil {
		t.Errorf("VerifyArtifact against live HEAD: %v", err)
	}
}

func checkManifestReadsBack(t *testing.T, store storage.Store) {
	ctx := t.Context()
	m := &capture.Manifest{
		SchemaVersion: capture.ManifestSchemaVersion, CaptureJobUID: "man-1", Namespace: "trawl-system", Name: "manifest",
		Interface: "eno1", Filter: "tcp port 443", Snaplen: 262144, RequestedDuration: "60s", RequestedMaxSize: 64 << 20,
		StartedAt: time.Unix(1_700_000_000, 0).UTC(), EndedAt: time.Unix(1_700_000_060, 0).UTC(),
		StopReason: "Duration", PacketCount: 12, SizeBytes: 4096, SHA256: hex.EncodeToString(bytes.Repeat([]byte{0xab}, 32)),
		DumpcapVersion: "4.0.11", RunnerVersion: "test",
	}
	raw, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	key := capture.ManifestKey("trawl-system", "man-1")
	opts := storage.PutOptions{IfNotExists: true, ContentType: capture.ContentTypeManifest}
	if _, err := store.Put(ctx, key, raw, opts); err != nil {
		t.Fatalf("Put manifest: %v", err)
	}
	back, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get manifest: %v", err)
	}
	parsed, err := capture.ParseManifest(back)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if *parsed != *m {
		t.Errorf("manifest changed in storage:\n%+v\n%+v", m, parsed)
	}
}

func checkDelete(t *testing.T, store storage.Store) {
	ctx := t.Context()
	// Retention deletes artifact then manifest and verifies with HEAD;
	// a retry after partial failure must not error on the missing half.
	obj := capture.ObjectKey("trawl-system", "del-1")
	man := capture.ManifestKey("trawl-system", "del-1")
	for _, key := range []string{obj, man} {
		if _, err := store.Put(ctx, key, []byte("x"), storage.PutOptions{IfNotExists: true}); err != nil {
			t.Fatalf("Put %s: %v", key, err)
		}
	}
	if err := store.Delete(ctx, obj); err != nil {
		t.Fatalf("Delete artifact: %v", err)
	}
	if _, err := store.Head(ctx, obj); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Head after delete = %v, want ErrNotFound", err)
	}
	if _, err := store.Head(ctx, man); err != nil {
		t.Errorf("manifest deleted alongside artifact: %v", err)
	}
	for i := range 2 {
		if err := store.Delete(ctx, obj); err != nil {
			t.Errorf("repeat delete %d: %v", i, err)
		}
		if err := store.Delete(ctx, man); err != nil {
			t.Errorf("manifest delete %d: %v", i, err)
		}
	}
	listed, err := store.List(ctx, "captures/trawl-system/del-1/", "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(listed) != 0 {
		t.Errorf("prefix still lists %d objects after delete", len(listed))
	}
}

func checkTimeout(t *testing.T, store storage.Store) {
	// A store that ignored PutOptions.Timeout would take the default 30 s
	// bound; a 1 ns bound must fail immediately, not hang.
	key := capture.ObjectKey("trawl-system", "timeout-1")
	body := randomBytes(t, 8<<20)
	done := make(chan error, 1)
	go func() {
		opts := storage.PutOptions{Timeout: time.Nanosecond}
		_, err := store.PutStream(context.Background(), key, bytes.NewReader(body), int64(len(body)), opts)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("1 ns timeout succeeded")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("PutStream ignored Timeout")
	}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	r := rand.New(rand.NewPCG(uint64(n), 7)) //nolint:gosec // Test data, determinism is the point.
	for i := 0; i+8 <= n; i += 8 {
		binary.LittleEndian.PutUint64(b[i:], r.Uint64())
	}
	return b
}
