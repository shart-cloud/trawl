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

package storage

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"trawl.cloud/trawl/internal/config"
)

// presignStore builds a store against an endpoint nothing listens on.
//
// Presigning is a local signature computation, so this needs no backend — and
// the fact that it needs none is itself the property the gateway depends on:
// minting a URL cannot fail because object storage is slow.
func presignStore(t *testing.T) *S3Store {
	t.Helper()
	dir := t.TempDir()
	for name, value := range map[string]string{accessKeyFile: "AKIAEXAMPLE", secretKeyFile: "s3cr3t"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	store, err := NewS3Store(config.BucketConfig{
		Endpoint:        "127.0.0.1:1",
		Bucket:          "trawl-artifacts",
		Region:          "us-east-1",
		CredentialsPath: dir,
	})
	if err != nil {
		t.Fatalf("building store: %v", err)
	}
	return store
}

func TestPresignGetClampsTheLifetime(t *testing.T) {
	store := presignStore(t)

	cases := []struct {
		name string
		ttl  time.Duration
		want time.Duration
	}{
		{"under the ceiling is honoured", time.Minute, time.Minute},
		{"at the ceiling is honoured", MaxPresignTTL, MaxPresignTTL},
		{"over the ceiling is clamped down", time.Hour, MaxPresignTTL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := store.PresignGet(t.Context(), "captures/ns/uid/capture.pcapng", tc.ttl)
			if err != nil {
				t.Fatalf("PresignGet: %v", err)
			}
			got, err := strconv.Atoi(u.Query().Get("X-Amz-Expires"))
			if err != nil {
				t.Fatalf("X-Amz-Expires %q: %v", u.Query().Get("X-Amz-Expires"), err)
			}
			if time.Duration(got)*time.Second != tc.want {
				t.Errorf("URL lifetime %ds, want %s", got, tc.want)
			}
		})
	}
}

// A non-positive lifetime means the caller's clamp against the retention
// deadline has already decided this must not be served. Issuing an
// already-expired URL instead of refusing would turn a denial into a 303 the
// client then fails to follow, which reads as a storage fault rather than the
// authorization decision it is.
func TestPresignGetRefusesANonPositiveLifetime(t *testing.T) {
	store := presignStore(t)
	for _, ttl := range []time.Duration{0, -time.Second} {
		if _, err := store.PresignGet(t.Context(), "k", ttl); !errors.Is(err, ErrPresignExpired) {
			t.Errorf("ttl %s: error = %v, want ErrPresignExpired", ttl, err)
		}
	}
}

// The fake has to clamp exactly as the real store does. A fake that minted
// longer-lived URLs would let a TTL bug in the gateway pass every handler test.
func TestFakePresignerClampsLikeTheRealOne(t *testing.T) {
	var f FakePresigner

	u, err := f.PresignGet(t.Context(), "k", time.Hour)
	if err != nil {
		t.Fatalf("PresignGet: %v", err)
	}
	if got := u.Query().Get("X-Amz-Expires"); got != strconv.Itoa(int(MaxPresignTTL.Seconds())) {
		t.Errorf("fake lifetime %ss, want %v", got, MaxPresignTTL.Seconds())
	}
	if _, err := f.PresignGet(t.Context(), "k", 0); !errors.Is(err, ErrPresignExpired) {
		t.Errorf("fake accepted a zero lifetime: %v", err)
	}

	// The recorded call keeps the lifetime as asked, not as clamped, so a test
	// can tell a caller that over-asked from one that clamped correctly.
	calls := f.Calls()
	if len(calls) != 2 || calls[0].TTL != time.Hour || calls[0].Key != "k" {
		t.Errorf("recorded calls = %+v", calls)
	}
}
