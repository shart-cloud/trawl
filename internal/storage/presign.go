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
	"context"
	"errors"
	"net/url"
	"time"

	"trawl.cloud/trawl/internal/sanitize"
)

// MaxPresignTTL is the longest life any presigned URL may have.
//
// A presigned URL is a bearer credential for one object: whoever holds it can
// fetch the packet bytes with no further authorization, and unlike a token it
// cannot be revoked. Five minutes is long enough for the CLI to follow a
// redirect and short enough that a URL captured from a proxy log or a shell
// history is worthless by the time anyone reads it.
const MaxPresignTTL = 5 * time.Minute

// Presigner issues short-lived, private download URLs for stored objects.
//
// It is deliberately NOT part of Store. Every component holding a Store can
// read, write and delete artifacts; only the gateway may mint a credential that
// lets a third party do so without presenting a Kubernetes identity. Keeping
// the two interfaces apart means a component is handed that ability explicitly
// rather than inheriting it from the store it already had.
type Presigner interface {
	// PresignGet returns a URL that serves the object at key for at most ttl.
	//
	// ttl is clamped to MaxPresignTTL: a caller asking for longer gets a
	// shorter URL, never a longer one. A ttl at or below zero is an error, not
	// an already-expired URL, because it means the caller's own clamp against
	// the retention deadline has already decided this must not be served.
	PresignGet(ctx context.Context, key string, ttl time.Duration) (*url.URL, error)
}

// ErrPresignExpired is returned when the requested lifetime has already run
// out. The caller must refuse the download rather than issue the URL.
var ErrPresignExpired = errors.New("presign lifetime is not positive")

// PresignGet implements Presigner against the bucket this store addresses.
//
// The signature is computed locally from the mounted credential; no request
// reaches the object store, so a presign cannot fail because the backend is
// slow. That is why the gateway verifies the object with Head first: without
// that check it would happily hand out a signed URL for an object retention
// has already removed.
func (s *S3Store) PresignGet(ctx context.Context, key string, ttl time.Duration) (*url.URL, error) {
	if ttl <= 0 {
		return nil, ErrPresignExpired
	}
	if ttl > MaxPresignTTL {
		ttl = MaxPresignTTL
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	signed, err := s.client.PresignedGetObject(ctx, s.bucket, key, ttl, url.Values{})
	if err != nil {
		// A minio presign error echoes the endpoint, and the endpoint may carry
		// embedded credentials.
		return nil, sanitize.Errorf("presigning %s: %v", key, err)
	}
	return signed, nil
}
