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

// Package storage wraps the private object store that holds capture artifacts
// and the audit ledger.
//
// Both live in the same MinIO/S3 service but in separate buckets with separate
// credentials (ADR-0003), so this package is instantiated once per bucket rather
// than once per process.
//
// The interface is deliberately small. Everything Trawl needs is conditional
// creation, existence verification, ordered listing, read, and delete — and
// keeping it small is what lets the audit sink and capture controller be tested
// without a live object store.
package storage

import (
	"context"
	"errors"
	"io"
	"time"
)

// Sentinel errors that callers branch on. Concrete client errors are sanitized
// before they leave this package, so these are the only distinctions available.
var (
	// ErrAlreadyExists is returned when a conditional Put finds an object
	// already at that key. For the audit ledger this is the normal
	// idempotent-retry path, not a failure.
	ErrAlreadyExists = errors.New("object already exists")

	// ErrNotFound is returned when an object does not exist.
	ErrNotFound = errors.New("object not found")
)

// ObjectInfo is the metadata returned by Head and List.
type ObjectInfo struct {
	Key          string
	Size         int64
	ETag         string
	LastModified time.Time
	// RetainUntil is the backend-enforced write-once deadline, zero when the
	// bucket does not apply one.
	RetainUntil time.Time
	// Metadata holds user metadata such as the SHA-256 checksum recorded at
	// upload time.
	//
	// Keys are returned lowercased. S3 metadata keys are case-insensitive and a
	// real backend hands them back canonicalised - "sha256" written, "Sha256"
	// read - so implementations normalise rather than leaving each caller to
	// discover which spelling their store happens to use.
	Metadata map[string]string
}

// PutOptions controls a single write.
type PutOptions struct {
	// IfNotExists makes the write conditional on the key being absent. The
	// audit ledger always sets this: it is what makes a stable key an
	// idempotency guarantee rather than a convention.
	IfNotExists bool

	// RetainUntil requests backend-enforced write-once retention.
	RetainUntil time.Time

	ContentType string
	Metadata    map[string]string

	// Timeout overrides the store's default per-call bound. A capture artifact
	// can be a gibibyte; the 30 s that suits ledger records would fail it.
	// Zero keeps the default.
	Timeout time.Duration
}

// Store is the object-store surface Trawl depends on.
//
// Implementations must sanitize errors: a raw S3 client error carries the
// presigned URL and often the credential.
type Store interface {
	// Put writes an object, honouring PutOptions. It returns ErrAlreadyExists
	// when IfNotExists is set and the key is taken.
	Put(ctx context.Context, key string, body []byte, opts PutOptions) (ObjectInfo, error)

	// PutStream is Put for a body too large to hold in memory. size must be
	// the exact length of body; implementations use it to write the object in
	// a single request so IfNotExists stays one atomic conditional PUT.
	PutStream(ctx context.Context, key string, body io.Reader, size int64, opts PutOptions) (ObjectInfo, error)

	// Head returns metadata for a key, or ErrNotFound.
	Head(ctx context.Context, key string) (ObjectInfo, error)

	// Get returns the object body, or ErrNotFound.
	Get(ctx context.Context, key string) ([]byte, error)

	// List returns objects under prefix in lexicographic key order, beginning
	// at startAt. Ordering is what makes cursor-based replay resumable.
	//
	// startAt is INCLUSIVE: the object at that exact key is part of the result.
	// This is the clause the two implementations disagreed on for the life of
	// the project - the parameter was called startAfter, S3's own start-after
	// is exclusive, and the Fake was inclusive - so it is stated here rather
	// than left to the name. Sink.Replay resumes from the last key it forwarded
	// and re-delivers it deliberately: copies keep their stable_key and audit
	// views collapse by it, so an overlap costs nothing, while a skipped record
	// is permanently invisible in search. Given the ledger is authoritative,
	// over-delivery is the safe direction to err in.
	//
	// An empty startAt begins at the first key under prefix. A startAt naming an
	// object that does not exist - retention may have removed it since the
	// caller last saw it - resumes at the next key rather than failing.
	//
	// Only Key, Size, ETag and LastModified are guaranteed. Metadata and
	// RetainUntil require a Head: a listing does not carry them on every
	// backend, and returning them from one implementation and not the other is
	// how a caller comes to depend on the Fake.
	//
	// storagetest.RunConformance asserts all of this against any implementation.
	List(ctx context.Context, prefix, startAt string) ([]ObjectInfo, error)

	// Delete removes a key. Deleting an absent key succeeds, so retention
	// cleanup is idempotent.
	Delete(ctx context.Context, key string) error
}
