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
}

// Store is the object-store surface Trawl depends on.
//
// Implementations must sanitize errors: a raw S3 client error carries the
// presigned URL and often the credential.
type Store interface {
	// Put writes an object, honouring PutOptions. It returns ErrAlreadyExists
	// when IfNotExists is set and the key is taken.
	Put(ctx context.Context, key string, body []byte, opts PutOptions) (ObjectInfo, error)

	// Head returns metadata for a key, or ErrNotFound.
	Head(ctx context.Context, key string) (ObjectInfo, error)

	// Get returns the object body, or ErrNotFound.
	Get(ctx context.Context, key string) ([]byte, error)

	// List returns objects under prefix in lexicographic key order, beginning
	// at startAfter when non-empty. Ordering is what makes cursor-based replay
	// resumable.
	List(ctx context.Context, prefix, startAfter string) ([]ObjectInfo, error)

	// Delete removes a key. Deleting an absent key succeeds, so retention
	// cleanup is idempotent.
	Delete(ctx context.Context, key string) error
}
