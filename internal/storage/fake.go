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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Fake is an in-memory Store for unit tests.
//
// It exists so audit and capture logic can be tested against the conditional
// creation, verification, and ordering semantics they actually depend on,
// without a container. It is not a substitute for the real MinIO integration
// tests, which are what prove those semantics match the backend.
//
// It deliberately models the properties that matter for correctness:
// conditional creation, key ordering, retention deadlines, and the ability to
// simulate a write that reports success but does not persist.
type Fake struct {
	mu sync.Mutex

	objects map[string]fakeObject
	order   []string

	putCounts   map[string]int
	headCounts  map[string]int
	conditional map[string]bool

	putErr       error
	headErr      error
	deleteErr    error
	swallow      bool
	swallowDels  bool
	deleteCounts map[string]int
	clock        func() time.Time
	seq          int
}

type fakeObject struct {
	body        []byte
	info        ObjectInfo
	retainUntil time.Time
}

// NewFake returns an empty in-memory store.
func NewFake() *Fake {
	start := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	f := &Fake{
		objects:      make(map[string]fakeObject),
		putCounts:    make(map[string]int),
		headCounts:   make(map[string]int),
		deleteCounts: make(map[string]int),
		conditional:  make(map[string]bool),
	}
	f.clock = func() time.Time {
		f.seq++
		// Distinct, increasing timestamps so ordering assertions are stable.
		return start.Add(time.Duration(f.seq) * time.Second)
	}
	return f
}

// FailPut makes every subsequent Put return err, simulating an unavailable
// ledger.
func (f *Fake) FailPut(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.putErr = err
}

// FailHead makes every subsequent Head return err, simulating a backend that
// is reachable for neither verification nor listing.
//
// Distinct from an absent object: ErrNotFound is an answer, and this is the
// absence of one. A caller that cannot tell them apart reports an outage as a
// deleted artifact.
func (f *Fake) FailHead(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.headErr = err
}

// FailDelete makes every subsequent Delete return err, simulating a backend
// that will not accept the removal. Retention must keep the artifact out of
// reach and try again rather than report an expiry it did not perform.
func (f *Fake) FailDelete(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleteErr = err
}

// SwallowDeletes makes Delete report success while leaving the object in
// place, simulating a backend that acknowledges a removal it did not perform.
//
// This is the only reason verifying absence with Head after a delete is worth
// anything: against a store that always tells the truth, the check cannot
// fail, so a test using one proves the check is present and nothing about
// whether it works.
func (f *Fake) SwallowDeletes(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.swallowDels = v
}

// SwallowPuts makes Put report success without persisting, simulating a backend
// that acknowledges a write it did not durably store.
func (f *Fake) SwallowPuts(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.swallow = v
}

// Put implements Store.
func (f *Fake) Put(_ context.Context, key string, body []byte, opts PutOptions) (ObjectInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.putCounts[key]++
	f.conditional[key] = opts.IfNotExists

	if f.putErr != nil {
		return ObjectInfo{}, f.putErr
	}
	if opts.IfNotExists {
		if _, exists := f.objects[key]; exists {
			return ObjectInfo{}, ErrAlreadyExists
		}
	}
	sum := sha256.Sum256(body)
	info := ObjectInfo{
		Key:          key,
		Size:         int64(len(body)),
		ETag:         hex.EncodeToString(sum[:]),
		LastModified: f.clock(),
		RetainUntil:  opts.RetainUntil,
		Metadata:     lowerKeys(opts.Metadata),
	}
	if f.swallow {
		// Report success but persist nothing.
		return info, nil
	}
	if _, exists := f.objects[key]; !exists {
		f.order = append(f.order, key)
	}
	f.objects[key] = fakeObject{body: append([]byte(nil), body...), info: info, retainUntil: opts.RetainUntil}
	return info, nil
}

// PutStream implements Store by buffering the body; the Fake exists for
// tests, where bodies are small.
func (f *Fake) PutStream(ctx context.Context, key string, body io.Reader, size int64, opts PutOptions) (ObjectInfo, error) {
	buf, err := io.ReadAll(io.LimitReader(body, size+1))
	if err != nil {
		return ObjectInfo{}, err
	}
	if int64(len(buf)) != size {
		return ObjectInfo{}, errors.New("body length does not match size")
	}
	return f.Put(ctx, key, buf, opts)
}

// Head implements Store.
func (f *Fake) Head(_ context.Context, key string) (ObjectInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.headCounts[key]++
	if f.headErr != nil {
		return ObjectInfo{}, f.headErr
	}
	obj, ok := f.objects[key]
	if !ok {
		return ObjectInfo{}, ErrNotFound
	}
	return obj.info, nil
}

// Get implements Store.
func (f *Fake) Get(_ context.Context, key string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	obj, ok := f.objects[key]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), obj.body...), nil
}

// List implements Store, returning keys in lexicographic order.
func (f *Fake) List(_ context.Context, prefix, startAt string) ([]ObjectInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	keys := make([]string, 0, len(f.objects))
	for k := range f.objects {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	out := make([]ObjectInfo, 0, len(keys))
	for _, k := range keys {
		if prefix != "" && !hasPrefix(k, prefix) {
			continue
		}
		if startAt != "" && k < startAt {
			continue
		}
		out = append(out, f.objects[k].info)
	}
	return out, nil
}

// Delete implements Store. Deleting an absent key succeeds.
func (f *Fake) Delete(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.deleteCounts[key]++
	if f.deleteErr != nil {
		return f.deleteErr
	}
	if f.swallowDels {
		return nil
	}
	delete(f.objects, key)
	for i, k := range f.order {
		if k == key {
			f.order = append(f.order[:i], f.order[i+1:]...)
			break
		}
	}
	return nil
}

// DeleteCount reports how many times key was asked to be removed.
func (f *Fake) DeleteCount(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deleteCounts[key]
}

// Object returns a stored body, or nil.
func (f *Fake) Object(key string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.objects[key].body
}

// ObjectCount returns how many objects are stored.
func (f *Fake) ObjectCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.objects)
}

// PutCount returns how many Put calls targeted key.
func (f *Fake) PutCount(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.putCounts[key]
}

// HeadCount returns how many Head calls targeted key.
func (f *Fake) HeadCount(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.headCounts[key]
}

// WasConditional reports whether the last Put for key was conditional.
func (f *Fake) WasConditional(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.conditional[key]
}

// RetainUntil returns the retention deadline recorded for key.
func (f *Fake) RetainUntil(key string) (time.Time, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj, ok := f.objects[key]
	if !ok || obj.retainUntil.IsZero() {
		return time.Time{}, false
	}
	return obj.retainUntil, true
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// lowerKeys normalises metadata keys the way a real backend does.
//
// S3 metadata keys are case-insensitive and come back canonicalised, so the
// Fake lowercases too rather than round-tripping whatever spelling the caller
// used - a fidelity the contract states and storagetest asserts.
func lowerKeys(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[strings.ToLower(k)] = v
	}
	return out
}

// FakePresigner is an in-memory Presigner for handler tests.
//
// It records the lifetime it was asked for so a test can assert the caller's
// clamp against the retention deadline, and it applies the same MaxPresignTTL
// ceiling the real one does — a fake that minted longer-lived URLs than the
// backend would let a TTL bug pass.
type FakePresigner struct {
	mu sync.Mutex

	// Err, when set, is returned instead of a URL.
	Err error

	// Base is the URL the signature is appended to. Empty means a default.
	Base string

	calls []PresignCall
}

// PresignCall is one recorded PresignGet.
type PresignCall struct {
	Key string
	TTL time.Duration
}

// PresignGet implements Presigner.
func (f *FakePresigner) PresignGet(_ context.Context, key string, ttl time.Duration) (*url.URL, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls = append(f.calls, PresignCall{Key: key, TTL: ttl})
	if f.Err != nil {
		return nil, f.Err
	}
	if ttl <= 0 {
		return nil, ErrPresignExpired
	}
	if ttl > MaxPresignTTL {
		ttl = MaxPresignTTL
	}

	base := f.Base
	if base == "" {
		base = "https://objects.invalid/artifacts"
	}
	u, err := url.Parse(base + "/" + key)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	// Named like the real thing so a test asserting no signature leaks into a
	// log or an error body is testing against the string it would really see.
	q.Set("X-Amz-Expires", strconv.Itoa(int(ttl.Seconds())))
	q.Set("X-Amz-Signature", "fake-signature")
	u.RawQuery = q.Encode()
	return u, nil
}

// Calls returns the presign requests made so far, in order.
func (f *FakePresigner) Calls() []PresignCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}
