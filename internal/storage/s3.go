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
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"trawl.cloud/trawl/internal/config"
	"trawl.cloud/trawl/internal/sanitize"
)

// Credential file names inside a mounted secret directory. Credentials are read
// from the filesystem, never from configuration or environment, so they stay
// inside the cluster's secret boundary.
const (
	accessKeyFile = "accessKeyID"
	secretKeyFile = "secretAccessKey"
)

// defaultTimeout bounds every object-store call. Without it a hung MinIO would
// stall a reconciler indefinitely, which turns a storage outage into a control
// plane outage.
const defaultTimeout = 30 * time.Second

// S3Store is a Store backed by a MinIO/S3-compatible bucket.
//
// One instance addresses exactly one bucket with one credential. The artifact
// bucket and the audit ledger get separate instances with separate credentials,
// which is what stops the artifact path from being able to rewrite the audit
// trail (ADR-0003).
type S3Store struct {
	client  *minio.Client
	bucket  string
	timeout time.Duration
}

// NewS3Store connects to the bucket described by cfg, reading credentials from
// the mounted secret directory.
func NewS3Store(cfg config.BucketConfig) (*S3Store, error) {
	accessKey, err := readCredential(cfg.CredentialsPath, accessKeyFile)
	if err != nil {
		return nil, err
	}
	secretKey, err := readCredential(cfg.CredentialsPath, secretKeyFile)
	if err != nil {
		return nil, err
	}

	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: cfg.UseTLS,
		Region: cfg.Region,
	})
	if err != nil {
		// A MinIO construction error can echo the endpoint, which may carry
		// embedded credentials.
		return nil, sanitize.Errorf("creating object store client: %v", err)
	}
	return &S3Store{client: client, bucket: cfg.Bucket, timeout: defaultTimeout}, nil
}

// readCredential loads one credential file from a mounted secret directory.
//
// Errors name the file, never its contents.
func readCredential(dir, name string) (string, error) {
	if dir == "" {
		return "", errors.New("credentials path is not configured")
	}
	// gosec G304: the directory is installation configuration and the file name
	// is a package constant, so no caller-controlled path reaches this.
	data, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec
	if err != nil {
		return "", sanitize.Errorf("reading credential %s: %v", name, err)
	}
	value := strings.TrimSpace(string(data))
	if value == "" {
		return "", sanitize.Errorf("credential %s is empty", name)
	}
	return value, nil
}

// Put implements Store.
//
// IfNotExists maps to the S3 conditional-write precondition, which is what makes
// the audit ledger's stable key an idempotency guarantee rather than a
// convention. RetainUntil maps to object-lock retention, enforced by the backend
// rather than by Trawl choosing not to delete.
func (s *S3Store) Put(ctx context.Context, key string, body []byte, opts PutOptions) (ObjectInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	putOpts := minio.PutObjectOptions{
		ContentType:  opts.ContentType,
		UserMetadata: opts.Metadata,
	}
	if !opts.RetainUntil.IsZero() {
		// Compliance mode: not even the bucket owner can shorten it. The audit
		// ledger's value depends on being unrewritable by whoever compromised
		// the thing it is recording.
		putOpts.Mode = minio.Compliance
		putOpts.RetainUntilDate = opts.RetainUntil.UTC()
	}
	if opts.IfNotExists {
		putOpts.SetMatchETagExcept("*")
	}

	info, err := s.client.PutObject(ctx, s.bucket, key, bytes.NewReader(body), int64(len(body)), putOpts)
	if err != nil {
		if isPreconditionFailed(err) {
			return ObjectInfo{}, ErrAlreadyExists
		}
		return ObjectInfo{}, sanitize.Errorf("writing object: %v", err)
	}
	return ObjectInfo{
		Key:          info.Key,
		Size:         info.Size,
		ETag:         info.ETag,
		LastModified: info.LastModified,
		RetainUntil:  opts.RetainUntil,
		Metadata:     opts.Metadata,
	}, nil
}

// Head implements Store.
func (s *S3Store) Head(ctx context.Context, key string) (ObjectInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	stat, err := s.client.StatObject(ctx, s.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		if isNotFound(err) {
			return ObjectInfo{}, ErrNotFound
		}
		return ObjectInfo{}, sanitize.Errorf("reading object metadata: %v", err)
	}
	info := objectInfoFrom(stat)

	// Retention lives on the object lock, not in StatObject's metadata. It is
	// read separately so callers can verify that write-once protection was
	// actually applied rather than assume the request took effect.
	if _, until, err := s.client.GetObjectRetention(ctx, s.bucket, key, ""); err == nil && until != nil {
		info.RetainUntil = *until
	}
	return info, nil
}

// Get implements Store.
func (s *S3Store) Get(ctx context.Context, key string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		if isNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, sanitize.Errorf("reading object: %v", err)
	}
	defer func() { _ = obj.Close() }()

	data, err := io.ReadAll(obj)
	if err != nil {
		if isNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, sanitize.Errorf("reading object body: %v", err)
	}
	return data, nil
}

// List implements Store, returning objects in lexicographic key order.
//
// S3's start-after is exclusive and this contract is inclusive, so the cursor's
// own object is fetched separately and prepended. That mismatch is not a detail
// to leave to the reader: passing the cursor straight through, which is what
// this did, silently skips one record per resume, and Sink.Replay's whole
// argument is that a skipped record is permanently invisible in search.
func (s *S3Store) List(ctx context.Context, prefix, startAt string) ([]ObjectInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	var out []ObjectInfo
	if startAt != "" && strings.HasPrefix(startAt, prefix) {
		switch info, err := s.Head(ctx, startAt); {
		case err == nil:
			// Reduced to the fields a listing guarantees, so one element of the
			// result is not quietly richer than the rest.
			out = append(out, ObjectInfo{
				Key:          info.Key,
				Size:         info.Size,
				ETag:         info.ETag,
				LastModified: info.LastModified,
			})
		case errors.Is(err, ErrNotFound):
			// The cursor object is gone; retention may have removed it since the
			// caller last saw the key. Listing resumes at the next one.
		default:
			return nil, err
		}
	}
	for obj := range s.client.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{
		Prefix:     prefix,
		StartAfter: startAt,
		Recursive:  true,
	}) {
		if obj.Err != nil {
			return nil, sanitize.Errorf("listing objects: %v", obj.Err)
		}
		out = append(out, ObjectInfo{
			Key:          obj.Key,
			Size:         obj.Size,
			ETag:         obj.ETag,
			LastModified: obj.LastModified,
		})
	}
	return out, nil
}

// Delete implements Store. Deleting an absent key succeeds, so retention
// cleanup converges when retried after a partial failure.
func (s *S3Store) Delete(ctx context.Context, key string) error {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	if err := s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{}); err != nil {
		if isNotFound(err) {
			return nil
		}
		return sanitize.Errorf("deleting object: %v", err)
	}
	return nil
}

func objectInfoFrom(stat minio.ObjectInfo) ObjectInfo {
	info := ObjectInfo{
		Key:          stat.Key,
		Size:         stat.Size,
		ETag:         stat.ETag,
		LastModified: stat.LastModified,
		Metadata:     make(map[string]string, len(stat.UserMetadata)),
	}
	// StatObject hands back x-amz-meta-* keys canonicalised, so "sha256" written
	// comes back "Sha256". The contract says lowercase; without this a caller
	// that reads info.Metadata["sha256"] works against the Fake and finds
	// nothing against a real bucket.
	for k, v := range stat.UserMetadata {
		info.Metadata[strings.ToLower(k)] = v
	}
	return info
}

// isNotFound recognises the several shapes MinIO uses for a missing object.
func isNotFound(err error) bool {
	if errors.Is(err, ErrNotFound) {
		return true
	}
	resp := minio.ToErrorResponse(err)
	switch resp.Code {
	case "NoSuchKey", "NoSuchBucket", "NotFound":
		return true
	}
	return resp.StatusCode == 404
}

// isPreconditionFailed recognises a failed conditional write, which for the
// audit ledger means the stable key is already taken.
func isPreconditionFailed(err error) bool {
	resp := minio.ToErrorResponse(err)
	if resp.Code == "PreconditionFailed" {
		return true
	}
	return resp.StatusCode == 412
}
