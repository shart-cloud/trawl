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

// Package harness starts the real service dependencies Trawl's integration
// tests need: MinIO with separate artifact and audit-ledger buckets, an mTLS
// audit sink, and process lifecycle helpers.
//
// Constitution V is explicit that analyzer ingestion, artifact storage,
// authorization, and retention must be tested across their actual process or
// service boundaries. The behaviors these tests depend on — conditional writes,
// object-lock retention, precondition failures, listing order — are backend
// semantics. A fake can model what we believe they are; only the real service
// tells us whether we believed correctly.
//
// Everything here is opt-in. Tests call RequireMinIO, which skips when Docker is
// unavailable, so `go test ./...` stays runnable on a machine without it.
package harness

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"trawl.cloud/trawl/internal/config"
	"trawl.cloud/trawl/internal/storage"
)

const (
	// minioImage is digest-pinned like every other image Trawl runs, so a test
	// run is reproducible and an upstream retag cannot change what CI verified.
	// This source-built release includes the October 2025 MinIO security fix.
	minioImage = "ghcr.io/coollabsio/minio@sha256:69b55a1c1c5dc285ce04db96689f5b2102317fc77a50680a1874ca6efd1c87f9"

	minioAccessKey = "trawltestaccess"
	minioSecretKey = "trawltestsecret0" //nolint:gosec // fixed credential for an ephemeral test container

	// AccessKey and SecretKey are the same values, exported so a test can
	// assert that neither ever appears in a log line or a status field.
	AccessKey = minioAccessKey
	SecretKey = minioSecretKey

	startupTimeout = 90 * time.Second
	pollInterval   = 500 * time.Millisecond
)

// MinIO is a running MinIO container with Trawl's two buckets provisioned.
type MinIO struct {
	Endpoint string

	// ArtifactBucket and AuditBucket are separate, with separate credential
	// directories, mirroring the production separation in ADR-0003. A test that
	// shares them would not catch a regression that collapses the two.
	ArtifactBucket string
	AuditBucket    string

	ArtifactCredsDir string
	AuditCredsDir    string

	containerID string
}

// RequireMinIO starts MinIO for one test, skipping when Docker is unavailable.
//
// Skipping rather than failing keeps the unit suite usable on a developer
// machine without Docker; CI runs these in a job that has it, so coverage is
// not silently lost.
func RequireMinIO(t *testing.T) *MinIO {
	t.Helper()
	requireDocker(t)

	port, err := freePort(t.Context())
	if err != nil {
		t.Fatalf("finding a free port: %v", err)
	}
	endpoint := fmt.Sprintf("127.0.0.1:%d", port)

	// Object-lock is enabled at container start: retention is a bucket-creation
	// property, and the audit ledger's write-once guarantee depends on it.
	// A clean runner prints image-pull progress to stderr; stdout must contain
	// only the container ID used by subsequent docker commands.
	out, err := exec.CommandContext(t.Context(), "docker", "run", "--detach", "--rm",
		"--publish", fmt.Sprintf("%d:9000", port),
		"--env", "MINIO_ROOT_USER="+minioAccessKey,
		"--env", "MINIO_ROOT_PASSWORD="+minioSecretKey,
		minioImage, "server", "/data",
	).Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("starting MinIO: %v: %s", err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		t.Fatalf("starting MinIO: %v", err)
	}
	containerID := strings.TrimSpace(string(out))

	m := &MinIO{
		Endpoint:       endpoint,
		ArtifactBucket: "trawl-artifacts",
		AuditBucket:    "trawl-audit",
		containerID:    containerID,
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := exec.CommandContext(stopCtx, "docker", "stop", containerID).Run(); err != nil {
			t.Logf("stopping MinIO container %s: %v", containerID, err)
		}
	})

	m.ArtifactCredsDir = writeCredentials(t, "artifacts")
	m.AuditCredsDir = writeCredentials(t, "audit")

	if err := m.waitReady(t.Context()); err != nil {
		t.Fatalf("waiting for MinIO: %v", err)
	}
	m.createBuckets(t)
	return m
}

// ArtifactStore returns a Store for the artifact bucket.
func (m *MinIO) ArtifactStore(t *testing.T) storage.Store {
	t.Helper()
	return m.storeFor(t, m.ArtifactBucket, m.ArtifactCredsDir)
}

// AuditStore returns a Store for the audit-ledger bucket.
func (m *MinIO) AuditStore(t *testing.T) *storage.S3Store {
	t.Helper()
	return m.storeFor(t, m.AuditBucket, m.AuditCredsDir)
}

func (m *MinIO) storeFor(t *testing.T, bucket, credsDir string) *storage.S3Store {
	t.Helper()
	store, err := storage.NewS3Store(config.BucketConfig{
		Endpoint:        m.Endpoint,
		Bucket:          bucket,
		CredentialsPath: credsDir,
		UseTLS:          false,
	})
	if err != nil {
		t.Fatalf("creating store for bucket %s: %v", bucket, err)
	}
	return store
}

// waitReady polls the MinIO health endpoint until it responds.
func (m *MinIO) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(startupTimeout)
	client := &http.Client{Timeout: 2 * time.Second}
	url := "http://" + m.Endpoint + "/minio/health/live"
	var lastErr error
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			if closeErr := resp.Body.Close(); closeErr != nil {
				lastErr = fmt.Errorf("closing MinIO health response: %w", closeErr)
			} else if resp.StatusCode == http.StatusOK {
				return nil
			} else {
				lastErr = fmt.Errorf("MinIO health returned HTTP %d", resp.StatusCode)
			}
		} else {
			lastErr = err
		}
		time.Sleep(pollInterval)
	}
	return fmt.Errorf("MinIO did not become ready within %s: %w", startupTimeout, lastErr)
}

// createBuckets provisions both buckets, enabling object-lock on the audit
// ledger so its write-once retention is enforced by the backend.
func (m *MinIO) createBuckets(t *testing.T) {
	t.Helper()

	alias := "local"
	m.mc(t, "alias", "set", alias,
		"http://127.0.0.1:9000", minioAccessKey, minioSecretKey)
	m.mc(t, "mb", alias+"/"+m.ArtifactBucket)
	m.mc(t, "mb", "--with-lock", alias+"/"+m.AuditBucket)
}

// mc runs a MinIO client command inside the container.
func (m *MinIO) mc(t *testing.T, args ...string) {
	t.Helper()
	full := append([]string{"exec", m.containerID, "mc"}, args...)
	cmd := exec.CommandContext(t.Context(), "docker", full...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("mc %s: %v: %s", strings.Join(args, " "), err, stderr.String())
	}
}

// writeCredentials materializes a credential directory in the shape the
// production code expects: files in a mounted secret directory, never
// environment variables.
func writeCredentials(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	for file, value := range map[string]string{
		"accessKeyID":     minioAccessKey,
		"secretAccessKey": minioSecretKey,
	} {
		if err := os.WriteFile(dir+"/"+file, []byte(value), 0o600); err != nil {
			t.Fatalf("writing %s credential %s: %v", name, file, err)
		}
	}
	return dir
}

// requireDocker skips the test when Docker is not usable.
func requireDocker(t *testing.T) {
	t.Helper()
	if os.Getenv("TRAWL_SKIP_CONTAINER_TESTS") != "" {
		t.Skip("TRAWL_SKIP_CONTAINER_TESTS is set")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed; skipping container integration test")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "info").Run(); err != nil {
		t.Skip("docker daemon is not available; skipping container integration test")
	}
}

// freePort asks the kernel for an unused port.
func freePort(ctx context.Context) (int, error) {
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		return 0, errors.New("unexpected listener address type")
	}
	return addr.Port, nil
}
