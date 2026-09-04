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

package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// artifactServer stands in for both halves of a download: the gateway that
// redirects and the object store that serves the bytes. They are one TLS server
// so the redirect is same-host — which is exactly the case where net/http would
// forward the Authorization header, and so the case worth testing.
type artifactServer struct {
	*httptest.Server

	mu               sync.Mutex
	objectAuthHeader string
	objectRequests   int

	// body is what the object store serves.
	body []byte
	// checksum overrides the reported SHA-256; empty means the real one.
	checksum string
	// omitChecksum drops the header entirely, as an older gateway would.
	omitChecksum bool
	// gatewayStatus, when non-zero, is returned by the gateway instead of a 303.
	gatewayStatus int
	gatewayBody   errorBody
}

func newArtifactServer(t *testing.T, body []byte) *artifactServer {
	t.Helper()
	s := &artifactServer{body: body}

	mux := http.NewServeMux()
	mux.HandleFunc(DownloadPath, func(w http.ResponseWriter, _ *http.Request) {
		if s.gatewayStatus != 0 {
			w.Header().Set("X-Request-ID", "req-1")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(s.gatewayStatus)
			_ = json.NewEncoder(w).Encode(s.gatewayBody)
			return
		}
		sum := sha256.Sum256(s.body)
		checksum := s.checksum
		if checksum == "" {
			checksum = hex.EncodeToString(sum[:])
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Request-ID", "req-1")
		if !s.omitChecksum {
			w.Header().Set(HeaderSHA256, checksum)
		}
		w.Header().Set("Location", s.URL+"/objects/capture.pcapng?X-Amz-Signature=deadbeef")
		w.WriteHeader(http.StatusSeeOther)
	})
	mux.HandleFunc("GET /objects/{name}", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.objectAuthHeader = r.Header.Get("Authorization")
		s.objectRequests++
		s.mu.Unlock()

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(s.body)
	})

	s.Server = httptest.NewTLSServer(mux)
	t.Cleanup(s.Close)
	return s
}

// caFile writes the test server's certificate where NewClient can read it.
func caFile(t *testing.T, s *httptest.Server) string {
	t.Helper()
	// httptest hands back a parsed certificate; the file has to be PEM.
	path := filepath.Join(t.TempDir(), "ca.crt")
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("writing the CA: %v", err)
	}
	return path
}

func newTestClient(t *testing.T, s *artifactServer) *Client {
	t.Helper()
	c, err := NewClient(ClientOptions{BaseURL: s.URL, CAFile: caFile(t, s.Server)})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// The test server's certificate is generated per run and is not TLS 1.3
	// only; trust it through the same pool but allow the handshake the server
	// actually offers.
	c.http.Transport.(*http.Transport).TLSClientConfig.MinVersion = 0
	return c
}

func TestClientDownloadsAndVerifies(t *testing.T) {
	body := []byte("pcapng bytes that must arrive intact")
	s := newArtifactServer(t, body)
	c := newTestClient(t, s)

	var out bytes.Buffer
	n, err := c.Download(t.Context(), analystToken, testNamespace, testJobName, &out)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if n != int64(len(body)) || !bytes.Equal(out.Bytes(), body) {
		t.Errorf("wrote %d bytes, want the %d served", n, len(body))
	}
}

// The reason redirects are followed by hand. net/http forwards Authorization
// across a same-host redirect, and the redirect target is object storage: the
// Kubernetes token would be handed to a service with no business seeing it.
func TestClientNeverSendsTheTokenToObjectStorage(t *testing.T) {
	s := newArtifactServer(t, []byte("bytes"))
	c := newTestClient(t, s)

	// Deliberately not fatal. What this test is about is what the object store
	// saw, and that assertion has to run whether or not the download itself
	// succeeded — otherwise a change that leaks the token fails here for some
	// unrelated reason and the leak goes unexamined.
	if _, err := c.Download(t.Context(), analystToken, testNamespace, testJobName, &bytes.Buffer{}); err != nil {
		t.Errorf("Download: %v", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.objectRequests != 1 {
		t.Errorf("object store saw %d requests, want 1", s.objectRequests)
	}
	if s.objectAuthHeader != "" {
		t.Errorf("object store received an Authorization header: %q", s.objectAuthHeader)
	}
}

// Evidence that does not match its recorded checksum is not evidence. The CLI
// has no other way to know: it never sees the CaptureJob.
func TestClientRejectsAChecksumMismatch(t *testing.T) {
	t.Run("wrong checksum", func(t *testing.T) {
		s := newArtifactServer(t, []byte("bytes"))
		s.checksum = strings.Repeat("11", 32)
		c := newTestClient(t, s)

		if _, err := c.Download(t.Context(), analystToken, testNamespace, testJobName, &bytes.Buffer{}); !errors.Is(err, ErrChecksumMismatch) {
			t.Errorf("error = %v, want ErrChecksumMismatch", err)
		}
	})

	// A gateway too old to send the header must not silently downgrade the CLI
	// to downloading unverified bytes.
	t.Run("no checksum at all", func(t *testing.T) {
		s := newArtifactServer(t, []byte("bytes"))
		s.omitChecksum = true
		c := newTestClient(t, s)

		_, err := c.Download(t.Context(), analystToken, testNamespace, testJobName, &bytes.Buffer{})
		if !errors.Is(err, ErrChecksumMismatch) {
			t.Errorf("error = %v, want ErrChecksumMismatch", err)
		}
	})
}

func TestClientReportsTheGatewaysError(t *testing.T) {
	s := newArtifactServer(t, nil)
	s.gatewayStatus = http.StatusForbidden
	s.gatewayBody = errorBody{Code: CodeForbidden, Message: "the caller may not download this capture", RequestID: "req-1"}
	c := newTestClient(t, s)

	_, err := c.Download(t.Context(), analystToken, testNamespace, testJobName, &bytes.Buffer{})
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v (%T), want *APIError", err, err)
	}
	if apiErr.StatusCode != http.StatusForbidden || apiErr.Code != CodeForbidden {
		t.Errorf("APIError = %+v", apiErr)
	}
	// The request ID is the one string that ties this refusal to the audit
	// ledger and the gateway's logs.
	if apiErr.RequestID != "req-1" {
		t.Errorf("request ID = %q, want req-1", apiErr.RequestID)
	}
	// Nothing was fetched, so nothing was written.
	if s.objectRequests != 0 {
		t.Errorf("fetched the object despite a %d", apiErr.StatusCode)
	}
}

func TestNewClientRefusesAnUnverifiableGateway(t *testing.T) {
	s := newArtifactServer(t, nil)
	ca := caFile(t, s.Server)

	for name, opts := range map[string]ClientOptions{
		"no base URL": {CAFile: ca},
		"no CA":       {BaseURL: s.URL},
		// Plain HTTP would put the bearer token on the wire in clear.
		"plaintext": {BaseURL: "http://gateway.invalid", CAFile: ca},
	} {
		if _, err := NewClient(opts); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Presigned URLs and tokens must not reach an error string the CLI prints.
func TestClientErrorsCarryNoSecret(t *testing.T) {
	s := newArtifactServer(t, nil)
	s.gatewayStatus = http.StatusServiceUnavailable
	s.gatewayBody = errorBody{
		Code:      CodeUnavailable,
		Message:   "https://minio:9000/artifacts/o?X-Amz-Signature=deadbeefcafe",
		RequestID: "req-1",
	}
	c := newTestClient(t, s)

	_, err := c.Download(t.Context(), analystToken, testNamespace, testJobName, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, secret := range []string{"X-Amz-Signature", "deadbeefcafe", analystToken} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error leaked %q: %v", secret, err)
		}
	}
}
