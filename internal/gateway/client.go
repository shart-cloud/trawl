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
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"trawl.cloud/trawl/internal/sanitize"
)

// clientTimeout bounds the whole download, redirect included. A capture can be
// a gibibyte, so this is generous where the audit client's ten seconds is not.
const clientTimeout = 30 * time.Minute

// APIError is a gateway error response, as the CLI should report it.
//
// It carries the request ID because that is the one string an operator can take
// to the audit ledger and the gateway's logs and find this exact request in
// both.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
	RequestID  string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s: %s (request %s)", e.Code, e.Message, e.RequestID)
}

// ErrChecksumMismatch means the downloaded bytes are not the artifact the
// controller verified.
var ErrChecksumMismatch = errors.New("downloaded artifact does not match its recorded checksum")

// ClientOptions configures a Client.
type ClientOptions struct {
	// BaseURL is the gateway, e.g. https://127.0.0.1:8443
	BaseURL string

	// CAFile is the PEM bundle the gateway's serving certificate is verified
	// against. Required: the response to this request is a credential for the
	// packet capture, so an unverified server is an unacceptable one.
	CAFile string
}

// Client downloads capture artifacts through the gateway.
//
// It is the supported CLI's transport, and it exists as a package rather than
// inside cmd/trawlctl so the redirect handling can be tested against a real
// HTTP server without building a binary.
type Client struct {
	baseURL *url.URL
	http    *http.Client
}

// NewClient builds a Client that trusts only the CA in opts.
func NewClient(opts ClientOptions) (*Client, error) {
	if strings.TrimSpace(opts.BaseURL) == "" {
		return nil, errors.New("gateway client requires a base URL")
	}
	base, err := url.Parse(opts.BaseURL)
	if err != nil {
		return nil, sanitize.Errorf("parsing the gateway URL: %v", err)
	}
	if base.Scheme != "https" {
		return nil, errors.New("gateway client requires an https URL")
	}
	if strings.TrimSpace(opts.CAFile) == "" {
		return nil, errors.New("gateway client requires a CA bundle")
	}

	//nolint:gosec // CAFile is an operator-supplied flag on this process's own command line
	caPEM, err := os.ReadFile(opts.CAFile)
	if err != nil {
		return nil, sanitize.Errorf("reading the gateway CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("gateway CA file contains no usable certificate")
	}

	return &Client{
		baseURL: base,
		http: &http.Client{
			Timeout: clientTimeout,
			// Redirects are followed by hand. net/http would forward the
			// Authorization header to the redirect target on a same-host
			// redirect, and the redirect target is object storage: the
			// Kubernetes token would be handed to a service that has no
			// business seeing it and may well log it.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13},
			},
		},
	}, nil
}

// Download writes the artifact for namespace/name into out and returns the
// number of bytes written.
//
// The checksum the gateway reports is verified against the bytes as they are
// written, so a truncated or substituted object fails here rather than at the
// analyst's desk. token is sent to the gateway and to nothing else.
func (c *Client) Download(ctx context.Context, token, namespace, name string, out io.Writer) (int64, error) {
	target := c.baseURL.JoinPath("api", "v1", "namespaces", namespace, "capturejobs", name, "download")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return 0, sanitize.Errorf("building the download request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, sanitize.Errorf("calling the gateway: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusSeeOther {
		return 0, apiErrorFrom(resp)
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return 0, errors.New("gateway redirected without a location")
	}
	want := resp.Header.Get(HeaderSHA256)

	// A fresh request, deliberately built from nothing the first one carried.
	// This is the line that keeps the bearer token away from object storage.
	objectReq, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		// The location is a presigned URL, so its parse error carries the
		// signature.
		return 0, sanitize.Errorf("building the artifact request: %v", err)
	}

	objectResp, err := c.http.Do(objectReq)
	if err != nil {
		return 0, sanitize.Errorf("fetching the artifact: %v", err)
	}
	defer func() { _ = objectResp.Body.Close() }()

	if objectResp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("artifact storage returned status %d", objectResp.StatusCode)
	}

	digest := sha256.New()
	written, err := io.Copy(out, io.TeeReader(objectResp.Body, digest))
	if err != nil {
		return written, sanitize.Errorf("writing the artifact: %v", err)
	}

	// An empty checksum is a gateway that did not send one, which means a
	// version mismatch. Downloading unverified evidence is not a safe default.
	if want == "" {
		return written, fmt.Errorf("gateway did not report a checksum: %w", ErrChecksumMismatch)
	}
	if got := hex.EncodeToString(digest.Sum(nil)); !strings.EqualFold(got, want) {
		return written, fmt.Errorf("%w: got %s, want %s", ErrChecksumMismatch, got, want)
	}
	return written, nil
}

// apiErrorFrom decodes a gateway error response.
//
// A body that is not the contract's error shape still produces an APIError:
// something answered on the gateway's port and the caller needs the status,
// which is more use than a decoding complaint.
func apiErrorFrom(resp *http.Response) error {
	apiErr := &APIError{
		StatusCode: resp.StatusCode,
		Code:       CodeUnavailable,
		Message:    fmt.Sprintf("gateway returned status %d", resp.StatusCode),
		RequestID:  resp.Header.Get("X-Request-ID"),
	}

	var body errorBody
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxErrorBodyBytes)).Decode(&body); err == nil && body.Code != "" {
		apiErr.Code = body.Code
		apiErr.Message = sanitize.String(body.Message)
		if body.RequestID != "" {
			apiErr.RequestID = body.RequestID
		}
	}
	return apiErr
}

// maxErrorBodyBytes bounds a gateway error body. The contract caps the message
// at 512 bytes; anything much larger is not the contract's response.
const maxErrorBodyBytes = 8 << 10
