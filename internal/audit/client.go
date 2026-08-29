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

package audit

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"time"

	"trawl.cloud/trawl/internal/sanitize"
)

// SinkPath is the endpoint the controller manager exposes for audit commits.
const SinkPath = "/audit/v1/commit"

// clientTimeout bounds a commit attempt.
//
// It is deliberately short. A user mutation blocks on this call, so a hung sink
// must surface as a fast, actionable failure rather than an admission timeout
// the operator has to diagnose from the API server side.
const clientTimeout = 10 * time.Second

// ClientOptions configures the mTLS audit client.
type ClientOptions struct {
	// Endpoint is the sink base URL, e.g. https://trawl-audit.trawl-system.svc:8443
	Endpoint string

	// Mutual TLS material. The client authenticates the sink and the sink
	// authenticates the client; the sink's allowed identities come from
	// installation config.
	CAFile     string
	CertFile   string
	KeyFile    string
	ServerName string
}

// Client commits audit records to the sink over mTLS.
//
// Admission webhooks, controllers, the event worker, and the artifact gateway
// all use this rather than writing to the ledger directly. Concentrating ledger
// credentials in the controller manager means a compromised gateway or worker
// cannot write arbitrary history.
type Client struct {
	endpoint string
	http     *http.Client
}

// NewClient builds a client from mounted mTLS material.
func NewClient(opts ClientOptions) (*Client, error) {
	if opts.Endpoint == "" {
		return nil, errors.New("audit client requires an endpoint")
	}
	cert, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
	if err != nil {
		return nil, sanitize.Errorf("loading audit client certificate: %v", err)
	}
	caPEM, err := os.ReadFile(opts.CAFile)
	if err != nil {
		return nil, sanitize.Errorf("reading audit CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("audit CA file contains no usable certificate")
	}

	return &Client{
		endpoint: opts.Endpoint,
		http: &http.Client{
			Timeout: clientTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					Certificates: []tls.Certificate{cert},
					RootCAs:      pool,
					ServerName:   opts.ServerName,
					MinVersion:   tls.VersionTLS13,
				},
			},
		},
	}, nil
}

// Commit submits rec and returns only after the sink confirms a durable,
// verified ledger write.
//
// A non-nil error means the caller must fail closed: the action it describes
// must not be reported as complete (FR-036).
func (c *Client) Commit(ctx context.Context, rec Record) (CommitResult, error) {
	body, err := json.Marshal(rec.Sanitized())
	if err != nil {
		return CommitResult{Result: ResultConflict}, sanitize.Errorf("encoding audit record: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+SinkPath, bytes.NewReader(body))
	if err != nil {
		return CommitResult{Result: ResultUnavailable}, sanitize.Errorf("building audit request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return CommitResult{Result: ResultUnavailable}, sanitize.Errorf("submitting audit record: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		var out CommitResult
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return CommitResult{Result: ResultUnavailable}, sanitize.Errorf("decoding audit response: %v", err)
		}
		if !slices.Contains([]string{ResultSuccess, ResultRetry}, out.Result) {
			return out, fmt.Errorf("audit sink returned result %q", sanitize.String(out.Result))
		}
		return out, nil

	case http.StatusConflict:
		return CommitResult{Result: ResultConflict}, errConflict

	default:
		// The body may echo a dependency error, so only the status is reported.
		return CommitResult{Result: ResultUnavailable},
			fmt.Errorf("audit sink returned status %d", resp.StatusCode)
	}
}

// Handler serves commits for a Sink over the mTLS listener.
//
// Client identity is verified by the TLS layer; this handler additionally checks
// the presented certificate's common name against the allowed identity list, so
// a certificate issued by the same CA for a different workload cannot write
// audit history.
func Handler(sink *Sink, allowedIdentities []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !authorizedClient(r, allowedIdentities) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		var rec Record
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRecordBytes)).Decode(&rec); err != nil {
			http.Error(w, "invalid audit record", http.StatusBadRequest)
			return
		}

		res, err := sink.Commit(r.Context(), rec)
		switch {
		case errors.Is(err, errConflict):
			writeJSON(w, http.StatusConflict, res)
		case err != nil:
			// The sink's error may name a dependency endpoint; the caller only
			// needs to know it must fail closed.
			writeJSON(w, http.StatusServiceUnavailable, CommitResult{Result: ResultUnavailable})
		default:
			writeJSON(w, http.StatusOK, res)
		}
	})
}

// maxRecordBytes bounds a submitted record. Audit records are small and
// structured; anything larger is a bug or an attempt to use the ledger as
// storage.
const maxRecordBytes = 64 << 10

func authorizedClient(r *http.Request, allowed []string) bool {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return false
	}
	cn := r.TLS.PeerCertificates[0].Subject.CommonName
	return slices.Contains(allowed, cn)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
