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
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"trawl.cloud/trawl/internal/sanitize"
)

// shutdownGrace bounds the wait for in-flight commits when the listener is
// stopping. A commit the caller is still blocked on should finish; the caller
// fails closed if it does not, so this is short.
const shutdownGrace = 5 * time.Second

// SinkServerOptions configures the mTLS audit listener.
type SinkServerOptions struct {
	// Sink is the ledger commits are written to.
	Sink *Sink

	// ListenAddr is the address to serve on.
	ListenAddr string

	// CertFile and KeyFile are the serving certificate; CAFile is the bundle
	// client certificates are verified against.
	CertFile string
	KeyFile  string
	CAFile   string

	// AllowedIdentities are the client-certificate common names permitted to
	// commit. TLS proves the certificate was issued by the CA; this decides
	// which of the CA's certificates may write history.
	AllowedIdentities []string
}

// SinkServer serves audit commits over mutual TLS.
//
// It exists because ledger credentials live only in the controller manager
// (ADR-0003). Everything else that must record an action - the artifact
// gateway, the event worker, the webhooks when they run out of process -
// reaches the ledger through here or not at all, and FR-036 makes "not at
// all" mean the action does not complete. That makes this listener part of
// the write path for those components rather than an accessory to it.
//
// Both directions are authenticated. The client checks the sink so it cannot
// be induced to report a commit that never reached the ledger, and the sink
// checks the client so a certificate issued by the same CA for some other
// workload cannot forge history.
type SinkServer struct {
	listener net.Listener
	server   *http.Server
}

// NewSinkServer builds the listener from mounted TLS material.
func NewSinkServer(opts SinkServerOptions) (*SinkServer, error) {
	switch {
	case opts.Sink == nil:
		return nil, errors.New("audit sink server requires a sink")
	case opts.ListenAddr == "":
		return nil, errors.New("audit sink server requires a listen address")
	case len(opts.AllowedIdentities) == 0:
		// An empty list authorizes nobody, which is safe but silently breaks
		// every client. Refusing to start says so at rollout instead.
		return nil, errors.New("audit sink server requires at least one allowed client identity")
	}

	reloader, err := newCertReloader(opts.CertFile, opts.KeyFile)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(opts.CAFile)
	if err != nil {
		return nil, sanitize.Errorf("reading the audit sink client CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("the audit sink client CA file contains no usable certificate")
	}

	// Bound here rather than in Start so that a port already in use is a
	// startup failure with a clear cause, rather than something discovered
	// later by a client whose commit fails closed.
	//
	// The context bounds the bind alone, not the listener's life, and binding
	// a local port does not block; the manager's context governs serving.
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", opts.ListenAddr)
	if err != nil {
		return nil, sanitize.Errorf("listening for audit commits: %v", err)
	}

	return &SinkServer{
		listener: ln,
		server: &http.Server{
			Handler: Handler(opts.Sink, opts.AllowedIdentities),
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				// Verified by the TLS layer, then narrowed to the allowed
				// common names by the handler. Requiring the certificate here
				// means an unauthenticated caller never reaches the decoder.
				ClientAuth:     tls.RequireAndVerifyClientCert,
				ClientCAs:      pool,
				GetCertificate: reloader.get,
			},
			ReadHeaderTimeout: clientTimeout,
		},
	}, nil
}

// NeedLeaderElection reports false: every manager replica must serve the sink.
//
// The Service load-balances across replicas, so a listener that only ran on
// the leader would leave a client's commit failing whenever it landed on a
// follower - and a failed commit fails the user's action.
func (s *SinkServer) NeedLeaderElection() bool { return false }

// Addr is the address the sink is bound to, resolved: asking for :0 gives a
// port here.
func (s *SinkServer) Addr() net.Addr { return s.listener.Addr() }

// Start serves until ctx is cancelled.
func (s *SinkServer) Start(ctx context.Context) error {
	errs := make(chan error, 1)
	go func() {
		// The certificate and key come from TLSConfig.GetCertificate.
		errs <- s.server.ServeTLS(s.listener, "", "")
	}()

	select {
	case err := <-errs:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return sanitize.Errorf("serving audit commits: %v", err)
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
		defer cancel()
		if err := s.server.Shutdown(shutdown); err != nil {
			return sanitize.Errorf("stopping the audit sink listener: %v", err)
		}
		return nil
	}
}

// certReloader serves the current serving certificate from disk.
//
// cert-manager rewrites the mounted Secret when it renews, and a listener
// holding the certificate it loaded at startup would keep presenting an
// expired one until the pod happened to restart. Since every client fails
// closed when the sink is unreachable, that is an outage of the write path
// rather than a degraded feature, so the files are re-read when they change.
type certReloader struct {
	certFile string
	keyFile  string

	mu       sync.Mutex
	cert     *tls.Certificate
	loadedAt [2]time.Time
}

func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile}
	// Load once here so a missing or malformed certificate fails at startup
	// rather than on the first commit somebody's mutation is waiting on.
	if _, err := r.get(nil); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	stamps := r.modTimes()
	if r.cert != nil && stamps == r.loadedAt {
		return r.cert, nil
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		if r.cert != nil {
			// A renewal writes two files and is not atomic across them, so a
			// handshake can land mid-rotation. The previous certificate is
			// still valid for a while; using it beats refusing the commit.
			return r.cert, nil
		}
		return nil, sanitize.Errorf("loading the audit sink certificate: %v", err)
	}
	r.cert, r.loadedAt = &cert, stamps
	return r.cert, nil
}

func (r *certReloader) modTimes() [2]time.Time {
	var out [2]time.Time
	for i, name := range []string{r.certFile, r.keyFile} {
		if fi, err := os.Stat(name); err == nil {
			out[i] = fi.ModTime()
		}
	}
	return out
}
