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

// Package tlsutil holds TLS plumbing shared by Trawl's own listeners.
package tlsutil

import (
	"crypto/tls"
	"os"
	"sync"
	"time"

	"trawl.cloud/trawl/internal/sanitize"
)

// CertReloader serves the current serving certificate from disk.
//
// cert-manager rewrites the mounted Secret when it renews, and a listener
// holding the certificate it loaded at startup would keep presenting an expired
// one until the pod happened to restart. For both listeners that use this — the
// audit sink and the artifact gateway — clients fail closed when the listener
// is unreachable, so that is an outage rather than a degraded feature. The
// files are re-read when they change.
type CertReloader struct {
	name     string
	certFile string
	keyFile  string

	mu       sync.Mutex
	cert     *tls.Certificate
	loadedAt [2]time.Time
}

// NewCertReloader returns a reloader for the pair, loading it once so a missing
// or malformed certificate fails at startup rather than on the first request
// somebody is waiting on. name appears in errors and must not be a secret.
func NewCertReloader(name, certFile, keyFile string) (*CertReloader, error) {
	r := &CertReloader{name: name, certFile: certFile, keyFile: keyFile}
	if _, err := r.GetCertificate(nil); err != nil {
		return nil, err
	}
	return r, nil
}

// GetCertificate satisfies tls.Config's callback of the same name.
func (r *CertReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
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
			// still valid for a while; using it beats refusing the request.
			return r.cert, nil
		}
		return nil, sanitize.Errorf("loading the %s certificate: %v", r.name, err)
	}
	r.cert, r.loadedAt = &cert, stamps
	return r.cert, nil
}

func (r *CertReloader) modTimes() [2]time.Time {
	var out [2]time.Time
	for i, name := range []string{r.certFile, r.keyFile} {
		if fi, err := os.Stat(name); err == nil {
			out[i] = fi.ModTime()
		}
	}
	return out
}
