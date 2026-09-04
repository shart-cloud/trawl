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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trawl.cloud/trawl/internal/storage"
)

// certAuthority issues the server and client certificates a round trip needs.
// Generating a real chain rather than stubbing the TLS layer is the point: the
// sink's whole job is to refuse a caller whose certificate does not check out,
// and that decision is made by crypto/tls, not by anything this package wrote.
type certAuthority struct {
	dir      string
	cert     *x509.Certificate
	key      *ecdsa.PrivateKey
	caPEMLoc string
}

func newCertAuthority(t *testing.T) *certAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "trawl-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing CA certificate: %v", err)
	}

	ca := &certAuthority{dir: t.TempDir(), cert: cert, key: key}
	ca.caPEMLoc = filepath.Join(ca.dir, "ca.crt")
	writeFile(t, ca.caPEMLoc, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return ca
}

// issue writes a certificate and key for one identity and returns their paths.
func (ca *certAuthority) issue(t *testing.T, name, commonName string, dnsNames []string, usage x509.ExtKeyUsage) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating %s key: %v", name, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     dnsNames,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("signing %s certificate: %v", name, err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling %s key: %v", name, err)
	}

	certPath := filepath.Join(ca.dir, name+".crt")
	keyPath := filepath.Join(ca.dir, name+".key")
	writeFile(t, certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	writeFile(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPath, keyPath
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// startSink runs a sink server against a Fake store and returns its endpoint.
func startSink(t *testing.T, ca *certAuthority, allowed []string) (string, *storage.Fake) {
	t.Helper()
	store := storage.NewFake()
	sink := newTestSink(t, store)

	certFile, keyFile := ca.issue(t, "server", "trawl-audit.trawl-system.svc",
		[]string{"trawl-audit.trawl-system.svc", "localhost"}, x509.ExtKeyUsageServerAuth)

	srv, err := NewSinkServer(SinkServerOptions{
		Sink:              sink,
		ListenAddr:        "127.0.0.1:0",
		CertFile:          certFile,
		KeyFile:           keyFile,
		CAFile:            ca.caPEMLoc,
		AllowedIdentities: allowed,
	})
	if err != nil {
		t.Fatalf("NewSinkServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("sink server stopped with %v", err)
		}
	})

	return fmt.Sprintf("https://%s", srv.Addr().String()), store
}

// clientFor builds an audit Client with a certificate for commonName.
func clientFor(t *testing.T, ca *certAuthority, endpoint, name, commonName string) *Client {
	t.Helper()
	certFile, keyFile := ca.issue(t, name, commonName, nil, x509.ExtKeyUsageClientAuth)
	c, err := NewClient(ClientOptions{
		Endpoint:   endpoint,
		CAFile:     ca.caPEMLoc,
		CertFile:   certFile,
		KeyFile:    keyFile,
		ServerName: "trawl-audit.trawl-system.svc",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// The whole of ADR-0003 rests on this path working: ledger credentials live
// only in the controller manager, so every other component records what it did
// by committing here. Until now nothing served it, and no test crossed a real
// TLS connection to find out.
func TestSinkServerCommitsAnAuthorizedClientsRecord(t *testing.T) {
	const gateway = "trawl-artifact-gateway.trawl-system.svc"
	ca := newCertAuthority(t)
	endpoint, store := startSink(t, ca, []string{gateway})
	client := clientFor(t, ca, endpoint, "gateway", gateway)

	res, err := client.Commit(context.Background(), testRecord())
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if res.Result != ResultSuccess {
		t.Errorf("result = %q, want %q", res.Result, ResultSuccess)
	}
	if res.LedgerKey == "" {
		t.Fatal("commit returned no ledger key")
	}
	if store.Object(res.LedgerKey) == nil {
		t.Error("the record never reached the ledger the sink was given")
	}
}

// A certificate from the same CA for a different workload must not be able to
// write history. This is what AuditClientIdentities is for: the TLS layer only
// proves the CA issued the certificate, not that its holder may commit.
func TestSinkServerRejectsAnUnlistedCommonName(t *testing.T) {
	ca := newCertAuthority(t)
	endpoint, store := startSink(t, ca, []string{"trawl-artifact-gateway.trawl-system.svc"})
	client := clientFor(t, ca, endpoint, "impostor", "trawl-sensor.trawl-system.svc")

	if _, err := client.Commit(context.Background(), testRecord()); err == nil {
		t.Fatal("a certificate for an unlisted identity was allowed to commit")
	}
	if store.ObjectCount() != 0 {
		t.Errorf("the rejected commit still wrote %d objects", store.ObjectCount())
	}
}

// Without a client certificate the connection must not get as far as the
// handler, so that an unauthenticated caller never reaches the decoder.
func TestSinkServerRefusesAClientWithNoCertificate(t *testing.T) {
	ca := newCertAuthority(t)
	endpoint, store := startSink(t, ca, []string{"trawl-artifact-gateway.trawl-system.svc"})

	// A certificate from an unrelated CA stands in for "not one of ours".
	other := newCertAuthority(t)
	client := clientFor(t, other, endpoint, "stranger", "trawl-artifact-gateway.trawl-system.svc")

	if _, err := client.Commit(context.Background(), testRecord()); err == nil {
		t.Fatal("a client certificate from an unknown CA was accepted")
	}
	if store.ObjectCount() != 0 {
		t.Errorf("the refused connection still wrote %d objects", store.ObjectCount())
	}
}

// The identity list is the only thing standing between "the CA issued this"
// and "this may write history", so an empty one must fail at startup rather
// than at the first commit somebody's mutation is blocked on.
func TestNewSinkServerRequiresAnIdentityList(t *testing.T) {
	ca := newCertAuthority(t)
	certFile, keyFile := ca.issue(t, "server2", "trawl-audit.trawl-system.svc", nil, x509.ExtKeyUsageServerAuth)

	_, err := NewSinkServer(SinkServerOptions{
		Sink:       newTestSink(t, storage.NewFake()),
		ListenAddr: "127.0.0.1:0",
		CertFile:   certFile,
		KeyFile:    keyFile,
		CAFile:     ca.caPEMLoc,
	})
	if err == nil {
		t.Fatal("NewSinkServer accepted an empty allowed-identity list")
	}
	if !strings.Contains(err.Error(), "identity") {
		t.Errorf("error %q does not name the missing identities", err)
	}
}

// A missing certificate must stop the manager at startup, not leave a
// listener that fails every handshake.
func TestNewSinkServerFailsOnUnreadableTLSMaterial(t *testing.T) {
	ca := newCertAuthority(t)
	_, err := NewSinkServer(SinkServerOptions{
		Sink:              newTestSink(t, storage.NewFake()),
		ListenAddr:        "127.0.0.1:0",
		CertFile:          filepath.Join(ca.dir, "absent.crt"),
		KeyFile:           filepath.Join(ca.dir, "absent.key"),
		CAFile:            ca.caPEMLoc,
		AllowedIdentities: []string{"trawl-artifact-gateway.trawl-system.svc"},
	})
	if err == nil {
		t.Fatal("NewSinkServer started with no serving certificate")
	}
	// sanitize.Errorf flattens the cause, so the message is what an operator
	// has to work from; it must still name what was missing.
	if !strings.Contains(err.Error(), "certificate") {
		t.Errorf("error %q does not name the certificate", err)
	}
}
