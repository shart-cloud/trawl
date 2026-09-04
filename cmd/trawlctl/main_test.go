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

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"trawl.cloud/trawl/internal/gateway"
)

// analystToken is the credential the CLI must deliver to the gateway and to
// nowhere else — not to a log line, not to stderr, not to its own argv.
const analystToken = "eyJhbGciOiJSUzI1NiJ9.analyst-token.signature"

// testJobName is the CaptureJob quickstart §6 downloads.
const testJobName = "manual-tls"

const artifactBody = "pcapng bytes that stand in for a capture"

// fakeGateway is the gateway half of a download plus a plaintext object store.
//
// The object store is plain HTTP on purpose. What the TLS trust boundary
// between the two hops does is settled in internal/gateway/client_test.go
// against two real certificates; repeating it here would test the client
// again rather than the CLI wrapped around it.
type fakeGateway struct {
	*httptest.Server

	objects *httptest.Server

	mu sync.Mutex
	// seenAuthorization is what the gateway received, so a test can prove the
	// token arrived where it belongs.
	seenAuthorization string

	// status, when non-zero, is an error response instead of a 303.
	status int
	body   struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	}
	// checksum overrides the reported SHA-256; empty means the real one.
	checksum string

	// duringTransfer, when set, runs with half the artifact delivered and the
	// rest still to come.
	duringTransfer func()
}

func newFakeGateway(t *testing.T) *fakeGateway {
	t.Helper()
	g := &fakeGateway{}

	objects := http.NewServeMux()
	objects.HandleFunc("GET /objects/capture.pcapng", func(w http.ResponseWriter, _ *http.Request) {
		g.mu.Lock()
		hook := g.duringTransfer
		g.mu.Unlock()
		if hook == nil {
			_, _ = w.Write([]byte(artifactBody))
			return
		}
		_, _ = w.Write([]byte(artifactBody[:10]))
		w.(http.Flusher).Flush()
		hook()
		_, _ = w.Write([]byte(artifactBody[10:]))
	})
	g.objects = httptest.NewServer(objects)

	mux := http.NewServeMux()
	mux.HandleFunc(gateway.DownloadPath, func(w http.ResponseWriter, r *http.Request) {
		// Every field of the fixture is read under the mutex, including the
		// ones a test sets before the first request: the fixture is shared
		// across two goroutines, and which half of it happens to be safe today
		// is not a rule anyone can follow.
		g.mu.Lock()
		g.seenAuthorization = r.Header.Get("Authorization")
		status, body, override := g.status, g.body, g.checksum
		g.mu.Unlock()

		w.Header().Set("X-Request-ID", "req-42")
		if status != 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(body)
			return
		}
		sum := sha256.Sum256([]byte(artifactBody))
		checksum := override
		if checksum == "" {
			checksum = hex.EncodeToString(sum[:])
		}
		w.Header().Set(gateway.HeaderSHA256, checksum)
		w.Header().Set("Location", g.objects.URL+"/objects/capture.pcapng?X-Amz-Signature=deadbeef")
		w.WriteHeader(http.StatusSeeOther)
	})
	g.Server = httptest.NewTLSServer(mux)

	t.Cleanup(func() {
		g.Close()
		g.objects.Close()
	})
	return g
}

// caFile writes the fake gateway's certificate where the CLI's --ca can read it.
func caFile(t *testing.T, g *fakeGateway) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gateway-ca.crt")
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: g.Certificate().Raw})
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("writing the CA: %v", err)
	}
	return path
}

// invocation is one CLI run: the arguments, what it read on stdin, and what it
// wrote where.
type invocation struct {
	code   int
	stdout string
	stderr string
}

func (i invocation) all() string { return i.stdout + i.stderr }

func runCLI(t *testing.T, stdin string, args ...string) invocation {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(t.Context(), args, strings.NewReader(stdin), &stdout, &stderr)
	return invocation{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

// downloadArgs is the quickstart §6 command, minus the token source.
func downloadArgs(g *fakeGateway, ca, output string) []string {
	return []string{
		captureCommand, downloadCommand, testJobName,
		"--namespace", "trawl-system",
		"--gateway", g.URL,
		"--ca", ca,
		"--output", output,
	}
}

func TestDownloadWritesTheVerifiedArtifact(t *testing.T) {
	g := newFakeGateway(t)
	dir := t.TempDir()
	output := filepath.Join(dir, testJobName+".pcapng")

	got := runCLI(t, analystToken+"\n", append(downloadArgs(g, caFile(t, g), output), "--token-stdin")...)
	if got.code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", got.code, got.stderr)
	}

	written, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("reading the download: %v", err)
	}
	if string(written) != artifactBody {
		t.Errorf("downloaded %q, want %q", written, artifactBody)
	}
	// The temporary name is cleaned up, so a later download to the same path
	// is not blocked by this one's leftovers.
	if left := namesIn(t, dir); !slices.Equal(left, []string{testJobName + ".pcapng"}) {
		t.Errorf("the directory holds %v, want only the artifact", left)
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seenAuthorization != "Bearer "+analystToken {
		t.Errorf("gateway saw Authorization %q, want the bearer token", g.seenAuthorization)
	}
}

// The download is written under a temporary name and renamed only once the
// checksum verifies, because bytes reach the file before the checksum can be
// known.
//
// This is asserted from inside the object store, while the transfer is still
// running, rather than from the wreckage afterwards: a CLI that wrote straight
// to --output and deleted it on error would leave the same empty directory
// behind, and would still expose an unverified artifact under the final name
// to anything watching the path - including an analyst whose terminal is
// killed mid-download.
func TestTheFinalNameNeverHoldsUnverifiedBytes(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, testJobName+".pcapng")

	g := newFakeGateway(t)
	var duringTransfer []string
	g.duringTransfer = func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		duringTransfer = namesIn(t, dir)
	}

	got := runCLI(t, analystToken, append(downloadArgs(g, caFile(t, g), output), "--token-stdin")...)
	if got.code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", got.code, got.stderr)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	want := []string{testJobName + ".pcapng.part"}
	if !slices.Equal(duringTransfer, want) {
		t.Errorf("during the transfer the directory held %v, want %v", duringTransfer, want)
	}
}

// namesIn lists a directory, sorted, for comparison against an expectation.
func namesIn(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Errorf("reading %s: %v", dir, err)
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	return names
}

// Nothing is left behind by a failure either - not the artifact, and not the
// partial file it was being written into.
func TestNoPartialFileSurvivesAFailedDownload(t *testing.T) {
	cases := map[string]func(*fakeGateway){
		"gateway refuses": func(g *fakeGateway) {
			g.status = http.StatusForbidden
			g.body.Code = gateway.CodeForbidden
			g.body.Message = "the caller may not download this capture"
			g.body.RequestID = "req-42"
		},
		"checksum mismatch": func(g *fakeGateway) {
			g.checksum = strings.Repeat("11", 32)
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			g := newFakeGateway(t)
			setup(g)
			dir := t.TempDir()
			output := filepath.Join(dir, testJobName+".pcapng")

			got := runCLI(t, analystToken, append(downloadArgs(g, caFile(t, g), output), "--token-stdin")...)
			if got.code == 0 {
				t.Errorf("exit = 0, want non-zero")
			}
			if left := namesIn(t, dir); len(left) != 0 {
				t.Errorf("left behind %v, want an empty directory", left)
			}
		})
	}
}

// The request ID is the one string that ties a refusal to the gateway's logs
// and to the audit ledger, so a denied download has to report it.
func TestARefusalReportsTheCodeAndRequestID(t *testing.T) {
	g := newFakeGateway(t)
	g.status = http.StatusForbidden
	g.body.Code = gateway.CodeForbidden
	g.body.Message = "the caller may not download this capture"
	g.body.RequestID = "req-42"

	output := filepath.Join(t.TempDir(), testJobName+".pcapng")
	got := runCLI(t, analystToken, append(downloadArgs(g, caFile(t, g), output), "--token-stdin")...)
	if got.code != 1 {
		t.Errorf("exit = %d, want 1", got.code)
	}
	for _, want := range []string{gateway.CodeForbidden, "req-42"} {
		if !strings.Contains(got.stderr, want) {
			t.Errorf("stderr does not mention %q: %s", want, got.stderr)
		}
	}
}

// A token that reaches a terminal, a shell history file, or a CI log is a token
// that has to be treated as disclosed. It may appear in exactly one place: the
// Authorization header.
func TestTheTokenIsNeverPrinted(t *testing.T) {
	g := newFakeGateway(t)
	g.status = http.StatusForbidden
	g.body.Code = gateway.CodeForbidden
	g.body.Message = "the caller may not download this capture"

	output := filepath.Join(t.TempDir(), testJobName+".pcapng")
	got := runCLI(t, analystToken, append(downloadArgs(g, caFile(t, g), output), "--token-stdin")...)
	if strings.Contains(got.all(), analystToken) {
		t.Errorf("the token appears in the CLI's own output: %s", got.all())
	}
}

// --token-exec exists so the token can come from `kubectl create token`
// without a shell pipeline. The command runs; the credential it prints is
// never an argument of anything.
func TestTokenExecSuppliesTheToken(t *testing.T) {
	g := newFakeGateway(t)
	output := filepath.Join(t.TempDir(), testJobName+".pcapng")

	script := filepath.Join(t.TempDir(), "mint-token")
	body := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' '%s'\n", analystToken)
	//nolint:gosec // a token command the CLI runs has to be executable
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatalf("writing the token command: %v", err)
	}

	args := append(downloadArgs(g, caFile(t, g), output), "--token-exec", script)
	got := runCLI(t, "", args...)
	if got.code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", got.code, got.stderr)
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seenAuthorization != "Bearer "+analystToken {
		t.Errorf("gateway saw Authorization %q, want the token the command printed", g.seenAuthorization)
	}
}

// A token command that fails must not be mistaken for an empty token: sending
// an empty bearer to the gateway would report an authorization failure for
// what is really a broken credential helper.
func TestAFailingTokenCommandIsAnError(t *testing.T) {
	g := newFakeGateway(t)
	output := filepath.Join(t.TempDir(), testJobName+".pcapng")

	// The command prints a plausible token and *then* fails, which is what a
	// credential helper serving a stale cache looks like. A CLI that only
	// noticed an empty standard output would send that token anyway.
	script := filepath.Join(t.TempDir(), "mint-token")
	body := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' '%s'\necho 'the token is expired' >&2\nexit 7\n", analystToken)
	//nolint:gosec // a token command the CLI runs has to be executable
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatalf("writing the token command: %v", err)
	}

	got := runCLI(t, "", append(downloadArgs(g, caFile(t, g), output), "--token-exec", script)...)
	if got.code == 0 {
		t.Fatalf("exit = 0, want non-zero")
	}
	// Readable, not a byte slice printed as decimal: this line is the only
	// explanation the operator gets for why no download was attempted.
	if !strings.Contains(got.stderr, "the token is expired") {
		t.Errorf("stderr does not quote the token command: %s", got.stderr)
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seenAuthorization != "" {
		t.Errorf("the gateway was called with %q despite no token", g.seenAuthorization)
	}
}

// An existing file at --output is refused rather than overwritten. Downloaded
// captures are evidence, and clobbering one silently is a way to lose it.
func TestAnExistingOutputIsNotOverwritten(t *testing.T) {
	g := newFakeGateway(t)
	output := filepath.Join(t.TempDir(), testJobName+".pcapng")
	if err := os.WriteFile(output, []byte("an earlier capture"), 0o600); err != nil {
		t.Fatalf("seeding the output: %v", err)
	}

	got := runCLI(t, analystToken, append(downloadArgs(g, caFile(t, g), output), "--token-stdin")...)
	if got.code == 0 {
		t.Errorf("exit = 0, want non-zero")
	}
	kept, err := os.ReadFile(output)
	if err != nil || string(kept) != "an earlier capture" {
		t.Errorf("output = %q (%v), want the earlier capture untouched", kept, err)
	}
}

// Usage mistakes are separated from download failures by exit code, so a
// script can tell "I called this wrong" from "the download was refused".
// without returns args with one flag and its value removed, so each case in
// the table below differs from a working command line in exactly one way.
func without(args []string, flag string) []string {
	i := slices.Index(args, flag)
	if i < 0 {
		panic("no " + flag + " to remove")
	}
	return slices.Delete(slices.Clone(args), i, i+2)
}

func TestUsageErrorsExitTwo(t *testing.T) {
	g := newFakeGateway(t)
	ca := caFile(t, g)
	output := filepath.Join(t.TempDir(), testJobName+".pcapng")

	full := append(downloadArgs(g, ca, output), "--token-stdin")
	cases := map[string][]string{
		"no arguments":      {},
		"unknown command":   {captureCommand, "upload", testJobName},
		"no name":           {captureCommand, downloadCommand, "--token-stdin"},
		"empty name":        withName(full, ""),
		"no token source":   downloadArgs(g, ca, output),
		"two token sources": append(slices.Clone(full), "--token-exec", "/bin/true"),
		"no namespace":      without(full, "--namespace"),
		"no gateway":        without(full, "--gateway"),
		"no ca":             without(full, "--ca"),
		"no output":         without(full, "--output"),
		"stray positional":  append(slices.Clone(full), "extra"),
		"unknown flag":      append(slices.Clone(full), "--force"),
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			got := runCLI(t, analystToken, args...)
			if got.code != 2 {
				t.Errorf("exit = %d, want 2; stderr: %s", got.code, got.stderr)
			}
		})
	}
}

// Help is a successful outcome on stdout, not a usage error on stderr: a
// script that pipes `trawlctl --help` somewhere should not see a failure.
func TestHelpSucceedsOnStdout(t *testing.T) {
	for _, arg := range []string{"help", "-h", "--help"} {
		t.Run(arg, func(t *testing.T) {
			got := runCLI(t, "", arg)
			if got.code != 0 {
				t.Errorf("exit = %d, want 0", got.code)
			}
			if !strings.Contains(got.stdout, "capture download") {
				t.Errorf("stdout does not describe the command: %s", got.stdout)
			}
			if got.stderr != "" {
				t.Errorf("stderr = %q, want nothing", got.stderr)
			}
		})
	}
}

// withName replaces the positional CaptureJob name.
func withName(args []string, name string) []string {
	replaced := slices.Clone(args)
	replaced[2] = name
	return replaced
}

// A --gateway or --ca the client cannot be built from is a fact about the
// command line, so it exits like one: a supervising loop that retried a typo'd
// URL would retry it forever.
func TestAnUnusableGatewayOrCAIsAUsageError(t *testing.T) {
	g := newFakeGateway(t)
	ca := caFile(t, g)
	output := filepath.Join(t.TempDir(), testJobName+".pcapng")
	full := append(downloadArgs(g, ca, output), "--token-stdin")

	cases := map[string][]string{
		"plaintext gateway": replace(full, "--gateway", "http://127.0.0.1:8443"),
		"unparseable URL":   replace(full, "--gateway", "https://:::/"),
		"missing CA file":   replace(full, "--ca", filepath.Join(t.TempDir(), "absent.crt")),
		"CA without a certificate": replace(full, "--ca", func() string {
			path := filepath.Join(t.TempDir(), "empty.crt")
			if err := os.WriteFile(path, []byte("not a certificate\n"), 0o600); err != nil {
				t.Fatalf("writing the CA: %v", err)
			}
			return path
		}()),
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if got := runCLI(t, analystToken, args...); got.code != 2 {
				t.Errorf("exit = %d, want 2; stderr: %s", got.code, got.stderr)
			}
		})
	}
}

// replace returns args with one flag's value changed.
func replace(args []string, flag, value string) []string {
	changed := slices.Clone(args)
	changed[slices.Index(changed, flag)+1] = value
	return changed
}

// The window between "--output does not exist" and the rename is minutes wide
// for a gibibyte capture. Whatever appears in it stays.
func TestAFileAppearingDuringTheDownloadIsNotClobbered(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, testJobName+".pcapng")

	g := newFakeGateway(t)
	g.duringTransfer = func() {
		if err := os.WriteFile(output, []byte("someone else's capture"), 0o600); err != nil {
			t.Errorf("writing the competing file: %v", err)
		}
	}

	got := runCLI(t, analystToken, append(downloadArgs(g, caFile(t, g), output), "--token-stdin")...)
	if got.code == 0 {
		t.Errorf("exit = 0, want non-zero")
	}
	kept, err := os.ReadFile(output)
	if err != nil || string(kept) != "someone else's capture" {
		t.Errorf("output = %q (%v), want the competing file untouched", kept, err)
	}

	// The artifact cost a token, a presigned URL, and a download record in the
	// ledger. A name collision is not a reason to make the operator spend all
	// three again, so the .part stays - and the error has to say where it is.
	part, err := os.ReadFile(output + ".part")
	if err != nil || string(part) != artifactBody {
		t.Errorf("the downloaded artifact = %q (%v), want it kept beside the collision", part, err)
	}
	if !strings.Contains(got.stderr, output+".part") {
		t.Errorf("stderr does not say where the artifact is: %s", got.stderr)
	}
}

// A .part left by a killed download blocks the path it names, and says so in
// terms an operator can act on: nothing about it changes on a retry.
func TestAStalePartFileIsReportedByName(t *testing.T) {
	g := newFakeGateway(t)
	output := filepath.Join(t.TempDir(), testJobName+".pcapng")
	if err := os.WriteFile(output+".part", []byte("half a capture"), 0o600); err != nil {
		t.Fatalf("seeding the stale file: %v", err)
	}

	got := runCLI(t, analystToken, append(downloadArgs(g, caFile(t, g), output), "--token-stdin")...)
	if got.code == 0 {
		t.Fatalf("exit = 0, want non-zero")
	}
	if !strings.Contains(got.stderr, "remove it if not") {
		t.Errorf("stderr does not name the remedy: %s", got.stderr)
	}
	kept, err := os.ReadFile(output + ".part")
	if err != nil || string(kept) != "half a capture" {
		t.Errorf("the stale file = %q (%v), want it left alone", kept, err)
	}
}

// --token-exec pointed at the wrong program must report that what it read is
// not a token, not read it forever.
//
// The command here never stops, so an unbounded read never returns: if the
// bound goes, this test does not fail with a wrong answer, it hangs until the
// package times out. That is the honest shape of the failure - buffering
// without a bound has no size at which it is wrong.
func TestAnOversizedTokenIsRefusedWithoutBuffering(t *testing.T) {
	g := newFakeGateway(t)
	output := filepath.Join(t.TempDir(), testJobName+".pcapng")

	script := filepath.Join(t.TempDir(), "flood")
	body := "#!/bin/sh\nexec yes token-shaped-nonsense\n"
	//nolint:gosec // a token command the CLI runs has to be executable
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatalf("writing the token command: %v", err)
	}

	got := runCLI(t, "", append(downloadArgs(g, caFile(t, g), output), "--token-exec", script)...)
	if got.code == 0 {
		t.Fatalf("exit = 0, want non-zero")
	}
	if !strings.Contains(got.stderr, "not a service account token") {
		t.Errorf("stderr = %q, want it to say the token is too long", got.stderr)
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seenAuthorization != "" {
		t.Errorf("the gateway was called with %q despite an unusable token", g.seenAuthorization)
	}
}

// An empty stdin is a mistake worth naming: it is what a forgotten pipe looks
// like, and the gateway's answer to an empty bearer would blame the caller's
// permissions instead.
func TestAnEmptyTokenOnStdinIsAnError(t *testing.T) {
	g := newFakeGateway(t)
	output := filepath.Join(t.TempDir(), testJobName+".pcapng")

	got := runCLI(t, "   \n", append(downloadArgs(g, caFile(t, g), output), "--token-stdin")...)
	if got.code == 0 {
		t.Fatalf("exit = 0, want non-zero")
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seenAuthorization != "" {
		t.Errorf("the gateway was called with %q despite an empty stdin", g.seenAuthorization)
	}
}
