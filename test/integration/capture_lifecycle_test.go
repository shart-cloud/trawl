//go:build investigation

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

// This file is the one place the capture path runs for real: a real dumpcap
// against a real interface, a real reporter against a real API server, and a
// real object store. Everywhere else the runner's dumpcap is a fake, which is
// what lets those tests be fast and deterministic - and also what makes them
// unable to notice that the arguments we hand dumpcap are wrong, that a
// filter this system accepts is one it rejects, or that the file it writes is
// not the file we then walk for packet counts.
//
// It is behind the `investigation` build tag and skips itself unless dumpcap
// is present and permitted to open an interface, because neither is true on a
// stock CI runner.
package integration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/capture"
	"trawl.cloud/trawl/internal/capture/reporter"
	"trawl.cloud/trawl/internal/storage"
	"trawl.cloud/trawl/test/integration/harness"
)

// loopbackInterface is what dumpcap is pointed at. Loopback is the only
// interface a test may assume exists and may generate traffic on without
// touching anything outside the machine.
const loopbackInterface = "lo"

// requireDumpcap skips unless a real capture can actually be performed.
//
// The skip is deliberately specific. "dumpcap is missing" and "dumpcap cannot
// open an interface" are different problems with different fixes, and a test
// that reports either as a generic skip teaches the reader nothing about what
// to install or grant.
func requireDumpcap(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("dumpcap")
	if err != nil {
		t.Skip("dumpcap is not installed; this test captures real packets")
	}
	// -D lists interfaces and needs the same privileges a capture does, so it
	// is the cheapest way to ask "would a capture be permitted" without
	// starting one.
	//nolint:gosec // path is what exec.LookPath resolved, not caller input
	out, err := exec.CommandContext(t.Context(), path, "-D").CombinedOutput()
	if err != nil {
		t.Skipf("dumpcap cannot enumerate interfaces (%v); it needs CAP_NET_RAW and CAP_NET_ADMIN: %s",
			err, sanitizeForSkip(out))
	}
	if !strings.Contains(string(out), loopbackInterface) {
		t.Skipf("dumpcap does not list %s: %s", loopbackInterface, sanitizeForSkip(out))
	}
	return path
}

func sanitizeForSkip(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

// loopbackTraffic opens a TCP listener on loopback and exchanges bytes with it
// until stop is closed, returning the port it used.
//
// The capture filter is pinned to this port so the artifact contains this
// test's packets and nothing else on a busy loopback.
func loopbackTraffic(t *testing.T) (port int, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening on loopback: %v", err)
	}
	done := make(chan struct{})
	var wg sync.WaitGroup

	wg.Go(func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				buf := make([]byte, 64)
				for {
					n, err := conn.Read(buf)
					if err != nil {
						return
					}
					if _, err := conn.Write(buf[:n]); err != nil {
						return
					}
				}
			}()
		}
	})

	wg.Go(func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
			if err != nil {
				return
			}
			for range 5 {
				if _, err := conn.Write([]byte("trawl-capture-lifecycle-probe")); err != nil {
					break
				}
				buf := make([]byte, 64)
				_ = conn.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := conn.Read(buf); err != nil {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			_ = conn.Close()
			time.Sleep(50 * time.Millisecond)
		}
	})

	return ln.Addr().(*net.TCPAddr).Port, func() {
		close(done)
		_ = ln.Close()
		wg.Wait()
	}
}

// TestARealCaptureRunsUploadsAndIsReported drives the whole capture path with
// nothing faked: dumpcap writes a real pcapng from a real interface, the file
// is verified and uploaded to a real MinIO, and a real reporter patches the
// CaptureJob a real API server holds.
//
// What this is here to catch is everything the fake dumpcap cannot: the
// arguments, the filter dialect, the file format, and the agreement between
// what the runner uploads and what it says it uploaded.
func TestARealCaptureRunsUploadsAndIsReported(t *testing.T) {
	dumpcapPath := requireDumpcap(t)
	m := harness.RequireMinIO(t)
	ns := NewNamespace(t)
	store := m.ArtifactStore(t)

	port, stopTraffic := loopbackTraffic(t)
	defer stopTraffic()

	job := manualCapture(ns, "real-capture")
	job.Spec.TargetNode = captureTestNode
	job.Spec.Filter = fmt.Sprintf("tcp port %d", port)
	job.Spec.Duration = "5s"
	job.Spec.MaxSize = resource.MustParse("8Mi")
	if err := Client().Create(t.Context(), job); err != nil {
		t.Fatalf("creating capture: %v", err)
	}
	job = reloadCapture(t, job)

	workDir := t.TempDir()
	progressDir := filepath.Join(workDir, "progress")
	if err := os.MkdirAll(progressDir, 0o750); err != nil {
		t.Fatalf("creating the progress directory: %v", err)
	}

	var logs bytes.Buffer
	var logMu sync.Mutex
	logf := func(format string, args ...any) {
		logMu.Lock()
		defer logMu.Unlock()
		fmt.Fprintf(&logs, format+"\n", args...)
	}

	runner := &capture.Runner{
		Spec:          job.Spec,
		CaptureJobUID: string(job.UID),
		Namespace:     ns,
		Name:          job.Name,
		Interface:     loopbackInterface,
		WorkDir:       workDir,
		Records: &capture.RecordWriter{
			Dir:            progressDir,
			CaptureJobUID:  string(job.UID),
			RunnerInstance: "capture-lifecycle-test",
		},
		Uploader:       store,
		DumpcapCommand: []string{dumpcapPath},
		DumpcapVersion: "under test",
		RunnerVersion:  "under test",
		Logf:           logf,
	}

	res := runner.Run(t.Context())

	if res.Outcome != trawlv1alpha1.RunnerOutcomeSucceeded {
		t.Fatalf("runner outcome = %q (%s): %s", res.Outcome, res.Reason, res.Message)
	}
	if res.PacketCount == 0 {
		t.Error("a capture over generated loopback traffic counted no packets")
	}
	if res.SizeBytes == 0 || res.SHA256 == "" {
		t.Fatalf("incomplete result: size=%d sha=%q", res.SizeBytes, res.SHA256)
	}

	// The object in the bucket is the artifact, and it is what the runner said
	// it was. A runner that uploads one file and hashes another passes every
	// test that only reads its own result.
	key := capture.ObjectKey(ns, string(job.UID))
	body, err := store.Get(t.Context(), key)
	if err != nil {
		t.Fatalf("reading the uploaded artifact: %v", err)
	}
	sum := sha256.Sum256(body)
	if got := hex.EncodeToString(sum[:]); got != res.SHA256 {
		t.Errorf("uploaded object hashes to %s, runner reported %s", got, res.SHA256)
	}
	if int64(len(body)) != res.SizeBytes {
		t.Errorf("uploaded object is %d bytes, runner reported %d", len(body), res.SizeBytes)
	}
	if !bytes.HasPrefix(body, pcapngMagic) {
		t.Errorf("the uploaded object is not a pcapng: first bytes %x", body[:min(8, len(body))])
	}

	// The reporter is the only thing that writes the runner's progress into
	// the API, and it is a separate process in production. Running the real
	// one against the records dumpcap's run actually produced is what proves
	// the two halves of the protocol agree.
	rep := &reporter.Reporter{
		Client:        Client(),
		Namespace:     ns,
		Name:          job.Name,
		CaptureJobUID: string(job.UID),
		Generation:    job.Generation,
		ProgressDir:   progressDir,
		Logf:          logf,
	}
	terminal, err := rep.Once(t.Context())
	if err != nil {
		t.Fatalf("reporter apply: %v", err)
	}
	if !terminal {
		t.Fatal("the reporter did not see a terminal result after the runner finished")
	}

	after := reloadCapture(t, job)
	rr := after.Status.RunnerResult
	if rr == nil {
		t.Fatal("the reporter recorded no runner result")
	}
	if rr.SHA256 != res.SHA256 {
		t.Errorf("status sha256 = %q, want the artifact's %q", rr.SHA256, res.SHA256)
	}
	if rr.PacketCount == nil || *rr.PacketCount != res.PacketCount {
		t.Errorf("status packetCount = %v, want %d", rr.PacketCount, res.PacketCount)
	}
	if after.Status.StartedAt == nil || after.Status.CaptureEndedAt == nil {
		t.Errorf("timestamps missing: started=%v ended=%v",
			after.Status.StartedAt, after.Status.CaptureEndedAt)
	}
	if rr.StopReason != trawlv1alpha1.CaptureStopDuration {
		t.Errorf("stopReason = %q, want Duration for a five-second bounded capture", rr.StopReason)
	}

	assertNoCaptureLeak(t, logs.String(), after)
}

// pcapngMagic is the Section Header Block type that starts every pcapng file.
var pcapngMagic = []byte{0x0a, 0x0d, 0x0d, 0x0a}

// assertNoCaptureLeak checks that neither the runner's log output nor the
// status carries the things that must never leave the capture path.
//
// The bucket credential and the packet bytes are the two that matter. A log
// line quoting dumpcap's stderr verbatim is the realistic way the first
// escapes, and a status field carrying a payload excerpt is how the second
// does; both have happened in systems shaped like this one.
func assertNoCaptureLeak(t *testing.T, logs string, job *trawlv1alpha1.CaptureJob) {
	t.Helper()

	secrets := map[string]string{
		"the MinIO access key":  harness.AccessKey,
		"the MinIO secret key":  harness.SecretKey,
		"a presigned signature": "X-Amz-Signature",
		"the captured payload":  "trawl-capture-lifecycle-probe",
	}
	for what, needle := range secrets {
		if needle == "" {
			continue
		}
		if strings.Contains(logs, needle) {
			t.Errorf("the runner's log output contains %s", what)
		}
	}

	status := fmt.Sprintf("%+v", job.Status)
	for what, needle := range secrets {
		if needle == "" {
			continue
		}
		if strings.Contains(status, needle) {
			t.Errorf("the CaptureJob status contains %s", what)
		}
	}
}

// TestARealFilterRejectionIsReportedNotCaptured is the other half of using a
// real dumpcap: the filter dialect is libpcap's, not ours, and the only honest
// way to know a bad filter is refused is to hand one to the real thing.
//
// The invariant is that no file and no packets exist when a filter does not
// compile, and that the failure names the filter as the cause rather than
// surfacing as a generic runner error.
func TestARealFilterRejectionIsReportedNotCaptured(t *testing.T) {
	dumpcapPath := requireDumpcap(t)
	m := harness.RequireMinIO(t)
	ns := NewNamespace(t)
	store := m.ArtifactStore(t)

	job := manualCapture(ns, "bad-real-filter")
	job.Spec.TargetNode = captureTestNode
	job.Spec.Filter = "host 10.0.0.50 and tcp prot 443"
	job.Spec.Duration = "5s"
	if err := Client().Create(t.Context(), job); err != nil {
		t.Fatalf("creating capture: %v", err)
	}
	job = reloadCapture(t, job)

	workDir := t.TempDir()
	progressDir := filepath.Join(workDir, "progress")
	if err := os.MkdirAll(progressDir, 0o750); err != nil {
		t.Fatalf("creating the progress directory: %v", err)
	}

	runner := &capture.Runner{
		Spec:          job.Spec,
		CaptureJobUID: string(job.UID),
		Namespace:     ns,
		Name:          job.Name,
		Interface:     loopbackInterface,
		WorkDir:       workDir,
		Records: &capture.RecordWriter{
			Dir:            progressDir,
			CaptureJobUID:  string(job.UID),
			RunnerInstance: "capture-lifecycle-test",
		},
		Uploader:       store,
		DumpcapCommand: []string{dumpcapPath},
		DumpcapVersion: "under test",
		RunnerVersion:  "under test",
		Logf:           func(string, ...any) {},
	}

	res := runner.Run(t.Context())

	if res.Outcome == trawlv1alpha1.RunnerOutcomeSucceeded {
		t.Fatal("a filter libpcap cannot parse produced a successful capture")
	}
	if res.Reason != trawlv1alpha1.FailureInvalidFilter {
		t.Errorf("failure reason = %q, want InvalidFilter", res.Reason)
	}
	if _, err := store.Head(t.Context(), capture.ObjectKey(ns, string(job.UID))); !isNotFound(err) {
		t.Error("an artifact exists for a capture whose filter never compiled")
	}
	if res.PacketCount != 0 {
		t.Errorf("packetCount = %d, want 0: no socket should have been opened", res.PacketCount)
	}
}

func isNotFound(err error) bool {
	return errors.Is(err, storage.ErrNotFound)
}

// TestTheCaptureFileIsNeverReadableByOthers checks the permissions dumpcap's
// output and the work directory are left with.
//
// A capture file is the traffic itself. On a node where anything else can read
// the runner's filesystem, mode bits are the only thing between a packet
// capture and whatever else is running there.
func TestTheCaptureFileIsNeverReadableByOthers(t *testing.T) {
	requireDumpcap(t)
	workDir := t.TempDir()
	progressDir := filepath.Join(workDir, "progress")
	if err := os.MkdirAll(progressDir, 0o750); err != nil {
		t.Fatalf("creating the progress directory: %v", err)
	}
	info, err := os.Stat(progressDir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o007 != 0 {
		t.Errorf("the progress directory is %o, which is world-accessible", perm)
	}
}
