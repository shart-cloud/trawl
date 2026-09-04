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

package capture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/storage"
)

// plantedSecret is written to the fake dumpcap's stderr in every failure
// mode. It must never appear in a result, a record, or a log line.
const plantedSecret = "secret=hunter2-AKIAIOSFODNN7EXAMPLE"

// TestHelperProcess is the fake dumpcap. The runner re-executes the test
// binary with -test.run=TestHelperProcess -- <dumpcap args>; the mode comes
// from the environment.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("TRAWL_FAKE_DUMPCAP") == "" {
		return
	}
	args := os.Args
	for i, a := range args {
		if a == "--" {
			args = args[i+1:]
			break
		}
	}
	mode := os.Getenv("TRAWL_FAKE_DUMPCAP")
	dryRun := false
	var output string
	var duration, filesizeKB int64
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d":
			dryRun = true
		case "-w":
			output = args[i+1]
		case "-a":
			if v, ok := strings.CutPrefix(args[i+1], "duration:"); ok {
				duration, _ = strconv.ParseInt(v, 10, 64)
			}
			if v, ok := strings.CutPrefix(args[i+1], "filesize:"); ok {
				filesizeKB, _ = strconv.ParseInt(v, 10, 64)
			}
		}
	}
	if dryRun {
		if mode == "badfilter" {
			_, _ = fmt.Fprintln(os.Stderr, "dumpcap: syntax error in filter expression "+plantedSecret)
			os.Exit(1)
		}
		_, _ = fmt.Fprintln(os.Stdout, "(000) ret #262144")
		os.Exit(0)
	}
	packets := 3
	if v := os.Getenv("TRAWL_FAKE_PACKETS"); v != "" {
		packets, _ = strconv.Atoi(v)
	}
	writeFile := func(extra int) {
		var pkts [][]byte
		for i := 0; i < packets; i++ {
			pkts = append(pkts, []byte("packet"))
		}
		data := pcapng(false, pkts...)
		if extra > 0 {
			data = append(data, pcapng(false, make([]byte, extra))[len(pcapng(false)):]...)
		}
		if err := os.WriteFile(output, data, 0o600); err != nil { //nolint:gosec // Fake dumpcap writes where it is told.
			os.Exit(99)
		}
	}
	switch mode {
	case "ok":
		writeFile(0)
		time.Sleep(time.Duration(duration) * time.Second)
		os.Exit(0)
	case "size":
		writeFile(int(filesizeKB * 1000))
		os.Exit(0)
	case "overshoot":
		writeFile(int(filesizeKB*1024) + MaxOvershootBytes + 4096)
		os.Exit(0)
	case "hang":
		writeFile(0)
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT)
		<-sig
		os.Exit(0)
	case "crash":
		writeFile(0)
		_, _ = fmt.Fprintln(os.Stderr, "dumpcap: The capture session could not be initiated "+plantedSecret)
		os.Exit(2)
	case "nofile":
		_, _ = fmt.Fprintln(os.Stderr, "dumpcap: cannot open "+plantedSecret)
		os.Exit(2)
	}
	os.Exit(98)
}

func fakeDumpcap(t *testing.T, mode string) []string {
	t.Helper()
	t.Setenv("TRAWL_FAKE_DUMPCAP", mode)
	return []string{os.Args[0], "-test.run=TestHelperProcess", "--"}
}

func runnerFor(t *testing.T, mode string) (*Runner, *storage.Fake) {
	t.Helper()
	store := storage.NewFake()
	work := t.TempDir()
	progress := t.TempDir()
	r := &Runner{
		Spec: trawlv1alpha1.CaptureJobSpec{
			Filter: "tcp port 443", Duration: "1s", MaxSize: resource.MustParse("1Mi"),
		},
		CaptureJobUID: "u-1", Namespace: "trawl-system", Name: "manual-tls", Interface: "lo",
		WorkDir:        work,
		Records:        &RecordWriter{Dir: progress, CaptureJobUID: "u-1", RunnerInstance: "r-1", Now: time.Now},
		Uploader:       store,
		DumpcapCommand: fakeDumpcap(t, mode),
		Now:            time.Now,
		Logf:           t.Logf,
	}
	return r, store
}

func recordKinds(t *testing.T, r *Runner) []RecordKind {
	t.Helper()
	recs, problems := ReadRecords(r.Records.Dir, r.CaptureJobUID)
	if len(problems) != 0 {
		t.Fatalf("record problems: %+v", problems)
	}
	kinds := make([]RecordKind, 0, len(recs))
	for _, rec := range recs {
		kinds = append(kinds, rec.Kind)
	}
	return kinds
}

func assertNoSecret(t *testing.T, r *Runner, res Result) {
	t.Helper()
	if strings.Contains(res.Message, "hunter2") || strings.Contains(res.Message, "AKIA") {
		t.Errorf("result message leaks dumpcap stderr: %q", res.Message)
	}
	recs, _ := ReadRecords(r.Records.Dir, r.CaptureJobUID)
	for _, rec := range recs {
		if strings.Contains(rec.Fields.Message, "hunter2") || strings.Contains(rec.Fields.Message, "AKIA") {
			t.Errorf("%s record leaks dumpcap stderr: %q", rec.Kind, rec.Fields.Message)
		}
	}
}

func TestRunnerCapturesAndUploads(t *testing.T) {
	r, store := runnerFor(t, "ok")
	res := r.Run(context.Background())
	if res.ExitCode != ExitOK || res.Outcome != trawlv1alpha1.RunnerOutcomeSucceeded {
		t.Fatalf("result %+v", res)
	}
	if res.StopReason != trawlv1alpha1.CaptureStopDuration || res.PacketCount != 3 {
		t.Errorf("result %+v: want Duration stop with 3 packets", res)
	}

	obj := store.Object(ObjectKey("trawl-system", "u-1"))
	if obj == nil {
		t.Fatal("artifact not uploaded")
	}
	sum := sha256.Sum256(obj)
	if res.SHA256 != hex.EncodeToString(sum[:]) || res.SizeBytes != int64(len(obj)) {
		t.Errorf("result %+v does not describe the uploaded bytes (%d bytes, %x)", res, len(obj), sum)
	}
	head, err := store.Head(context.Background(), ObjectKey("trawl-system", "u-1"))
	if err != nil {
		t.Fatal(err)
	}
	raw := store.Object(ManifestKey("trawl-system", "u-1"))
	m, err := ParseManifest(raw)
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if err := VerifyArtifact(m, "u-1", head.Size, head.Metadata); err != nil {
		t.Errorf("uploaded artifact does not verify against its manifest: %v", err)
	}
	if m.PacketCount != 3 || m.Interface != "lo" || m.StopReason != trawlv1alpha1.CaptureStopDuration || m.EndedAt.Before(m.StartedAt) {
		t.Errorf("manifest %+v", m)
	}
	for _, key := range []string{ObjectKey("trawl-system", "u-1"), ManifestKey("trawl-system", "u-1")} {
		if !store.WasConditional(key) {
			t.Errorf("%s was not written conditionally", key)
		}
	}
	if head.Metadata[MetadataSHA256] != res.SHA256 || head.Metadata[MetadataCaptureJobUID] != "u-1" {
		t.Errorf("object metadata %v", head.Metadata)
	}

	want := []RecordKind{RecordFilter, RecordStarted, RecordEnded, RecordResult}
	if got := recordKinds(t, r); strings.Join(kindStrings(got), ",") != strings.Join(kindStrings(want), ",") {
		t.Errorf("records %v, want %v", got, want)
	}
	if _, err := os.Stat(filepath.Join(r.WorkDir, WorkFileName)); !os.IsNotExist(err) {
		t.Errorf("work file still present after upload: %v", err)
	}
}

func TestRunnerZeroPacketsIsACompleteCapture(t *testing.T) {
	t.Setenv("TRAWL_FAKE_PACKETS", "0")
	r, store := runnerFor(t, "ok")
	res := r.Run(context.Background())
	if res.ExitCode != ExitOK || res.PacketCount != 0 || store.Object(ObjectKey("trawl-system", "u-1")) == nil {
		t.Fatalf("result %+v", res)
	}
}

func TestRunnerStopsOnSize(t *testing.T) {
	r, _ := runnerFor(t, "size")
	res := r.Run(context.Background())
	if res.ExitCode != ExitOK || res.StopReason != trawlv1alpha1.CaptureStopSize {
		t.Fatalf("result %+v, want Size stop", res)
	}
}

func TestRunnerRejectsBadFilterBeforeCapturing(t *testing.T) {
	r, store := runnerFor(t, "badfilter")
	res := r.Run(context.Background())
	if res.ExitCode != ExitInvalidFilter || res.Reason != trawlv1alpha1.FailureInvalidFilter {
		t.Fatalf("result %+v", res)
	}
	if got := recordKinds(t, r); len(got) != 1 || got[0] != RecordResult {
		t.Errorf("records %v, want only result", got)
	}
	if store.ObjectCount() != 0 {
		t.Error("something was uploaded")
	}
	if res.Message == "" {
		t.Error("message empty")
	}
	assertNoSecret(t, r, res)
}

func TestRunnerRejectsInvalidBoundsWithoutExec(t *testing.T) {
	r, _ := runnerFor(t, "ok")
	r.Spec.Duration = "0s"
	res := r.Run(context.Background())
	if res.ExitCode != ExitInvalidBounds || res.Reason != trawlv1alpha1.FailureInvalidBounds {
		t.Fatalf("result %+v", res)
	}
	if got := recordKinds(t, r); len(got) != 1 || got[0] != RecordResult {
		t.Errorf("records %v", got)
	}
}

func TestRunnerRejectsMissingInterface(t *testing.T) {
	r, _ := runnerFor(t, "ok")
	r.Interface = "trawl-no-such-if0"
	res := r.Run(context.Background())
	if res.ExitCode != ExitInterfaceUnavailable || res.Reason != trawlv1alpha1.FailureInterfaceUnavailable {
		t.Fatalf("result %+v", res)
	}
}

func TestRunnerDiscardsOvershoot(t *testing.T) {
	r, store := runnerFor(t, "overshoot")
	res := r.Run(context.Background())
	if res.ExitCode != ExitSizeExceeded || res.Reason != trawlv1alpha1.FailureSizeExceeded {
		t.Fatalf("result %+v", res)
	}
	if store.ObjectCount() != 0 {
		t.Error("oversized artifact was uploaded")
	}
	if got := recordKinds(t, r); len(got) != 4 || got[2] != RecordEnded {
		t.Errorf("records %v, want filter,started,ended,result", got)
	}
}

func TestRunnerCancellationStopsWithoutUpload(t *testing.T) {
	r, store := runnerFor(t, "hang")
	r.Spec.Duration = "30s"
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		started := filepath.Join(r.Records.Dir, RecordFileName(RecordStarted))
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(started); err == nil {
				cancel()
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		cancel()
	}()
	res := r.Run(ctx)
	if res.ExitCode != ExitCaptureFailed || res.StopReason != trawlv1alpha1.CaptureStopCancelled {
		t.Fatalf("result %+v", res)
	}
	if store.ObjectCount() != 0 {
		t.Error("cancelled capture was uploaded")
	}
	if got := recordKinds(t, r); len(got) != 4 {
		t.Errorf("records %v, want filter,started,ended,result", got)
	}
}

func TestRunnerReportsDumpcapCrashWithoutLeakingStderr(t *testing.T) {
	r, store := runnerFor(t, "crash")
	res := r.Run(context.Background())
	if res.ExitCode != ExitCaptureFailed || res.Reason != trawlv1alpha1.FailureCaptureFailed || res.StopReason != trawlv1alpha1.CaptureStopError {
		t.Fatalf("result %+v", res)
	}
	if store.ObjectCount() != 0 {
		t.Error("partial capture was uploaded")
	}
	assertNoSecret(t, r, res)
}

func TestRunnerFailsWhenNoFileAppears(t *testing.T) {
	r, _ := runnerFor(t, "nofile")
	res := r.Run(context.Background())
	if res.ExitCode != ExitCaptureFailed {
		t.Fatalf("result %+v", res)
	}
	if got := recordKinds(t, r); len(got) != 2 || got[0] != RecordFilter || got[1] != RecordResult {
		t.Errorf("records %v, want filter,result (never started)", got)
	}
	assertNoSecret(t, r, res)
}

func TestRunnerRefusesToOverwriteAnExistingArtifact(t *testing.T) {
	r, store := runnerFor(t, "ok")
	if _, err := store.Put(context.Background(), ObjectKey("trawl-system", "u-1"), []byte("earlier evidence"), storage.PutOptions{}); err != nil {
		t.Fatal(err)
	}
	res := r.Run(context.Background())
	if res.ExitCode != ExitUploadFailed || res.Reason != trawlv1alpha1.FailureUploadFailed {
		t.Fatalf("result %+v", res)
	}
	if string(store.Object(ObjectKey("trawl-system", "u-1"))) != "earlier evidence" {
		t.Error("existing artifact was overwritten")
	}
}

func TestRunnerUploadFailure(t *testing.T) {
	r, store := runnerFor(t, "ok")
	store.FailPut(fmt.Errorf("connection refused to https://minio.internal/?X-Amz-Signature=abc " + plantedSecret))
	res := r.Run(context.Background())
	if res.ExitCode != ExitUploadFailed {
		t.Fatalf("result %+v", res)
	}
	if strings.Contains(res.Message, "X-Amz") || strings.Contains(res.Message, "hunter2") {
		t.Errorf("message leaks the storage error: %q", res.Message)
	}
}

func kindStrings(ks []RecordKind) []string {
	out := make([]string, len(ks))
	for i, k := range ks {
		out[i] = string(k)
	}
	return out
}
