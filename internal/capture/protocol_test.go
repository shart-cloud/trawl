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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
)

func writer(t *testing.T, dir string) *RecordWriter {
	t.Helper()
	return &RecordWriter{Dir: dir, CaptureJobUID: "u-1", RunnerInstance: "runner-1", Now: func() time.Time { return time.Unix(1000, 0).UTC() }}
}

func TestRecordsRoundTripInOrder(t *testing.T) {
	dir := t.TempDir()
	w := writer(t, dir)
	started := time.Unix(1001, 0).UTC()
	ended := time.Unix(1061, 0).UTC()
	steps := []Fields{
		{Interface: "eth0"},
		{StartedAt: &started},
		{EndedAt: &ended, StopReason: trawlv1alpha1.CaptureStopDuration, PacketCount: ptr(int64(7)), SizeBytes: ptr(int64(4096))},
		{Outcome: trawlv1alpha1.RunnerOutcomeSucceeded, SHA256: strings.Repeat("ab", 32), ExitCode: ptr(int32(0))},
	}
	kinds := []RecordKind{RecordFilter, RecordStarted, RecordEnded, RecordResult}
	for i, k := range kinds {
		if err := w.Write(k, steps[i]); err != nil {
			t.Fatalf("write %s: %v", k, err)
		}
	}

	recs, problems := ReadRecords(dir, "u-1")
	if len(problems) != 0 {
		t.Fatalf("problems: %+v", problems)
	}
	if len(recs) != 4 {
		t.Fatalf("got %d records, want 4", len(recs))
	}
	for i, r := range recs {
		if r.Kind != kinds[i] || r.Seq != SeqFor(kinds[i]) || r.CaptureJobUID != "u-1" ||
			r.RunnerInstance != "runner-1" || r.SchemaVersion != ProgressSchemaVersion {
			t.Errorf("record %d: %+v", i, r)
		}
	}
	if recs[1].Fields.StartedAt == nil || !recs[1].Fields.StartedAt.Equal(started) {
		t.Errorf("started record lost its timestamp: %+v", recs[1].Fields)
	}
	if recs[2].Fields.PacketCount == nil || *recs[2].Fields.PacketCount != 7 {
		t.Errorf("ended record lost its counters: %+v", recs[2].Fields)
	}

	entries, _ := os.ReadDir(dir)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	want := []string{"01-filter.json", "02-started.json", "03-ended.json", "09-result.json"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("files %v, want %v (no temp files left behind)", names, want)
	}
}

func TestWriteRefusesToOverwrite(t *testing.T) {
	w := writer(t, t.TempDir())
	if err := w.Write(RecordFilter, Fields{Interface: "eth0"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(RecordFilter, Fields{Interface: "eth1"}); err == nil {
		t.Fatal("second write of the same record succeeded")
	}
	recs, _ := ReadRecords(w.Dir, "u-1")
	if len(recs) != 1 || recs[0].Fields.Interface != "eth0" {
		t.Errorf("first record was replaced: %+v", recs)
	}
}

func TestWriteBoundsAndSanitizesMessage(t *testing.T) {
	w := writer(t, t.TempDir())
	msg := "dumpcap: secret=hunter2 " + strings.Repeat("x", 2000)
	if err := w.Write(RecordResult, Fields{Outcome: trawlv1alpha1.RunnerOutcomeFailed, Reason: trawlv1alpha1.FailureCaptureFailed, Message: msg}); err != nil {
		t.Fatal(err)
	}
	recs, problems := ReadRecords(w.Dir, "u-1")
	if len(problems) != 0 || len(recs) != 1 {
		t.Fatalf("recs=%+v problems=%+v", recs, problems)
	}
	got := recs[0].Fields.Message
	if strings.Contains(got, "hunter2") || len(got) > 512 {
		t.Errorf("message not sanitized/bounded: %q", got)
	}
}

func TestReadRecordsRejectsWhatItMustNotTrust(t *testing.T) {
	dir := t.TempDir()
	w := writer(t, dir)
	if err := w.Write(RecordFilter, Fields{Interface: "eth0"}); err != nil {
		t.Fatal(err)
	}

	// A record for another capture, a symlink, an oversized file, an unknown
	// name, and a subdirectory must each be reported and skipped.
	other := &RecordWriter{Dir: t.TempDir(), CaptureJobUID: "u-2", RunnerInstance: "r", Now: time.Now}
	if err := other.Write(RecordStarted, Fields{StartedAt: ptr(time.Now())}); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(other.Dir, "02-started.json"), filepath.Join(dir, "02-started.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "03-ended.json"), []byte(strings.Repeat(" ", MaxRecordBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "09-result.json"), 0o700); err != nil {
		t.Fatal(err)
	}

	recs, problems := ReadRecords(dir, "u-1")
	if len(recs) != 1 || recs[0].Kind != RecordFilter {
		t.Errorf("records %+v, want only the filter record", recs)
	}
	if len(problems) != 4 {
		t.Errorf("problems %+v, want 4", problems)
	}
	for _, p := range problems {
		if p.File == "" || p.Reason == "" {
			t.Errorf("problem %+v lacks file or reason", p)
		}
	}
}

func TestReadRecordsRejectsForeignUIDAndBrokenSequence(t *testing.T) {
	dir := t.TempDir()
	foreign := &RecordWriter{Dir: dir, CaptureJobUID: "u-9", RunnerInstance: "r", Now: time.Now}
	if err := foreign.Write(RecordFilter, Fields{Interface: "eth0"}); err != nil {
		t.Fatal(err)
	}
	recs, problems := ReadRecords(dir, "u-1")
	if len(recs) != 0 || len(problems) != 1 {
		t.Errorf("foreign uid: recs=%+v problems=%+v", recs, problems)
	}

	dir = t.TempDir()
	w := &RecordWriter{Dir: dir, CaptureJobUID: "u-1", RunnerInstance: "r", Now: time.Now}
	if err := w.Write(RecordEnded, Fields{EndedAt: ptr(time.Now())}); err != nil {
		t.Fatal(err)
	}
	recs, problems = ReadRecords(dir, "u-1")
	if len(recs) != 0 || len(problems) != 1 {
		t.Errorf("ended without started: recs=%+v problems=%+v", recs, problems)
	}

	// A result without a start is legal: the runner failed before capturing.
	dir = t.TempDir()
	w = &RecordWriter{Dir: dir, CaptureJobUID: "u-1", RunnerInstance: "r", Now: time.Now}
	if err := w.Write(RecordResult, Fields{Outcome: trawlv1alpha1.RunnerOutcomeFailed, Reason: trawlv1alpha1.FailureInvalidFilter}); err != nil {
		t.Fatal(err)
	}
	recs, problems = ReadRecords(dir, "u-1")
	if len(recs) != 1 || len(problems) != 0 {
		t.Errorf("early result: recs=%+v problems=%+v", recs, problems)
	}
}

func TestReadRecordsMissingDirIsEmptyNotFatal(t *testing.T) {
	recs, problems := ReadRecords(filepath.Join(t.TempDir(), "absent"), "u-1")
	if len(recs) != 0 || len(problems) != 0 {
		t.Errorf("recs=%+v problems=%+v", recs, problems)
	}
}

func ptr[T any](v T) *T { return &v }
