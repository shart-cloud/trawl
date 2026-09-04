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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/sanitize"
)

// The runner and the reporter share an emptyDir. The runner writes one file
// per milestone; the reporter reads them and writes status. The runner holds
// no API credentials and the reporter holds no capture capability, and this
// directory is the only thing they share.
const (
	// ProgressSchemaVersion identifies the record envelope.
	ProgressSchemaVersion = "trawl.capture-progress/v1"

	// DefaultProgressDir is where the progress volume is mounted in both
	// containers.
	DefaultProgressDir = "/var/run/trawl/capture"

	// MaxRecordBytes bounds a record file. The reporter mounts the directory
	// read-only, but the runner could still fill it; nothing legitimate is
	// anywhere near this size.
	MaxRecordBytes = 16 << 10

	// MaxRecordFiles bounds how many directory entries the reporter examines.
	MaxRecordFiles = 16
)

// RecordKind names a milestone.
type RecordKind string

const (
	// RecordFilter says the filter compiled against the interface.
	RecordFilter RecordKind = "filter"
	// RecordStarted says the capture file exists and packets may be arriving.
	RecordStarted RecordKind = "started"
	// RecordEnded says dumpcap stopped; the file is complete and not yet uploaded.
	RecordEnded RecordKind = "ended"
	// RecordResult is the runner's terminal outcome.
	RecordResult RecordKind = "result"
)

var recordFiles = map[RecordKind]string{
	RecordFilter:  "01-filter.json",
	RecordStarted: "02-started.json",
	RecordEnded:   "03-ended.json",
	RecordResult:  "09-result.json",
}

var recordSeq = map[RecordKind]int{
	RecordFilter: 1, RecordStarted: 2, RecordEnded: 3, RecordResult: 9,
}

// SeqFor is the sequence number a kind carries.
func SeqFor(k RecordKind) int { return recordSeq[k] }

// RecordFileName is the file a kind is written to.
func RecordFileName(k RecordKind) string { return recordFiles[k] }

// Fields is the union of what the milestones carry. Each kind fills its own
// subset; the rest stay empty.
type Fields struct {
	// filter
	Interface string `json:"interface,omitempty"`

	// started
	StartedAt *time.Time `json:"startedAt,omitempty"`

	// ended
	EndedAt     *time.Time                      `json:"endedAt,omitempty"`
	StopReason  trawlv1alpha1.CaptureStopReason `json:"stopReason,omitempty"`
	PacketCount *int64                          `json:"packetCount,omitempty"`
	SizeBytes   *int64                          `json:"sizeBytes,omitempty"`

	// result
	Outcome  trawlv1alpha1.RunnerOutcome `json:"outcome,omitempty"`
	Reason   trawlv1alpha1.FailureReason `json:"reason,omitempty"`
	SHA256   string                      `json:"sha256,omitempty"`
	ExitCode *int32                      `json:"exitCode,omitempty"`
	Message  string                      `json:"message,omitempty"`
}

// Record is the envelope around every milestone.
type Record struct {
	SchemaVersion  string     `json:"schemaVersion"`
	Kind           RecordKind `json:"kind"`
	Seq            int        `json:"seq"`
	CaptureJobUID  string     `json:"captureJobUID"`
	RecordedAt     time.Time  `json:"recordedAt"`
	RunnerInstance string     `json:"runnerInstance"`
	Fields         Fields     `json:"fields"`
}

// Problem describes a file the reader refused. File is the base name only.
type Problem struct {
	File   string
	Reason string
}

// RecordWriter writes milestones for one capture.
type RecordWriter struct {
	Dir            string
	CaptureJobUID  string
	RunnerInstance string
	Now            func() time.Time
}

// Write persists one milestone atomically: a temp file that must not already
// exist, fsync, rename onto the final name, fsync the directory. A reader
// therefore sees either nothing or a complete record, and a record, once
// written, is never replaced.
func (w *RecordWriter) Write(kind RecordKind, fields Fields) error {
	name, ok := recordFiles[kind]
	if !ok {
		return fmt.Errorf("unknown record kind %q", kind)
	}
	fields.Message = sanitize.String(fields.Message)
	rec := Record{
		SchemaVersion:  ProgressSchemaVersion,
		Kind:           kind,
		Seq:            recordSeq[kind],
		CaptureJobUID:  w.CaptureJobUID,
		RecordedAt:     w.Now().UTC(),
		RunnerInstance: w.RunnerInstance,
		Fields:         fields,
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	final := filepath.Join(w.Dir, name)
	if _, err := os.Lstat(final); err == nil {
		return fmt.Errorf("record %s already written", name)
	}
	tmp := final + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) //nolint:gosec // The reporter reads it as another uid.
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(w.Dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // The progress directory, from configuration.
	if err != nil {
		return err
	}
	defer d.Close() //nolint:errcheck // Read-only handle.
	return d.Sync()
}

// ReadRecords loads the milestones for a capture. It never fails outright: a
// missing directory is an empty result, and each file it refuses becomes a
// Problem so the reporter can count it without trusting it.
//
// Refused: anything not a regular file, unknown names, files over
// MaxRecordBytes, malformed JSON, another capture's UID, a wrong sequence
// number, and a record whose predecessor is missing (started needs filter,
// ended needs started). A result alone is legal — the runner may fail before
// it starts.
func ReadRecords(dir, captureJobUID string) ([]Record, []Problem) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil
	}
	var recs []Record
	var problems []Problem
	seen := 0
	for _, e := range entries {
		if seen++; seen > MaxRecordFiles {
			problems = append(problems, Problem{File: "", Reason: "too many files"})
			break
		}
		name := e.Name()
		kind, known := kindForFile(name)
		if !known {
			problems = append(problems, Problem{File: name, Reason: "not a record file"})
			continue
		}
		rec, perr := readRecord(dir, name)
		if perr != "" {
			problems = append(problems, Problem{File: name, Reason: perr})
			continue
		}
		if rec.Kind != kind || rec.Seq != recordSeq[kind] {
			problems = append(problems, Problem{File: name, Reason: "kind or seq does not match file name"})
			continue
		}
		if rec.CaptureJobUID != captureJobUID {
			problems = append(problems, Problem{File: name, Reason: "record belongs to another capture"})
			continue
		}
		recs = append(recs, rec)
	}
	slices.SortFunc(recs, func(a, b Record) int { return a.Seq - b.Seq })

	has := func(k RecordKind) bool {
		return slices.ContainsFunc(recs, func(r Record) bool { return r.Kind == k })
	}
	kept := recs[:0]
	for _, r := range recs {
		switch {
		case r.Kind == RecordStarted && !has(RecordFilter):
			problems = append(problems, Problem{File: recordFiles[r.Kind], Reason: "started without filter"})
		case r.Kind == RecordEnded && !has(RecordStarted):
			problems = append(problems, Problem{File: recordFiles[r.Kind], Reason: "ended without started"})
		default:
			kept = append(kept, r)
		}
	}
	return kept, problems
}

func kindForFile(name string) (RecordKind, bool) {
	for k, f := range recordFiles {
		if f == name {
			return k, true
		}
	}
	return "", false
}

// readRecord returns a reason string rather than an error so nothing from the
// file can ride along in an error message.
func readRecord(dir, name string) (Record, string) {
	path := filepath.Join(dir, name)
	info, err := os.Lstat(path)
	if err != nil {
		return Record{}, "cannot stat"
	}
	if !info.Mode().IsRegular() {
		return Record{}, "not a regular file"
	}
	if info.Size() > MaxRecordBytes {
		return Record{}, "record too large"
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // Name is one of four constants.
	if err != nil {
		return Record{}, "cannot open"
	}
	defer f.Close() //nolint:errcheck // Read-only handle.
	raw, err := io.ReadAll(io.LimitReader(f, MaxRecordBytes+1))
	if err != nil {
		return Record{}, "cannot read"
	}
	if len(raw) > MaxRecordBytes {
		return Record{}, "record too large"
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var rec Record
	if err := dec.Decode(&rec); err != nil {
		return Record{}, "malformed record"
	}
	if rec.SchemaVersion != ProgressSchemaVersion {
		return Record{}, "unsupported schema version"
	}
	rec.CaptureJobUID = sanitize.String(rec.CaptureJobUID)
	rec.RunnerInstance = sanitize.String(rec.RunnerInstance)
	rec.Fields.Interface = sanitize.String(rec.Fields.Interface)
	rec.Fields.SHA256 = sanitize.String(rec.Fields.SHA256)
	rec.Fields.Message = sanitize.String(rec.Fields.Message)
	rec.Fields.StopReason = trawlv1alpha1.CaptureStopReason(sanitize.String(string(rec.Fields.StopReason)))
	rec.Fields.Outcome = trawlv1alpha1.RunnerOutcome(sanitize.String(string(rec.Fields.Outcome)))
	rec.Fields.Reason = trawlv1alpha1.FailureReason(sanitize.String(string(rec.Fields.Reason)))
	return rec, ""
}
