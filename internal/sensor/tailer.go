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

package sensor

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"sync/atomic"
	"time"

	"trawl.cloud/trawl/internal/observation"
	"trawl.cloud/trawl/internal/sanitize"
)

// Tailer bounds.
const (
	// MaxLineBytes caps one analyzer record. Suricata and Zeek records are
	// kilobytes; anything far larger is a corrupt file or a runaway field, and
	// reading it into memory unbounded is how a sensor OOMs on bad input.
	MaxLineBytes = 1 << 20

	// pollInterval is how often a tailer checks an idle file for new data.
	pollInterval = 250 * time.Millisecond
)

// RecordResult classifies one processed line, matching the
// trawl_sensor_records_total `result` label.
type RecordResult string

const (
	ResultAccepted    RecordResult = "accepted"
	ResultUnsupported RecordResult = "unsupported"
	ResultMalformed   RecordResult = "malformed"
)

// ParseFunc converts one raw line into an observation.
//
// Returning (nil, nil) means the line was consumed but produced no observation,
// which is how Suricata stats records are handled.
type ParseFunc func(line []byte) (*observation.Observation, error)

// EmitFunc receives a normalized, validated observation.
type EmitFunc func(obs *observation.Observation, duplication string) error

// Counters are the tailer's observable outcomes.
//
// Malformed and unsupported are tracked separately: an operator needs to
// distinguish "the analyzer emits a record type we do not model yet" from "the
// analyzer is producing garbage", because only the second is an incident.
type Counters struct {
	Accepted    int64
	Unsupported int64
	Malformed   int64
}

// counters holds the same values atomically. The status reporter samples them
// from its own goroutine while Run is writing, so plain fields would be a data
// race in production, not only under test.
type counters struct {
	accepted    atomic.Int64
	unsupported atomic.Int64
	malformed   atomic.Int64

	// Unix nanoseconds of the last accepted record, 0 for none. The status
	// reporter needs to distinguish an analyzer that has produced nothing from
	// one that produced something a while ago; a zero time would claim the
	// former for both.
	lastRecord atomic.Int64
}

// Tailer follows one analyzer log file and emits normalized observations.
//
// Its central guarantee is FR-016: a malformed or unsupported record is counted
// and stepped over, never allowed to stop the records around it. An analyzer
// that emits one bad line must not blind the sensor for everything after it.
type Tailer struct {
	// Path is the analyzer log file.
	Path string

	// Parse converts a line to an observation.
	Parse ParseFunc

	// OnAccept is called for each accepted record.
	//
	// Rejections had a callback and acceptances did not, so
	// trawl_sensor_records_total only ever counted failures - a record
	// counter that went silent precisely when everything was working.
	OnAccept func()

	// Emit receives accepted observations.
	Emit EmitFunc

	// Duplicates marks suspected duplicate observations.
	Duplicates *DuplicateCache

	// OnReject is called with a diagnostic fingerprint for each rejected line.
	// It receives a hash, never the content, since a malformed record can carry
	// traffic data including credentials.
	OnReject func(result RecordResult, fingerprint string)

	counters counters
}

// LastRecord reports when this tailer last accepted a record.
//
// The boolean distinguishes "nothing yet" from a zero time.
func (t *Tailer) LastRecord() (time.Time, bool) {
	ns := t.counters.lastRecord.Load()
	if ns == 0 {
		return time.Time{}, false
	}
	return time.Unix(0, ns), true
}

// Counters returns a snapshot of processing outcomes.
//
// Safe to call from another goroutine while Run is active; the status reporter
// does exactly that on every heartbeat.
func (t *Tailer) Counters() Counters {
	return Counters{
		Accepted:    t.counters.accepted.Load(),
		Unsupported: t.counters.unsupported.Load(),
		Malformed:   t.counters.malformed.Load(),
	}
}

// Run follows the file until ctx is cancelled.
//
// Rotation is handled by reopening when the file's identity changes. Analyzers
// rotate their own logs, and a tailer holding the old inode would go silent
// while the analyzer kept writing — a monitoring outage whose only symptom is
// absence of data.
func (t *Tailer) Run(ctx context.Context) error {
	var (
		file    *os.File
		reader  *bufio.Reader
		lastIno uint64
	)
	defer func() {
		if file != nil {
			_ = file.Close()
		}
	}()

	for {
		if err := ctx.Err(); err != nil {
			return nil
		}

		if file == nil {
			opened, ino, err := openLog(t.Path)
			if err != nil {
				// The analyzer may not have created the file yet. Waiting is
				// correct; failing would make sensor startup depend on
				// analyzer startup ordering.
				if sleepCtx(ctx, pollInterval) {
					continue
				}
				return nil
			}
			file, lastIno = opened, ino
			reader = bufio.NewReaderSize(file, 64<<10)
		}

		line, err := readLine(reader)
		switch {
		case err == nil:
			t.process(line)
			continue

		case errors.Is(err, errLineTooLong):
			// The oversized line was discarded by readLine; count it and keep
			// going rather than letting one runaway record stop the stream.
			t.reject(ResultMalformed, sanitize.DiagnosticHash("oversized-line"))
			continue

		case errors.Is(err, io.EOF):
			// Caught up. Check for rotation, then wait for more data.
			if rotated(t.Path, lastIno) {
				_ = file.Close()
				file = nil
				continue
			}
			if sleepCtx(ctx, pollInterval) {
				continue
			}
			return nil

		default:
			// A read error on the file itself: reopen rather than exit, so a
			// transient filesystem problem does not end monitoring.
			_ = file.Close()
			file = nil
			if sleepCtx(ctx, pollInterval) {
				continue
			}
			return nil
		}
	}
}

// process handles one line. It never returns an error: every outcome is a
// counted classification, because the alternative is one bad record ending the
// stream.
func (t *Tailer) process(line []byte) {
	if len(line) == 0 {
		return
	}

	obs, err := t.Parse(line)
	if err != nil {
		result := ResultMalformed
		if errors.Is(err, observation.ErrUnsupportedRecord) {
			result = ResultUnsupported
		}
		// The fingerprint identifies a repeating bad producer without storing
		// what it produced.
		t.reject(result, sanitize.DiagnosticHash(string(line)))
		return
	}
	if obs == nil {
		// Consumed but not an observation, e.g. a Suricata stats record.
		return
	}

	if err := observation.Normalize(obs); err != nil {
		t.reject(ResultMalformed, sanitize.DiagnosticHash(string(line)))
		return
	}
	// Validation happens here rather than downstream because Loki enforces no
	// schema: an invalid record would be stored and only noticed when a query
	// silently returned nothing.
	if err := observation.Validate(obs); err != nil {
		t.reject(ResultMalformed, sanitize.DiagnosticHash(string(line)))
		return
	}

	duplication := ""
	if t.Duplicates != nil {
		duplication = string(t.Duplicates.Mark(obs))
	}

	if t.Emit != nil {
		if err := t.Emit(obs, duplication); err != nil {
			t.reject(ResultMalformed, sanitize.DiagnosticHash("emit-failure"))
			return
		}
	}
	t.counters.accepted.Add(1)
	t.counters.lastRecord.Store(time.Now().UnixNano())
	if t.OnAccept != nil {
		t.OnAccept()
	}
}

func (t *Tailer) reject(result RecordResult, fingerprint string) {
	switch result {
	case ResultUnsupported:
		t.counters.unsupported.Add(1)
	default:
		t.counters.malformed.Add(1)
	}
	if t.OnReject != nil {
		t.OnReject(result, fingerprint)
	}
}

var errLineTooLong = errors.New("analyzer record exceeds the maximum line length")

// readLine reads one newline-terminated record, discarding any line longer than
// MaxLineBytes rather than buffering it.
func readLine(r *bufio.Reader) ([]byte, error) {
	line, err := r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		// Drain the rest of the oversized line so the reader resynchronizes on
		// the next record boundary instead of emitting fragments.
		total := len(line)
		for {
			more, drainErr := r.ReadSlice('\n')
			total += len(more)
			if drainErr == nil || total > MaxLineBytes {
				break
			}
			if !errors.Is(drainErr, bufio.ErrBufferFull) {
				return nil, drainErr
			}
		}
		return nil, errLineTooLong
	}
	if err != nil {
		return nil, err
	}
	if len(line) > MaxLineBytes {
		return nil, errLineTooLong
	}
	// Copy: ReadSlice's buffer is reused on the next call.
	out := make([]byte, len(line)-1)
	copy(out, line[:len(line)-1])
	return out, nil
}

// sleepCtx waits for d, returning false when the context is cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
