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
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"trawl.cloud/trawl/internal/observation"
)

// collector captures what a tailer emitted and rejected.
type collector struct {
	mu           sync.Mutex
	emitted      []*observation.Observation
	rejects      []RecordResult
	fingerprints []string
}

func (c *collector) emit(obs *observation.Observation, _ string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.emitted = append(c.emitted, obs)
	return nil
}

func (c *collector) reject(result RecordResult, fp string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rejects = append(c.rejects, result)
	c.fingerprints = append(c.fingerprints, fp)
}

func (c *collector) counts() (emitted int, rejects []RecordResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.emitted), append([]RecordResult(nil), c.rejects...)
}

// runTailer runs a tailer over path until it has processed the expected number
// of outcomes or the deadline passes.
func runTailer(t *testing.T, tl *Tailer, wantOutcomes int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = tl.Run(ctx)
		close(done)
	}()

	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		c := tl.Counters()
		if int(c.Accepted+c.Malformed+c.Unsupported) >= wantOutcomes {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
}

func suricataTailer(t *testing.T, path string, c *collector) *Tailer {
	t.Helper()
	n := SuricataNormalizerFor(t)
	return &Tailer{
		Path: path,
		Parse: func(line []byte) (*observation.Observation, error) {
			obs, _, err := n.Normalize(line)
			return obs, err
		},
		Emit:       c.emit,
		OnReject:   c.reject,
		Duplicates: NewDuplicateCache(1000),
	}
}

// SuricataNormalizerFor builds a normalizer with fixed identity for tests.
func SuricataNormalizerFor(t *testing.T) observation.SuricataNormalizer {
	t.Helper()
	fixed := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	return observation.SuricataNormalizer{
		Version: "8.0.6",
		Tap:     &observation.Tap{Namespace: "trawl-system", Name: "tap", UID: "tap-1"},
		Target:  observation.Target{Node: "sensor-01", Interface: "enp5s0"},
		Now:     func() time.Time { return fixed },
	}
}

const validAlert = `{"timestamp":"2026-08-29T11:59:30.123456+0000","event_type":"alert","src_ip":"10.0.0.1","src_port":1234,"dest_ip":"10.0.0.2","dest_port":443,"proto":"TCP","community_id":"1:abc=","alert":{"signature_id":2019401,"rev":1,"signature":"test","category":"cat","severity":2}}`

func TestTailerEmitsValidRecords(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	if err := os.WriteFile(path, []byte(validAlert+"\n"+validAlert+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := &collector{}
	tl := suricataTailer(t, path, c)
	runTailer(t, tl, 2)

	emitted, rejects := c.counts()
	if emitted != 2 {
		t.Errorf("emitted %d records, want 2", emitted)
	}
	if len(rejects) != 0 {
		t.Errorf("unexpected rejects: %v", rejects)
	}
}

func TestMalformedRecordDoesNotStopItsNeighbours(t *testing.T) {
	// FR-016. This is the property that matters most in the tailer: an analyzer
	// emitting one bad line must not blind the sensor for everything after it.
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	content := validAlert + "\n" +
		`{"event_type":"alert"` + "\n" + // truncated JSON
		validAlert + "\n" +
		`not json at all` + "\n" +
		validAlert + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := &collector{}
	tl := suricataTailer(t, path, c)
	runTailer(t, tl, 5)

	emitted, rejects := c.counts()
	if emitted != 3 {
		t.Errorf("emitted %d valid records, want 3 — a bad line stopped the stream", emitted)
	}
	if len(rejects) != 2 {
		t.Errorf("recorded %d rejects, want 2", len(rejects))
	}
	if got := tl.Counters().Malformed; got != 2 {
		t.Errorf("malformed counter = %d, want 2", got)
	}
}

func TestUnsupportedAndMalformedAreCountedSeparately(t *testing.T) {
	// An operator needs to tell "the analyzer emits a record type we do not
	// model" from "the analyzer is producing garbage". Only the second is an
	// incident.
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	content := `{"timestamp":"2026-08-29T11:59:30.000000+0000","event_type":"dns","dns":{}}` + "\n" +
		`{"broken":` + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := &collector{}
	tl := suricataTailer(t, path, c)
	runTailer(t, tl, 2)

	counters := tl.Counters()
	if counters.Unsupported != 1 {
		t.Errorf("unsupported = %d, want 1", counters.Unsupported)
	}
	if counters.Malformed != 1 {
		t.Errorf("malformed = %d, want 1", counters.Malformed)
	}
}

func TestRejectFingerprintsNeverCarryContent(t *testing.T) {
	// A malformed record can contain traffic data, including credentials in a
	// cleartext protocol. Only a hash is reported.
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	secret := "hunter2trombone"
	if err := os.WriteFile(path, []byte(`{"bad":"`+secret+`"`+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := &collector{}
	tl := suricataTailer(t, path, c)
	runTailer(t, tl, 1)

	c.mu.Lock()
	defer c.mu.Unlock()
	for _, fp := range c.fingerprints {
		if strings.Contains(fp, secret) {
			t.Errorf("reject fingerprint carried record content: %q", fp)
		}
	}
	if len(c.fingerprints) == 0 {
		t.Fatal("no reject recorded")
	}
}

func TestRepeatedBadProducerHasAStableFingerprint(t *testing.T) {
	// The fingerprint exists so an operator can tell one repeating bad producer
	// from many distinct failures without storing what it produced.
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	bad := `{"broken":` + "\n"
	if err := os.WriteFile(path, []byte(bad+bad+bad), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := &collector{}
	tl := suricataTailer(t, path, c)
	runTailer(t, tl, 3)

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.fingerprints) < 3 {
		t.Fatalf("got %d fingerprints, want 3", len(c.fingerprints))
	}
	first := c.fingerprints[0]
	for _, fp := range c.fingerprints[1:3] {
		if fp != first {
			t.Errorf("identical bad lines produced different fingerprints: %q vs %q", first, fp)
		}
	}
}

func TestOversizedLineIsRejectedWithoutStoppingTheStream(t *testing.T) {
	// Reading an unbounded line into memory is how a sensor OOMs on corrupt
	// input. The line is discarded, counted, and the reader resynchronizes.
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")

	huge := `{"x":"` + strings.Repeat("A", MaxLineBytes+1024) + `"}`
	content := huge + "\n" + validAlert + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := &collector{}
	tl := suricataTailer(t, path, c)
	runTailer(t, tl, 2)

	emitted, _ := c.counts()
	if emitted != 1 {
		t.Errorf("emitted %d records after an oversized line, want 1", emitted)
	}
	if tl.Counters().Malformed == 0 {
		t.Error("oversized line was not counted as malformed")
	}
}

func TestTailerFollowsAppendedRecords(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	if err := os.WriteFile(path, []byte(validAlert+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := &collector{}
	tl := suricataTailer(t, path, c)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = tl.Run(ctx)
		close(done)
	}()

	waitFor(t, func() bool { return tl.Counters().Accepted >= 1 })

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, err := f.WriteString(validAlert + "\n"); err != nil {
		t.Fatalf("append: %v", err)
	}
	_ = f.Close()

	waitFor(t, func() bool { return tl.Counters().Accepted >= 2 })
	cancel()
	<-done

	if got := tl.Counters().Accepted; got < 2 {
		t.Errorf("accepted %d records, want at least 2", got)
	}
}

func TestTailerReopensAfterRotation(t *testing.T) {
	// Analyzers rotate their own logs. A tailer holding the old inode would go
	// silent while the analyzer kept writing, and the only symptom would be an
	// absence of data.
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	if err := os.WriteFile(path, []byte(validAlert+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := &collector{}
	tl := suricataTailer(t, path, c)

	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = tl.Run(ctx)
		close(done)
	}()

	waitFor(t, func() bool { return tl.Counters().Accepted >= 1 })

	// Rotate: move the old file aside and create a new one, as logrotate does.
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if err := os.WriteFile(path, []byte(validAlert+"\n"+validAlert+"\n"), 0o600); err != nil {
		t.Fatalf("write rotated file: %v", err)
	}

	waitFor(t, func() bool { return tl.Counters().Accepted >= 3 })
	cancel()
	<-done

	if got := tl.Counters().Accepted; got < 3 {
		t.Errorf("accepted %d records after rotation, want at least 3", got)
	}
}

func TestTailerWaitsForAFileThatDoesNotExistYet(t *testing.T) {
	// Sensor startup must not depend on analyzer startup ordering; the analyzer
	// may not have created its log when the sidecar starts.
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")

	c := &collector{}
	tl := suricataTailer(t, path, c)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = tl.Run(ctx)
		close(done)
	}()

	time.Sleep(300 * time.Millisecond)
	if err := os.WriteFile(path, []byte(validAlert+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	waitFor(t, func() bool { return tl.Counters().Accepted >= 1 })
	cancel()
	<-done

	if tl.Counters().Accepted == 0 {
		t.Error("tailer did not pick up a file created after it started")
	}
}

func TestTailerStopsOnContextCancel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	if err := os.WriteFile(path, []byte(validAlert+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	tl := suricataTailer(t, path, &collector{})
	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan error, 1)
	go func() { done <- tl.Run(ctx) }()

	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v on cancel, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Rejections had a callback and acceptances did not, so
// trawl_sensor_records_total only ever counted failures. The counter went
// silent exactly when the sensor started working, which is the wrong way round
// for a metric an operator uses to confirm records are flowing.
func TestTailerReportsAcceptancesAndLastRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "in.log")
	if err := os.WriteFile(path, []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var accepted atomic.Int64
	n := SuricataNormalizerFor(t)
	tl := &Tailer{
		Path: path,
		Parse: func(line []byte) (*observation.Observation, error) {
			obs, _, err := n.Normalize(line)
			return obs, err
		},
		Emit:     func(*observation.Observation, string) error { return nil },
		OnAccept: func() { accepted.Add(1) },
	}

	if _, ok := tl.LastRecord(); ok {
		t.Error("a tailer that has read nothing reports a last-record time")
	}

	tl.process([]byte(validAlert))

	if got := accepted.Load(); got != 1 {
		t.Errorf("OnAccept called %d times, want 1", got)
	}
	if got := tl.Counters().Accepted; got != 1 {
		t.Errorf("Accepted = %d, want 1", got)
	}
	ts, ok := tl.LastRecord()
	if !ok {
		t.Fatal("no last-record time after accepting a record")
	}
	if time.Since(ts) > time.Minute {
		t.Errorf("last-record time %v is not recent", ts)
	}
}
