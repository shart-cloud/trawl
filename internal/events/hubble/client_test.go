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

package hubble

import (
	"testing"
	"time"
)

func TestWatermarkOnlyMovesForward(t *testing.T) {
	// Hubble can deliver slightly out of order. A watermark that moved
	// backwards would re-request flows already handled on every subsequent
	// reconnect, growing the replay window without bound.
	c := &Client{}

	later := time.Date(2026, 8, 29, 12, 0, 30, 0, time.UTC)
	earlier := later.Add(-10 * time.Second)

	c.advanceWatermark(later)
	c.advanceWatermark(earlier)

	if got := c.Watermark(); !got.Equal(later) {
		t.Errorf("watermark = %v, want it to stay at %v", got, later)
	}
}

func TestResumePointOverlapsTheWatermark(t *testing.T) {
	// Hubble's stream is lossy across disconnects and has no cursor, so the
	// choice is to re-read a little or skip a little. Duplicate flows carry
	// stable IDs and collapse downstream; a skipped denied flow is a trigger
	// that never fires and evidence nobody knows is missing.
	c := &Client{}
	at := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	c.advanceWatermark(at)

	resume := c.resumePoint()
	if !resume.Before(at) {
		t.Errorf("resume point %v is not before the watermark %v", resume, at)
	}
	if got := at.Sub(resume); got != replayOverlap {
		t.Errorf("overlap = %v, want %v", got, replayOverlap)
	}
}

func TestResumePointIsZeroBeforeAnyFlow(t *testing.T) {
	// A first connection must not ask for flows from an arbitrary point in the
	// past; it follows from now.
	c := &Client{}
	if got := c.resumePoint(); !got.IsZero() {
		t.Errorf("resume point = %v before any flow, want zero", got)
	}
}

func TestConnectionChangesAreReportedOnce(t *testing.T) {
	// trawl_trigger_source_connected is a gauge an operator alerts on. Repeated
	// identical transitions would produce noise rather than signal.
	var changes []bool
	c := &Client{OnConnectionChange: func(v bool) { changes = append(changes, v) }}

	c.setConnected(true)
	c.setConnected(true)
	c.setConnected(false)
	c.setConnected(false)

	if len(changes) != 2 {
		t.Fatalf("got %d change callbacks, want 2", len(changes))
	}
	if changes[0] != true || changes[1] != false {
		t.Errorf("changes = %v, want [true false]", changes)
	}
}

func TestGapsAreReportedWithAReason(t *testing.T) {
	// FR-039 requires known coverage gaps be visible. Silently thinner evidence
	// is the failure mode an analyst cannot detect.
	var reasons []string
	c := &Client{OnGap: func(r string) { reasons = append(reasons, r) }}

	c.reportGap("relay_lost_events")
	c.reportGap("stream_error")

	if len(reasons) != 2 {
		t.Fatalf("got %d gap reports, want 2", len(reasons))
	}
	for _, r := range reasons {
		if r == "" {
			t.Error("a gap was reported with no reason")
		}
	}
}

func TestClientRequiresAnEndpoint(t *testing.T) {
	if _, err := NewClient(hubbleConfig(""), &Normalizer{}); err == nil {
		t.Fatal("a client was created with no endpoint")
	}
}

func TestClientRequiresUsableTLSMaterial(t *testing.T) {
	// Hubble Relay serves every connection in the cluster. An unauthenticated
	// reader would be a cluster-wide traffic disclosure, so missing material is
	// a hard failure rather than a fallback to plaintext.
	if _, err := NewClient(hubbleConfig("hubble-relay:80"), &Normalizer{}); err == nil {
		t.Fatal("a client was created without usable TLS material")
	}
}
