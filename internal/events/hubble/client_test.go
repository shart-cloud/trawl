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
	"context"
	"testing"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"

	"trawl.cloud/trawl/internal/observation"
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

func TestTheWorkerValidatesWhatItEmits(t *testing.T) {
	// The sensor validates every record before emitting it and counts what it
	// rejects, because Loki enforces no schema: an off-contract record is
	// stored happily and only discovered when a dashboard query silently
	// returns nothing (FR-016). The event worker did neither. It normalized a
	// flow and handed the result straight to the emitter.
	//
	// That is how an incomplete verdict enum survived: a quarter of the
	// cluster_flow records on a live cluster did not satisfy the schema, and
	// the only symptom was that they were there.
	var rejected []string
	c := &Client{
		normalizer: normalizer(),
		OnReject:   func(reason string) { rejected = append(rejected, reason) },
	}

	if obs, ok := c.accept(forwardedFlow()); !ok || obs == nil {
		t.Error("a well-formed forwarded flow was not accepted")
	}
	if len(rejected) != 0 {
		t.Errorf("a well-formed flow was counted as rejected: %v", rejected)
	}

	// A verdict from a Cilium newer than the one Trawl was built against. The
	// record is uninterpretable, so it must be counted and dropped rather than
	// stored where an analyst would read it as evidence.
	future := forwardedFlow()
	future.Verdict = flowpb.Verdict(99)
	if _, ok := c.accept(future); ok {
		t.Error("a flow carrying a verdict Cilium does not define was accepted")
	}
	if len(rejected) != 1 {
		t.Fatalf("an invalid record produced %d rejections, want 1", len(rejected))
	}

	// A flow the normalizer cannot parse was already dropped, but silently.
	// A dropped record that is not counted is indistinguishable from traffic
	// that never happened.
	unparseable := forwardedFlow()
	unparseable.Time = nil
	if _, ok := c.accept(unparseable); ok {
		t.Error("a flow with no timestamp was accepted")
	}
	if len(rejected) != 2 {
		t.Errorf("an unparseable flow produced %d total rejections, want 2", len(rejected))
	}
}

func TestResumeCoversTheLongestThresholdWindow(t *testing.T) {
	// A drop policy with a threshold counts flows over a rolling window. If a
	// reconnect resumes only the default overlap, every flow older than that is
	// gone from the worker's view and the window rebuilds from almost nothing -
	// so a threshold that was one flow short of firing silently never fires,
	// and the burst it was watching for passes unrecorded.
	//
	// The worker sets this to the widest window across armed policies, so the
	// replay is as long as the evidence any policy still needs and no longer.
	at := time.Date(2026, 9, 9, 22, 0, 0, 0, time.UTC)
	c := &Client{replayWindow: 15 * time.Minute}
	c.advanceWatermark(at)

	if got, want := c.resumePoint(), at.Add(-15*time.Minute); !got.Equal(want) {
		t.Errorf("resume point = %s, want %s", got, want)
	}
}

func TestResumeNeverShortensBelowTheDefaultOverlap(t *testing.T) {
	// A policy with a threshold window shorter than the overlap - or no armed
	// threshold policy at all - must not shrink the replay. The overlap exists
	// for a different reason: Hubble's stream is lossy across a disconnect, so
	// re-reading a little is what stops a denied flow being skipped outright.
	at := time.Date(2026, 9, 9, 22, 0, 0, 0, time.UTC)

	for name, window := range map[string]time.Duration{
		"no threshold policies": 0,
		"shorter than overlap":  5 * time.Second,
	} {
		t.Run(name, func(t *testing.T) {
			c := &Client{replayWindow: window}
			c.advanceWatermark(at)

			if got, want := c.resumePoint(), at.Add(-replayOverlap); !got.Equal(want) {
				t.Errorf("resume point = %s, want %s", got, want)
			}
		})
	}
}

func TestAnOutageBeyondTheReplayBoundIsReportedAsUnrecoverable(t *testing.T) {
	// Hubble keeps a ring buffer and offers no cursor, so flows that aged out
	// of it while the worker was disconnected cannot be recovered by asking
	// again. That is a different fact from an ordinary reconnect gap, and it
	// has to be said differently: a gap the worker closed by re-reading is
	// recovered coverage, while this one is evidence that no longer exists.
	//
	// Reported rather than inferred, because the alternative is a policy whose
	// counters look healthy over a window it never actually saw.
	at := time.Date(2026, 9, 9, 22, 0, 0, 0, time.UTC)
	var reasons []string
	c := &Client{
		replayWindow: time.Minute,
		OnGap:        func(r string) { reasons = append(reasons, r) },
		now:          func() time.Time { return at.Add(2 * time.Hour) },
	}
	c.advanceWatermark(at)

	c.checkReplayable()

	if len(reasons) != 1 || reasons[0] != GapUnrecoverable {
		t.Errorf("gap reasons = %v, want exactly [%s]", reasons, GapUnrecoverable)
	}
}

func TestAShortOutageIsNotReportedAsUnrecoverable(t *testing.T) {
	// The counterpart: a brief relay restart is fully covered by the replay,
	// and calling that unrecoverable would train an operator to ignore the one
	// signal that means evidence is actually gone.
	at := time.Date(2026, 9, 9, 22, 0, 0, 0, time.UTC)
	var reasons []string
	c := &Client{
		replayWindow: time.Minute,
		OnGap:        func(r string) { reasons = append(reasons, r) },
		now:          func() time.Time { return at.Add(10 * time.Second) },
	}
	c.advanceWatermark(at)

	c.checkReplayable()

	if len(reasons) != 0 {
		t.Errorf("a 10-second outage reported %v", reasons)
	}
}

func TestReconnectSuppressesHandledIDsButDeliversUnseenOutageFlows(t *testing.T) {
	// The reconnect deliberately overlaps the watermark. Stable IDs already
	// handed to the worker must stop here, before either evidence emission or
	// policy evaluation, while a flow that occurred during the outage must pass
	// in the order the relay returned it.
	at := time.Date(2026, 9, 9, 22, 0, 0, 0, time.UTC)
	c := &Client{replayWindow: time.Minute}
	var delivered []string
	handle := func(_ context.Context, parsed *ParsedFlow) error {
		delivered = append(delivered, parsed.Observation.ID)
		return nil
	}
	parsed := func(id string, eventTime time.Time) *ParsedFlow {
		obs := &observation.Observation{ID: id, EventTime: eventTime}
		return &ParsedFlow{Observation: obs, EventTime: eventTime}
	}

	for _, flow := range []*ParsedFlow{
		parsed("handled-a", at),
		parsed("handled-b", at.Add(20*time.Second)),
	} {
		if err := c.deliver(context.Background(), flow, handle); err != nil {
			t.Fatalf("initial delivery: %v", err)
		}
	}
	for _, flow := range []*ParsedFlow{
		parsed("handled-a", at),
		parsed("outage-unseen", at.Add(10*time.Second)),
		parsed("handled-b", at.Add(20*time.Second)),
	} {
		if err := c.deliver(context.Background(), flow, handle); err != nil {
			t.Fatalf("reconnect delivery: %v", err)
		}
	}

	want := []string{"handled-a", "handled-b", "outage-unseen"}
	if len(delivered) != len(want) {
		t.Fatalf("delivered IDs = %v, want %v", delivered, want)
	}
	for i := range want {
		if delivered[i] != want[i] {
			t.Errorf("delivered IDs = %v, want %v", delivered, want)
			break
		}
	}
}

func TestHandledIDsExpireBehindTheReplayHorizon(t *testing.T) {
	// The cursor lives for the process lifetime and denied flows can be
	// continuous. Retaining identities Hubble can no longer return would turn
	// reconnect safety into an unbounded memory leak.
	at := time.Date(2026, 9, 9, 22, 0, 0, 0, time.UTC)
	c := &Client{replayWindow: time.Minute}
	c.remember("old-a", at)
	c.remember("old-b", at.Add(10*time.Second))
	c.remember("current", at.Add(2*time.Minute))

	if len(c.handled) != 1 {
		t.Fatalf("retained handled IDs = %v, want only the replayable identity", c.handled)
	}
	if _, ok := c.handled["current"]; !ok {
		t.Errorf("current identity was pruned: %v", c.handled)
	}
}
