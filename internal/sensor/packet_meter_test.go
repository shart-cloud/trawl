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
	"testing"
	"time"

	"trawl.cloud/trawl/internal/observation"
)

func at(seconds int) time.Time {
	return time.Date(2026, 9, 1, 12, 0, seconds, 0, time.UTC)
}

func i64(v int64) *int64 { return &v }

func TestAMeterWithNoStatsClaimsNothing(t *testing.T) {
	// FR-039 draws the line between zero and unmeasured. A sensor that has not
	// yet seen a stats record has not established that no packets arrived.
	got := NewPacketMeter(DiscardPackets).Counters()

	if got.PacketsObserved != 0 {
		t.Errorf("packets observed = %d before any stats record, want 0",
			got.PacketsObserved)
	}
	if got.KernelDrops != nil {
		t.Errorf("kernel drops = %v before any stats record, want nil unreported",
			*got.KernelDrops)
	}
	if got.LastPacketTime != nil {
		t.Errorf("last packet time = %v before any stats record, want nil",
			*got.LastPacketTime)
	}
}

func TestAMeterReportsWhatTheCaptureBoundarySaw(t *testing.T) {
	m := NewPacketMeter(DiscardPackets)
	m.Observe(&observation.SuricataStats{
		KernelPackets: i64(1200), KernelDrops: i64(3), Timestamp: at(10),
	})

	got := m.Counters()
	if got.PacketsObserved != 1200 {
		t.Errorf("packets observed = %d, want 1200", got.PacketsObserved)
	}
	if got.KernelDrops == nil || *got.KernelDrops != 3 {
		t.Errorf("kernel drops = %v, want 3", got.KernelDrops)
	}
	if got.LastPacketTime == nil || !got.LastPacketTime.Equal(at(10)) {
		t.Errorf("last packet time = %v, want %v", got.LastPacketTime, at(10))
	}
}

func TestAMeterAccumulatesAcrossStatsRecords(t *testing.T) {
	// Suricata's counters are cumulative for its process, so the meter must
	// track the latest value rather than adding each record to the last.
	m := NewPacketMeter(DiscardPackets)
	m.Observe(&observation.SuricataStats{KernelPackets: i64(100), Timestamp: at(10)})
	m.Observe(&observation.SuricataStats{KernelPackets: i64(250), Timestamp: at(20)})

	if got := m.Counters().PacketsObserved; got != 250 {
		t.Errorf("packets observed = %d after 100 then 250, want 250", got)
	}
}

func TestAnAnalyzerRestartDoesNotLoseThePacketsItAlreadyCounted(t *testing.T) {
	// Suricata's counters reset when Suricata restarts, which the sensor
	// survives - the reporter's instance ID only distinguishes a *sensor*
	// restart. Reporting the raw value would make the count jump backwards,
	// and a consumer reads a count going backwards as traffic having stopped.
	m := NewPacketMeter(DiscardPackets)
	m.Observe(&observation.SuricataStats{KernelPackets: i64(900), Timestamp: at(10)})
	m.Observe(&observation.SuricataStats{KernelPackets: i64(40), Timestamp: at(20)})

	if got := m.Counters().PacketsObserved; got != 940 {
		t.Errorf("packets observed = %d after 900 then a reset to 40, want 940", got)
	}
}

func TestAMeterDoesNotClaimAPacketArrivedWhenTheCountStoodStill(t *testing.T) {
	// A stats record is emitted on a timer whether or not traffic arrived. Its
	// timestamp says when Suricata reported, not when a packet was seen, so
	// advancing last-packet-time on a flat counter would invent an arrival and
	// make a dead interface look live.
	m := NewPacketMeter(DiscardPackets)
	m.Observe(&observation.SuricataStats{KernelPackets: i64(500), Timestamp: at(10)})
	m.Observe(&observation.SuricataStats{KernelPackets: i64(500), Timestamp: at(60)})

	got := m.Counters()
	if got.LastPacketTime == nil || !got.LastPacketTime.Equal(at(10)) {
		t.Errorf("last packet time = %v after a flat counter, want it to stay at %v",
			got.LastPacketTime, at(10))
	}
	if got.PacketsObserved != 500 {
		t.Errorf("packets observed = %d, want 500", got.PacketsObserved)
	}
}

func TestAMeterDistinguishesZeroDropsFromUnreportedDrops(t *testing.T) {
	// FR-039 again, at the point the value enters the sensor rather than the
	// point it leaves: reporting zero for an analyzer that said nothing about
	// drops claims a clean capture nobody measured.
	unreported := NewPacketMeter(DiscardPackets)
	unreported.Observe(&observation.SuricataStats{KernelPackets: i64(10), Timestamp: at(10)})
	if got := unreported.Counters().KernelDrops; got != nil {
		t.Errorf("kernel drops = %d when the record reported none, want nil", *got)
	}

	zero := NewPacketMeter(DiscardPackets)
	zero.Observe(&observation.SuricataStats{
		KernelPackets: i64(10), KernelDrops: i64(0), Timestamp: at(10),
	})
	if got := zero.Counters().KernelDrops; got == nil || *got != 0 {
		t.Errorf("kernel drops = %v when the record reported 0, want a pointer to 0", got)
	}
}

func TestAMeterFallsBackToDecoderPacketsAndDoesNotMixCounters(t *testing.T) {
	// Not every capture method reports kernel counters. Falling back keeps a
	// working tap from reporting nothing, but the two counters measure
	// different points, so a switch between them re-baselines instead of
	// subtracting one from the other.
	m := NewPacketMeter(DiscardPackets)
	m.Observe(&observation.SuricataStats{DecoderPackets: i64(70), Timestamp: at(10)})
	if got := m.Counters().PacketsObserved; got != 70 {
		t.Errorf("packets observed = %d from decoder packets alone, want 70", got)
	}

	// The switch itself adds nothing. This case previously expected 75 - the
	// new counter's whole cumulative value added on top - which read as
	// reasonable only because 5 is a small number. Both counters count from the
	// same process start, so in production the value arriving here is the
	// history over again; see the double-counting regression below.
	m.Observe(&observation.SuricataStats{KernelPackets: i64(5), Timestamp: at(20)})
	if got := m.Counters().PacketsObserved; got != 70 {
		t.Errorf("packets observed = %d after switching counter source, want 70", got)
	}

	// From the new baseline it measures normally again.
	m.Observe(&observation.SuricataStats{KernelPackets: i64(9), Timestamp: at(30)})
	if got := m.Counters().PacketsObserved; got != 74 {
		t.Errorf("packets observed = %d after the kernel counter advanced by 4, want 74", got)
	}
}

func TestAMeterIgnoresAStatsRecordWithNoCounters(t *testing.T) {
	m := NewPacketMeter(DiscardPackets)
	m.Observe(&observation.SuricataStats{KernelPackets: i64(42), Timestamp: at(10)})
	m.Observe(&observation.SuricataStats{Timestamp: at(20)})
	m.Observe(nil)

	got := m.Counters()
	if got.PacketsObserved != 42 {
		t.Errorf("packets observed = %d, want the last measured 42", got.PacketsObserved)
	}
	if got.LastPacketTime == nil || !got.LastPacketTime.Equal(at(10)) {
		t.Errorf("last packet time = %v, want it unchanged at %v", got.LastPacketTime, at(10))
	}
}

func TestAMeterReportsEachMeasurementToItsObserver(t *testing.T) {
	// The observer is how the counters reach the metrics plane. Reporting the
	// running total instead of the increment would make a Prometheus counter
	// climb quadratically, so what it hands over is what this measurement
	// added.
	var got []Increment
	m := NewPacketMeter(func(inc Increment) { got = append(got, inc) })

	m.Observe(&observation.SuricataStats{KernelPackets: i64(100), KernelDrops: i64(2), Timestamp: at(10)})
	m.Observe(&observation.SuricataStats{KernelPackets: i64(250), Timestamp: at(20)})
	m.Observe(&observation.SuricataStats{KernelPackets: i64(250), Timestamp: at(30)})

	if len(got) != 3 {
		t.Fatalf("observer saw %d measurements, want 3", len(got))
	}
	if got[0].Packets != 100 || got[1].Packets != 150 {
		t.Errorf("increments were %d then %d, want 100 then 150",
			got[0].Packets, got[1].Packets)
	}
	if got[2].Packets != 0 {
		t.Errorf("a flat counter reported %d new packets, want 0", got[2].Packets)
	}
	if !got[1].LastPacket.Equal(at(20)) {
		t.Errorf("last packet = %v, want %v", got[1].LastPacket, at(20))
	}
	if !got[2].LastPacket.IsZero() {
		t.Errorf("a flat counter reported an arrival at %v, want none", got[2].LastPacket)
	}
	// Drops are cumulative and carry forward even when a later record omits
	// them, because the analyzer having stopped mentioning drops is not the
	// analyzer reporting zero.
	if got[1].Drops == nil || *got[1].Drops != 2 {
		t.Errorf("drops = %v on the second measurement, want a carried-forward 2", got[1].Drops)
	}
}

func TestAMeterWithNoObserverStillMeasures(t *testing.T) {
	// A nil observer is a caller who forgot; the meter must not panic on the
	// tailer's hot path because of it.
	m := NewPacketMeter(nil)
	m.Observe(&observation.SuricataStats{KernelPackets: i64(7), Timestamp: at(10)})
	if got := m.Counters().PacketsObserved; got != 7 {
		t.Errorf("packets observed = %d, want 7", got)
	}
}

func TestAFallbackToTheOtherCounterDoesNotCountTheSamePacketsTwice(t *testing.T) {
	// Both counters count the same traffic from the analyzer's start, at
	// different points in its pipeline: decoder.pkts tracks kernel_packets less
	// what the kernel dropped. So when a single stats record omits the kernel
	// counter - which happens on capture-method reinitialisation - the decoder
	// total it carries covers packets this meter has already counted. Adding it
	// whole made PacketsObserved jump by the whole history, and a status that
	// doubles on a hiccup is not a packet count.
	m := NewPacketMeter(DiscardPackets)
	m.Observe(&observation.SuricataStats{KernelPackets: i64(5_000_000), Timestamp: at(10)})
	m.Observe(&observation.SuricataStats{DecoderPackets: i64(4_999_000), Timestamp: at(20)})

	if got := m.Counters().PacketsObserved; got != 5_000_000 {
		t.Errorf("packets observed = %d after falling back to the decoder counter, want 5000000", got)
	}

	// Having adopted the decoder counter as the baseline, it measures from
	// there: the next record's growth is real and is counted.
	m.Observe(&observation.SuricataStats{DecoderPackets: i64(4_999_500), Timestamp: at(30)})
	if got := m.Counters().PacketsObserved; got != 5_000_500 {
		t.Errorf("packets observed = %d after the decoder counter advanced by 500, want 5000500", got)
	}

	// And switching back does not re-count the kernel counter's history either.
	m.Observe(&observation.SuricataStats{KernelPackets: i64(5_001_000), Timestamp: at(40)})
	if got := m.Counters().PacketsObserved; got != 5_000_500 {
		t.Errorf("packets observed = %d after switching back to the kernel counter, want 5000500", got)
	}
}
