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
	"sync"
	"time"

	"trawl.cloud/trawl/internal/observation"
)

// counterSource names which of Suricata's counters a reading came from.
//
// The two count at different points in the pipeline, so a value from one is not
// comparable with a value from the other and the difference between them is not
// a number of packets.
type counterSource int

const (
	sourceNone counterSource = iota
	sourceKernel
	sourceDecoder
)

// PacketMeter turns an analyzer's periodic stats records into the capture
// boundary counters a target's status reports.
//
// Suricata already parses these - SuricataNormalizer lifts kernel_packets and
// kernel_drops out of every EVE stats record - and StatusReporter already has a
// slot for them. Until this existed, the sensor discarded the stats value at
// the point it was produced and reported a permanently empty struct, so a tap
// capturing traffic perfectly well said PacketsObserved=False forever.
//
// The tailer goroutine writes and the status reporter reads, so this locks for
// the same reason DuplicateCache does.
type PacketMeter struct {
	mu sync.Mutex

	// observed accumulates rather than mirroring the analyzer's counter.
	// Suricata's counters are cumulative for the Suricata *process*, which the
	// sensor outlives: an analyzer restart resets them to zero while the
	// StatusReporter's instance ID - which exists to explain exactly this kind
	// of reset - stays the same, because the sensor did not restart. Reporting
	// the raw value would make the count jump backwards, and a consumer reads
	// a count going backwards as traffic having stopped.
	observed int64

	// last is the previous raw reading, and lastSource which counter it came
	// from. A reading below its predecessor, or one from a different counter,
	// starts a new segment instead of producing a negative delta.
	last       int64
	lastSource counterSource

	// drops is nil until an analyzer reports drops, because zero drops and
	// unmeasured drops are different answers (FR-039).
	drops *int64

	// lastPacket advances only when the count actually grew. Stats records are
	// emitted on a timer whether or not traffic arrived, so their timestamp
	// says when the analyzer reported, not when a packet was seen.
	lastPacket *time.Time
}

// NewPacketMeter returns a meter that has measured nothing.
func NewPacketMeter() *PacketMeter { return &PacketMeter{} }

// Observe folds one stats record into the running counters.
//
// A nil record, or one carrying no packet counter, leaves the measurement
// untouched: it is an absence of information, not a report of zero.
func (m *PacketMeter) Observe(stats *observation.SuricataStats) {
	if stats == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if stats.KernelDrops != nil {
		d := *stats.KernelDrops
		m.drops = &d
	}

	raw, source := packetReading(stats)
	if source == sourceNone {
		return
	}

	switch {
	case source != m.lastSource:
		// A different counter, so the previous reading is not a baseline for
		// this one. Everything it reports is new to this meter.
		m.observed += raw
	case raw < m.last:
		// The analyzer restarted. The packets it counted before the reset were
		// still observed, so they are kept and the new run is added to them.
		m.observed += raw
	default:
		m.observed += raw - m.last
	}

	grew := raw != m.last || source != m.lastSource
	m.last, m.lastSource = raw, source

	if grew && raw > 0 {
		seen := stats.Timestamp
		m.lastPacket = &seen
	}
}

// Counters reports what has been measured so far.
func (m *PacketMeter) Counters() PacketCounters {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := PacketCounters{PacketsObserved: m.observed}
	if m.drops != nil {
		d := *m.drops
		out.KernelDrops = &d
	}
	if m.lastPacket != nil {
		t := *m.lastPacket
		out.LastPacketTime = &t
	}
	return out
}

// packetReading picks the counter to measure with.
//
// Kernel counters are preferred because they describe the capture boundary
// itself - what the kernel handed the analyzer - which is what the status field
// claims to report. Decoder packets are the fallback for a capture method that
// reports no kernel counters, so that a working tap reports what it saw rather
// than nothing at all.
func packetReading(stats *observation.SuricataStats) (int64, counterSource) {
	if stats.KernelPackets != nil {
		return *stats.KernelPackets, sourceKernel
	}
	if stats.DecoderPackets != nil {
		return *stats.DecoderPackets, sourceDecoder
	}
	return 0, sourceNone
}
