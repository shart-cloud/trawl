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
	"testing"
	"time"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/observation"
)

func port(p int32) *int32 { return &p }

func flowObs(at time.Time, srcIP string, srcPort int32, dstIP string, dstPort int32) *observation.Observation {
	return &observation.Observation{
		EventTime:       at,
		Source:          observation.Source{Kind: observation.SourceSuricata},
		Tap:             &observation.Tap{UID: "tap-1"},
		Target:          observation.Target{Node: "sensor-01", Interface: "enp5s0"},
		ObservationType: observation.TypeSignature,
		Flow: &observation.Flow{
			Protocol:    "tcp",
			Source:      observation.Endpoint{IP: srcIP, Port: port(srcPort)},
			Destination: observation.Endpoint{IP: dstIP, Port: port(dstPort)},
		},
	}
}

func TestDuplicateWithinWindowIsSuspected(t *testing.T) {
	// Mirrored traffic legitimately carries the same packet twice.
	c := NewDuplicateCache(1000)
	at := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

	if got := c.Mark(flowObs(at, "10.0.0.1", 1234, "10.0.0.2", 443)); got != trawlv1alpha1.DuplicationNotDetected {
		t.Errorf("first sighting = %q, want NotDetected", got)
	}
	if got := c.Mark(flowObs(at.Add(200*time.Microsecond), "10.0.0.1", 1234, "10.0.0.2", 443)); got != trawlv1alpha1.DuplicationSuspected {
		t.Errorf("duplicate within window = %q, want Suspected", got)
	}
	if c.Suspected() != 1 {
		t.Errorf("suspected count = %d, want 1", c.Suspected())
	}
}

func TestIdenticalFlowOutsideWindowIsNotADuplicate(t *testing.T) {
	// A periodic beacon produces identical tuples minutes apart. Marking those
	// as duplicates would erase exactly the pattern an analyst is looking for.
	c := NewDuplicateCache(1000)
	at := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

	c.Mark(flowObs(at, "10.0.0.1", 1234, "10.0.0.2", 443))
	got := c.Mark(flowObs(at.Add(30*time.Second), "10.0.0.1", 1234, "10.0.0.2", 443))

	if got != trawlv1alpha1.DuplicationNotDetected {
		t.Errorf("repeat after 30s = %q, want NotDetected", got)
	}
}

func TestDirectionIsNormalized(t *testing.T) {
	// A mirror can present the same packet from either side. Without direction
	// normalization each copy would look like a distinct flow.
	c := NewDuplicateCache(1000)
	at := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

	c.Mark(flowObs(at, "10.0.0.1", 1234, "10.0.0.2", 443))
	got := c.Mark(flowObs(at.Add(100*time.Microsecond), "10.0.0.2", 443, "10.0.0.1", 1234))

	if got != trawlv1alpha1.DuplicationSuspected {
		t.Errorf("reversed direction = %q, want Suspected", got)
	}
}

func TestDifferentFlowsAreNotDuplicates(t *testing.T) {
	c := NewDuplicateCache(1000)
	at := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

	c.Mark(flowObs(at, "10.0.0.1", 1234, "10.0.0.2", 443))
	for _, tc := range []struct {
		name  string
		sIP   string
		sPort int32
		dIP   string
		dPort int32
	}{
		{"different source ip", "10.0.0.9", 1234, "10.0.0.2", 443},
		{"different source port", "10.0.0.1", 9999, "10.0.0.2", 443},
		{"different dest port", "10.0.0.1", 1234, "10.0.0.2", 8443},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := c.Mark(flowObs(at.Add(10*time.Microsecond), tc.sIP, tc.sPort, tc.dIP, tc.dPort))
			if got == trawlv1alpha1.DuplicationSuspected {
				t.Errorf("%s was marked as a duplicate", tc.name)
			}
		})
	}
}

func TestDifferentTargetsAreNotDuplicates(t *testing.T) {
	// The same packet observed on two nodes is two genuine observations. The
	// fingerprint includes the target so cross-node sightings stay distinct.
	c := NewDuplicateCache(1000)
	at := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

	first := flowObs(at, "10.0.0.1", 1234, "10.0.0.2", 443)
	second := flowObs(at, "10.0.0.1", 1234, "10.0.0.2", 443)
	second.Target.Node = "sensor-02"

	c.Mark(first)
	if got := c.Mark(second); got == trawlv1alpha1.DuplicationSuspected {
		t.Error("the same packet on a different node was marked as a duplicate")
	}
}

func TestObservationsWithoutFlowReportUnknown(t *testing.T) {
	// A certificate or file record has no tuple to normalize. Unknown is the
	// truthful answer; NotDetected would claim a check we did not run.
	c := NewDuplicateCache(1000)
	obs := &observation.Observation{
		EventTime:       time.Now(),
		Source:          observation.Source{Kind: observation.SourceZeek},
		Target:          observation.Target{Node: "sensor-01"},
		ObservationType: observation.TypeCertificate,
	}

	if got := c.Mark(obs); got != trawlv1alpha1.DuplicationUnknown {
		t.Errorf("flowless record = %q, want Unknown", got)
	}
	if c.Unknown() != 1 {
		t.Errorf("unknown count = %d, want 1", c.Unknown())
	}
}

func TestCacheIsBoundedAndEvicts(t *testing.T) {
	// A sensor on a busy mirror must not trade unbounded memory for duplicate
	// detection.
	const max = 100
	c := NewDuplicateCache(max)
	at := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

	for i := range int32(max * 3) {
		c.Mark(flowObs(at.Add(time.Duration(i)*time.Second), "10.0.0.1", i, "10.0.0.2", 443))
	}

	if c.Len() > max {
		t.Errorf("cache holds %d entries, want at most %d", c.Len(), max)
	}
	if c.Evicted() == 0 {
		t.Error("no evictions recorded despite exceeding capacity")
	}
}

func TestEvictionDegradesStateToUnknownNotNotDetected(t *testing.T) {
	// Once the window has overflowed, a NotDetected result no longer means
	// anything: the record it would have matched may simply have been evicted.
	// Reporting NotDetected there would claim an absence we cannot support.
	c := NewDuplicateCache(10)
	at := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

	for i := range int32(50) {
		c.Mark(flowObs(at.Add(time.Duration(i)*time.Second), "10.0.0.1", i, "10.0.0.2", 443))
	}

	if got := c.State(); got != trawlv1alpha1.DuplicationUnknown {
		t.Errorf("state after eviction = %q, want Unknown", got)
	}
}

func TestStateReportsSuspectedOnceSeen(t *testing.T) {
	c := NewDuplicateCache(1000)
	at := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

	c.Mark(flowObs(at, "10.0.0.1", 1234, "10.0.0.2", 443))
	if got := c.State(); got != trawlv1alpha1.DuplicationNotDetected {
		t.Errorf("state with one record = %q, want NotDetected", got)
	}

	c.Mark(flowObs(at.Add(time.Microsecond), "10.0.0.1", 1234, "10.0.0.2", 443))
	if got := c.State(); got != trawlv1alpha1.DuplicationSuspected {
		t.Errorf("state after a duplicate = %q, want Suspected", got)
	}
}

func TestEmptyCacheStateIsUnknown(t *testing.T) {
	// Before any record arrives there is no basis for any claim.
	if got := NewDuplicateCache(10).State(); got != trawlv1alpha1.DuplicationUnknown {
		t.Errorf("empty cache state = %q, want Unknown", got)
	}
}

func TestMarkNeverModifiesTheObservation(t *testing.T) {
	// Marking must not discard or alter evidence; deciding two records describe
	// one event is a judgement an analyst may need to overturn.
	c := NewDuplicateCache(1000)
	at := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

	obs := flowObs(at, "10.0.0.1", 1234, "10.0.0.2", 443)
	before := *obs
	c.Mark(obs)
	c.Mark(obs)

	if obs.EventTime != before.EventTime || obs.ObservationType != before.ObservationType {
		t.Error("Mark modified the observation")
	}
	if obs.Flow.Source.IP != before.Flow.Source.IP {
		t.Error("Mark modified the flow")
	}
}

// The cache is written by the tailers and read by the status reporter, which
// publishes from its own goroutine. Sharing one cache across a target's
// analyzers is what lets duplication reach status at all - duplication is a
// property of the target, not of one analyzer, which is why StatusReporter has
// a single Duplicates field - but it means Mark and State run concurrently.
//
// Run with -race. Without the lock this fails there rather than here.
func TestTheCacheSurvivesConcurrentTailersAndStatusReads(t *testing.T) {
	c := NewDuplicateCache(1024)

	var wg sync.WaitGroup
	// Two tailers, as a target with both analyzers has.
	for _, kind := range []observation.SourceKind{observation.SourceZeek, observation.SourceSuricata} {
		wg.Go(func() {
			for i := range 500 {
				at := time.Now().Add(time.Duration(i) * time.Millisecond)
				obs := flowObs(at, "10.0.0.1", 4444, "10.0.0.2", 443)
				obs.Source.Kind = kind
				c.Mark(obs)
			}
		})
	}
	// The status reporter, reading while they write.
	wg.Go(func() {
		for range 500 {
			_ = c.State()
			_ = c.Len()
		}
	})
	wg.Wait()

	if got := c.State(); got == "" {
		t.Error("the cache reported no state after concurrent use")
	}
}
