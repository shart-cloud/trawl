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
	"strings"
	"testing"
	"time"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/content"
)

type fakeAnalyzer struct {
	name       trawlv1alpha1.AnalyzerName
	healthy    bool
	reason     string
	version    string
	lastRecord *time.Time
	counters   Counters
	contentSt  content.Status
}

func (f *fakeAnalyzer) Name() trawlv1alpha1.AnalyzerName { return f.name }
func (f *fakeAnalyzer) Healthy() (bool, string)          { return f.healthy, f.reason }
func (f *fakeAnalyzer) Version() string                  { return f.version }
func (f *fakeAnalyzer) Counters() Counters               { return f.counters }
func (f *fakeAnalyzer) ContentStatus() content.Status    { return f.contentSt }
func (f *fakeAnalyzer) LastRecord() (time.Time, bool) {
	if f.lastRecord == nil {
		return time.Time{}, false
	}
	return *f.lastRecord, true
}

func fixedNow() time.Time { return time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC) }

func healthyReporter() *StatusReporter {
	return &StatusReporter{
		NodeName:   "sensor-01",
		Interface:  "enp5s0",
		InstanceID: "instance-a",
		Now:        fixedNow,
		Analyzers: []AnalyzerObserver{
			&fakeAnalyzer{name: trawlv1alpha1.AnalyzerSuricata, healthy: true, version: "8.0.6"},
			&fakeAnalyzer{name: trawlv1alpha1.AnalyzerZeek, healthy: true, version: "8.0.10"},
		},
	}
}

func TestBuildReportsTargetIdentityAndHeartbeat(t *testing.T) {
	st := healthyReporter().Build()

	if st.NodeName != "sensor-01" || st.Interface != "enp5s0" {
		t.Errorf("target identity = %+v", st)
	}
	if !st.HeartbeatTime.Time.Equal(fixedNow()) {
		t.Errorf("heartbeat = %v", st.HeartbeatTime)
	}
	if st.ReporterInstance != "instance-a" {
		t.Errorf("reporter instance = %q", st.ReporterInstance)
	}
}

func TestReporterInstanceDistinguishesRestartFromStall(t *testing.T) {
	// Counters reset when a sensor restarts. Without knowing the instance
	// changed, a consumer reads that reset as traffic having stopped, which is
	// the opposite of what happened.
	first := healthyReporter()
	first.Packets = func() PacketCounters { return PacketCounters{PacketsObserved: 5000} }
	before := first.Build()

	restarted := healthyReporter()
	restarted.InstanceID = "instance-b"
	restarted.Packets = func() PacketCounters { return PacketCounters{PacketsObserved: 12} }
	after := restarted.Build()

	if before.ReporterInstance == after.ReporterInstance {
		t.Fatal("a restarted sensor reported the same instance ID")
	}
	if after.PacketsObserved >= before.PacketsObserved {
		t.Skip("fixture does not model a counter reset")
	}
}

func TestBuildDistinguishesZeroDropsFromUnreported(t *testing.T) {
	// FR-039: reporting zero when the analyzer said nothing would claim a clean
	// capture that was never measured.
	zero := int64(0)

	withZero := healthyReporter()
	withZero.Packets = func() PacketCounters {
		return PacketCounters{PacketsObserved: 100, KernelDrops: &zero}
	}
	if got := withZero.Build().KernelDrops; got == nil || *got != 0 {
		t.Errorf("explicit zero drops = %v, want a pointer to 0", got)
	}

	unreported := healthyReporter()
	unreported.Packets = func() PacketCounters {
		return PacketCounters{PacketsObserved: 100}
	}
	if got := unreported.Build().KernelDrops; got != nil {
		t.Errorf("unreported drops = %v, want nil", got)
	}
}

func TestBuildOmitsLastPacketTimeWhenNoPacketsSeen(t *testing.T) {
	// A target that has seen nothing must not claim a last-packet time. That
	// field is how an operator tells "quiet link" from "never worked".
	r := healthyReporter()
	r.Packets = func() PacketCounters { return PacketCounters{} }

	if got := r.Build().LastPacketTime; got != nil {
		t.Errorf("last packet time = %v, want nil", got)
	}
}

func TestBuildReportsPerAnalyzerHealthIndependently(t *testing.T) {
	// One analyzer failing while another keeps working must be visible as
	// exactly that, so the tap can report Degraded rather than all-or-nothing.
	r := healthyReporter()
	r.Analyzers = []AnalyzerObserver{
		&fakeAnalyzer{name: trawlv1alpha1.AnalyzerSuricata, healthy: true, version: "8.0.6"},
		&fakeAnalyzer{name: trawlv1alpha1.AnalyzerZeek, healthy: false, reason: "no records for 5m"},
	}

	st := r.Build()
	if len(st.Analyzers) != 2 {
		t.Fatalf("got %d analyzer statuses, want 2", len(st.Analyzers))
	}

	byName := map[trawlv1alpha1.AnalyzerName]trawlv1alpha1.AnalyzerStatus{}
	for _, a := range st.Analyzers {
		byName[a.Name] = a
	}
	if !byName[trawlv1alpha1.AnalyzerSuricata].Healthy {
		t.Error("healthy analyzer reported unhealthy")
	}
	if byName[trawlv1alpha1.AnalyzerZeek].Healthy {
		t.Error("failed analyzer reported healthy")
	}
	if byName[trawlv1alpha1.AnalyzerZeek].Reason == "" {
		t.Error("failed analyzer has no reason")
	}
}

func TestAnalyzerReasonIsSanitizedAndBounded(t *testing.T) {
	// The reason is surfaced in status, which many people can read, and it
	// originates from a dependency error.
	r := healthyReporter()
	r.Analyzers = []AnalyzerObserver{
		&fakeAnalyzer{
			name:    trawlv1alpha1.AnalyzerSuricata,
			healthy: false,
			reason:  "failed: https://minio:9000/b/o?X-Amz-Signature=deadbeefcafe " + strings.Repeat("x", 500),
		},
	}

	got := r.Build().Analyzers[0].Reason
	if strings.Contains(got, "deadbeefcafe") {
		t.Errorf("reason leaked a signature: %q", got)
	}
	if len(got) > maxReasonBytes {
		t.Errorf("reason is %d bytes, want <= %d", len(got), maxReasonBytes)
	}
}

func TestBuildReportsContentCurrency(t *testing.T) {
	// FR-045: an operator verifies which detection content is loaded without
	// exec'ing into a pod.
	fetched := time.Date(2026, 8, 29, 6, 0, 0, 0, time.UTC)
	digest := "sha256:" + strings.Repeat("a", 64)

	r := healthyReporter()
	r.Analyzers = []AnalyzerObserver{
		&fakeAnalyzer{
			name: trawlv1alpha1.AnalyzerSuricata, healthy: true,
			contentSt: content.Status{
				UpstreamFetchedAt: fetched,
				CustomDigest:      digest,
				CustomApplied:     true,
			},
		},
	}

	as := r.Build().Analyzers[0]
	if as.UpstreamFetchedAt == nil || !as.UpstreamFetchedAt.Time.Equal(fetched) {
		t.Errorf("upstream fetched at = %v, want %v", as.UpstreamFetchedAt, fetched)
	}
	if as.CustomContentDigest != digest {
		t.Errorf("custom digest = %q", as.CustomContentDigest)
	}
}

func TestBuildOmitsCustomDigestWhenUpstreamOnly(t *testing.T) {
	// An empty digest is how an operator sees that no overlay applied. A
	// placeholder would make upstream-only indistinguishable from a failed pull.
	r := healthyReporter()
	r.Analyzers = []AnalyzerObserver{
		&fakeAnalyzer{
			name: trawlv1alpha1.AnalyzerSuricata, healthy: true,
			contentSt: content.Status{UpstreamFetchedAt: fixedNow()},
		},
	}
	if got := r.Build().Analyzers[0].CustomContentDigest; got != "" {
		t.Errorf("custom digest = %q, want empty", got)
	}
}

func TestBuildAggregatesRejectedRecordCounts(t *testing.T) {
	// FR-016 requires the rejection count be observable. Content is never
	// stored, only the count.
	r := healthyReporter()
	r.Analyzers = []AnalyzerObserver{
		&fakeAnalyzer{name: trawlv1alpha1.AnalyzerSuricata, healthy: true,
			counters: Counters{Accepted: 100, Malformed: 3, Unsupported: 7}},
		&fakeAnalyzer{name: trawlv1alpha1.AnalyzerZeek, healthy: true,
			counters: Counters{Accepted: 50, Malformed: 2}},
	}

	if got := r.Build().RejectedRecords; got != 12 {
		t.Errorf("rejected records = %d, want 12", got)
	}
}

func TestBuildReportsDuplicationState(t *testing.T) {
	r := healthyReporter()
	cache := NewDuplicateCache(100)
	at := fixedNow()
	cache.Mark(flowObs(at, "10.0.0.1", 1234, "10.0.0.2", 443))
	cache.Mark(flowObs(at.Add(time.Microsecond), "10.0.0.1", 1234, "10.0.0.2", 443))
	r.Duplicates = cache

	if got := r.Build().Duplication; got != trawlv1alpha1.DuplicationSuspected {
		t.Errorf("duplication = %q, want Suspected", got)
	}
}

func TestBuildDefaultsDuplicationToUnknownWithoutACache(t *testing.T) {
	r := healthyReporter()
	r.Duplicates = nil

	if got := r.Build().Duplication; got != trawlv1alpha1.DuplicationUnknown {
		t.Errorf("duplication = %q, want Unknown", got)
	}
}
