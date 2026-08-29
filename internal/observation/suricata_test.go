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

package observation

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func suricataNormalizer() *SuricataNormalizer {
	fixed := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	return &SuricataNormalizer{
		Version: "8.0.6",
		Tap:     &Tap{Namespace: "trawl-system", Name: "mirror-0", UID: "tap-uid-1"},
		Target:  Target{Node: "sensor-01", Interface: "enp5s0"},
		Now:     func() time.Time { return fixed },
	}
}

// A real EVE alert line, trimmed to the fields Trawl reads.
const eveAlert = `{
  "timestamp": "2026-08-29T11:59:30.123456+0000",
  "flow_id": 1234567890,
  "event_type": "alert",
  "src_ip": "192.168.1.50",
  "src_port": 44321,
  "dest_ip": "203.0.113.10",
  "dest_port": 443,
  "proto": "TCP",
  "community_id": "1:LQU9qZlK+B5F3KDmev6m5PMibrg=",
  "alert": {
    "action": "allowed",
    "signature_id": 2019401,
    "rev": 5,
    "signature": "ET POLICY Suspicious outbound TLS",
    "category": "Potentially Bad Traffic",
    "severity": 2
  }
}`

func TestSuricataNormalizesAlert(t *testing.T) {
	n := suricataNormalizer()

	obs, stats, err := n.Normalize([]byte(eveAlert))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if stats != nil {
		t.Error("an alert produced stats")
	}
	if obs.ObservationType != TypeSignature {
		t.Errorf("observation_type = %q, want %q", obs.ObservationType, TypeSignature)
	}
	if obs.SchemaVersion != SchemaVersion {
		t.Errorf("schema_version = %q", obs.SchemaVersion)
	}

	sig := obs.Details.Signature
	if sig == nil {
		t.Fatal("no signature body")
	}
	// FR-012: severity, rule identity, category, and message must survive.
	if sig.RuleID != 2019401 {
		t.Errorf("rule_id = %d, want 2019401", sig.RuleID)
	}
	if sig.Revision == nil || *sig.Revision != 5 {
		t.Errorf("revision = %v, want 5", sig.Revision)
	}
	if sig.Severity != 2 {
		t.Errorf("severity = %d, want 2", sig.Severity)
	}
	if sig.Category != "Potentially Bad Traffic" {
		t.Errorf("category = %q", sig.Category)
	}
	if sig.Message != "ET POLICY Suspicious outbound TLS" {
		t.Errorf("message = %q", sig.Message)
	}
}

func TestSuricataPreservesCommunityIDVerbatim(t *testing.T) {
	// FR-011: Community ID is the exact-pivot key between Suricata and Zeek.
	// It is copied, never recomputed - two implementations of the hash would
	// eventually disagree on an edge case and silently break correlation for
	// exactly the flows hardest to reason about.
	n := suricataNormalizer()

	obs, _, err := n.Normalize([]byte(eveAlert))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if obs.Flow == nil {
		t.Fatal("no flow envelope")
	}
	if got := obs.Flow.CommunityID; got != "1:LQU9qZlK+B5F3KDmev6m5PMibrg=" {
		t.Errorf("community_id = %q, want the value Suricata reported", got)
	}
}

func TestSuricataPreservesBothTimestamps(t *testing.T) {
	// Producer clocks drift. An analyst reconstructing a sequence needs to see
	// the skew rather than have it silently resolved, so event time and
	// observation time are both kept (FR-010).
	n := suricataNormalizer()

	obs, _, err := n.Normalize([]byte(eveAlert))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	wantEvent := time.Date(2026, 8, 29, 11, 59, 30, 123456000, time.UTC)
	if !obs.EventTime.Equal(wantEvent) {
		t.Errorf("event_time = %v, want %v", obs.EventTime, wantEvent)
	}
	if !obs.ObservedAt.Equal(time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("observed_at = %v", obs.ObservedAt)
	}
	if !obs.ObservedAt.After(obs.EventTime) {
		t.Error("observed_at is not after event_time in this fixture")
	}
}

func TestSuricataCarriesFlowEndpoints(t *testing.T) {
	n := suricataNormalizer()
	obs, _, err := n.Normalize([]byte(eveAlert))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	f := obs.Flow
	if f.Source.IP != "192.168.1.50" || f.Source.Port == nil || *f.Source.Port != 44321 {
		t.Errorf("source endpoint = %+v", f.Source)
	}
	if f.Destination.IP != "203.0.113.10" || f.Destination.Port == nil || *f.Destination.Port != 443 {
		t.Errorf("destination endpoint = %+v", f.Destination)
	}
	if f.Protocol != "tcp" {
		t.Errorf("protocol = %q, want lowercase tcp", f.Protocol)
	}
}

func TestSuricataRecordIDIsStableAcrossReparse(t *testing.T) {
	// A sensor restarting mid-file re-reads lines it already emitted. A random
	// ID would turn every restart into a burst of apparently new observations.
	n := suricataNormalizer()

	first, _, err := n.Normalize([]byte(eveAlert))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	second, _, err := n.Normalize([]byte(eveAlert))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if first.ID != second.ID {
		t.Errorf("record ID is not stable: %q vs %q", first.ID, second.ID)
	}
	if len(first.ID) != idLen {
		t.Errorf("record ID length = %d, want %d", len(first.ID), idLen)
	}
}

func TestSuricataStatsAreHealthNotObservations(t *testing.T) {
	// Stats describe the sensor, not traffic. Emitting them as observations
	// would inflate observation counts with records about nothing observed.
	n := suricataNormalizer()
	line := `{
	  "timestamp": "2026-08-29T11:59:30.000000+0000",
	  "event_type": "stats",
	  "stats": {
	    "capture": {"kernel_packets": 918273, "kernel_drops": 42},
	    "decoder": {"pkts": 918200}
	  }
	}`

	obs, stats, err := n.Normalize([]byte(line))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if obs != nil {
		t.Error("a stats record produced an observation")
	}
	if stats == nil {
		t.Fatal("no stats returned")
	}
	if stats.KernelPackets == nil || *stats.KernelPackets != 918273 {
		t.Errorf("kernel_packets = %v", stats.KernelPackets)
	}
	if stats.KernelDrops == nil || *stats.KernelDrops != 42 {
		t.Errorf("kernel_drops = %v", stats.KernelDrops)
	}
}

func TestSuricataStatsDistinguishZeroDropsFromUnknown(t *testing.T) {
	// FR-039 reports packet loss where available. "Zero drops" and "the
	// analyzer did not say" are different answers, and flattening them would
	// claim a clean capture we never measured.
	n := suricataNormalizer()

	withZero := `{"timestamp":"2026-08-29T11:59:30.000000+0000","event_type":"stats","stats":{"capture":{"kernel_packets":10,"kernel_drops":0}}}`
	_, stats, err := n.Normalize([]byte(withZero))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if stats.KernelDrops == nil || *stats.KernelDrops != 0 {
		t.Errorf("explicit zero drops = %v, want a pointer to 0", stats.KernelDrops)
	}

	withoutDrops := `{"timestamp":"2026-08-29T11:59:30.000000+0000","event_type":"stats","stats":{"capture":{"kernel_packets":10}}}`
	_, stats, err = n.Normalize([]byte(withoutDrops))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if stats.KernelDrops != nil {
		t.Errorf("absent drops = %v, want nil", stats.KernelDrops)
	}
}

func TestSuricataRejectsMalformedRecords(t *testing.T) {
	n := suricataNormalizer()

	cases := map[string]string{
		"invalid json":       `{"event_type": "alert"`,
		"missing type":       `{"timestamp":"2026-08-29T11:59:30.000000+0000"}`,
		"alert with no body": `{"timestamp":"2026-08-29T11:59:30.000000+0000","event_type":"alert"}`,
		"missing signature":  `{"timestamp":"2026-08-29T11:59:30.000000+0000","event_type":"alert","alert":{"signature":"x"}}`,
		"missing timestamp":  `{"event_type":"alert","alert":{"signature_id":1,"signature":"x"}}`,
		"bad timestamp":      `{"timestamp":"not-a-time","event_type":"alert","alert":{"signature_id":1,"signature":"x"}}`,
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			obs, _, err := n.Normalize([]byte(line))
			if err == nil {
				t.Fatal("malformed record accepted")
			}
			if obs != nil {
				t.Error("malformed record produced an observation")
			}
			if errors.Is(err, ErrUnsupportedRecord) {
				t.Error("malformed record was classified as merely unsupported")
			}
		})
	}
}

func TestSuricataDistinguishesUnsupportedFromMalformed(t *testing.T) {
	// The two are counted separately so an operator can tell "the analyzer
	// emits a new record type" from "the analyzer is producing garbage".
	n := suricataNormalizer()

	line := `{"timestamp":"2026-08-29T11:59:30.000000+0000","event_type":"dns","dns":{"rrname":"example.com"}}`
	obs, _, err := n.Normalize([]byte(line))
	if !errors.Is(err, ErrUnsupportedRecord) {
		t.Fatalf("err = %v, want ErrUnsupportedRecord", err)
	}
	if obs != nil {
		t.Error("unsupported record produced an observation")
	}
}

func TestSuricataErrorsNeverEchoRecordContent(t *testing.T) {
	// A malformed record can contain traffic content, including credentials in
	// a cleartext protocol. The error names the problem, never the input.
	n := suricataNormalizer()

	secret := "password=hunter2trombone"
	line := `{"timestamp":"bad","event_type":"alert","alert":{"signature_id":1,"signature":"` + secret + `"}}`

	_, _, err := n.Normalize([]byte(line))
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "hunter2trombone") {
		t.Errorf("error echoed record content: %v", err)
	}
}

func TestSuricataNormalizedAlertSatisfiesSchema(t *testing.T) {
	// The sensor validates every record it emits. Loki enforces no schema, so
	// an invalid record would be stored and only noticed when a dashboard
	// silently returned nothing.
	n := suricataNormalizer()

	obs, _, err := n.Normalize([]byte(eveAlert))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if err := Normalize(obs); err != nil {
		t.Fatalf("Normalize envelope: %v", err)
	}
	if err := Validate(obs); err != nil {
		t.Fatalf("normalized alert violates the normative schema: %v", err)
	}
}

func TestSuricataHandlesAlertWithoutCommunityID(t *testing.T) {
	// Community ID is configurable in Suricata. Its absence must degrade to
	// attribute-based correlation, not fail the record (FR-011 says "whenever
	// both analysis modes can derive one").
	n := suricataNormalizer()
	line := `{"timestamp":"2026-08-29T11:59:30.000000+0000","event_type":"alert","src_ip":"10.0.0.1","dest_ip":"10.0.0.2","proto":"UDP","alert":{"signature_id":99,"signature":"x","category":"c","severity":3}}`

	obs, _, err := n.Normalize([]byte(line))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if obs.Flow == nil {
		t.Fatal("no flow envelope")
	}
	if obs.Flow.CommunityID != "" {
		t.Errorf("community_id = %q, want empty", obs.Flow.CommunityID)
	}
	if err := Validate(obs); err != nil {
		t.Errorf("alert without community_id violates the schema: %v", err)
	}
}
