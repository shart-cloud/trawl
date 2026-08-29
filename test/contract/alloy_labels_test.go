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

package contract

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Loki creates a stream per distinct label combination. Promoting an IP, a rule
// ID, or a username to a label would produce millions of streams and degrade
// the query path for every user of the cluster's Loki — and it would only be
// noticeable once enough traffic had flowed to make it expensive to undo.
//
// The telemetry contract fixes which labels are permitted. These tests are what
// stop a future edit from adding one without the cardinality review the
// constitution requires.

// labelsBlock extracts the values of a stage.labels or stage.static_labels
// block from an Alloy config.
var labelsBlockRE = regexp.MustCompile(`(?s)stage\.(?:labels|static_labels)\s*\{\s*values\s*=\s*\{(.*?)\}`)

var labelKeyRE = regexp.MustCompile(`(?m)^\s*([a-z_][a-z0-9_]*)\s*=`)

func alloyLabels(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), path))
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	var labels []string
	for _, block := range labelsBlockRE.FindAllStringSubmatch(string(data), -1) {
		for _, m := range labelKeyRE.FindAllStringSubmatch(block[1], -1) {
			labels = append(labels, m[1])
		}
	}
	return labels
}

func TestObservationPipelinePromotesOnlyContractLabels(t *testing.T) {
	// contracts/telemetry.md: service_name, cluster, source_kind,
	// observation_type. Nothing else becomes a label without a measured
	// cardinality review.
	allowed := []string{"service_name", "cluster", "source_kind", "observation_type"}

	for _, got := range alloyLabels(t, "config/alloy/trawl-observations.alloy") {
		if !slices.Contains(allowed, got) {
			t.Errorf("observation pipeline promotes %q to a Loki label; the contract permits only %v",
				got, allowed)
		}
	}
}

func TestAuditPipelinePromotesOnlyContractLabels(t *testing.T) {
	// An audit stream labelled by username would create a stream per user.
	allowed := []string{"service_name", "cluster", "action", "decision"}

	for _, got := range alloyLabels(t, "config/alloy/trawl-audit.alloy") {
		if !slices.Contains(allowed, got) {
			t.Errorf("audit pipeline promotes %q to a Loki label; the contract permits only %v",
				got, allowed)
		}
	}
}

func TestHighCardinalityFieldsAreStructuredMetadataNotLabels(t *testing.T) {
	// These are exactly the fields an analyst filters on, which is why the
	// temptation to label them exists. They belong in structured metadata,
	// which is indexed without multiplying streams.
	mustBeMetadata := []string{
		"source_ip", "destination_ip", "source_port", "destination_port",
		"community_id", "zeek_uid", "rule_id", "tap_uid", "target_node",
		"actor_username", "request_id", "stable_key",
	}

	for _, path := range []string{
		"config/alloy/trawl-observations.alloy",
		"config/alloy/trawl-audit.alloy",
	} {
		labels := alloyLabels(t, path)
		for _, field := range mustBeMetadata {
			if slices.Contains(labels, field) {
				t.Errorf("%s promotes high-cardinality field %q to a label", path, field)
			}
		}
	}
}

func TestPipelinesUseEventTimeNotIngestionTime(t *testing.T) {
	// An observation's place in an investigation timeline is when the traffic
	// happened. Using ingestion time would reorder records whenever the
	// pipeline hiccuped, which is precisely when an analyst is looking.
	for path, source := range map[string]string{
		"config/alloy/trawl-observations.alloy": "event_time",
		"config/alloy/trawl-audit.alloy":        "recorded_at",
	} {
		data, err := os.ReadFile(filepath.Join(repoRoot(t), path))
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		if !strings.Contains(string(data), "stage.timestamp") {
			t.Errorf("%s does not set a timestamp stage", path)
			continue
		}
		if !strings.Contains(string(data), `source = "`+source+`"`) {
			t.Errorf("%s does not derive its timestamp from %q", path, source)
		}
	}
}

func TestObservationPipelineDropsUnknownSchemaVersions(t *testing.T) {
	// A record the pipeline cannot interpret must not be stored as though it
	// could be; a dashboard would silently fail to match it.
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "config/alloy/trawl-observations.alloy"))
	if err != nil {
		t.Fatalf("reading pipeline: %v", err)
	}
	if !strings.Contains(string(data), "trawl.observation/v1alpha1") {
		t.Error("the observation pipeline does not check the envelope schema version")
	}
	if !strings.Contains(string(data), "drop_counter_reason") {
		t.Error("dropped records are not counted, so the drop would be invisible")
	}
}

func TestAnalyzerConfigsDisablePacketWriting(t *testing.T) {
	// Packet capture belongs to CaptureJob, under its own authorization and
	// retention boundary. An analyzer-side pcap would put packet data outside
	// that boundary with no retention and no audit trail.
	for _, tc := range []struct {
		path      string
		forbidden []string
	}{
		{"images/suricata/suricata.yaml", []string{"pcap-log", "file-store"}},
		{"images/zeek/local.zeek", []string{"Log::Writer::PCAP", "PacketFilter::"}},
	} {
		data, err := os.ReadFile(filepath.Join(repoRoot(t), tc.path))
		if err != nil {
			t.Fatalf("reading %s: %v", tc.path, err)
		}
		// Comments are stripped first. The prose explaining why packet writing
		// is disabled necessarily names the directive being disabled, and
		// matching that would make the test fail on its own documentation.
		for line := range strings.SplitSeq(string(data), "\n") {
			code, _, _ := strings.Cut(line, "#")
			for _, f := range tc.forbidden {
				if strings.Contains(code, f) {
					t.Errorf("%s enables packet writing via %q", tc.path, strings.TrimSpace(line))
				}
			}
		}
	}
}

func TestAnalyzerConfigsAgreeOnCommunityIDSeed(t *testing.T) {
	// A seed mismatch produces two different strings for the same flow and
	// silently breaks every cross-analyzer pivot. The failure looks like "the
	// pivot found nothing" rather than an error, which is why it is asserted
	// here rather than left to a runtime check.
	suricata, err := os.ReadFile(filepath.Join(repoRoot(t), "images/suricata/suricata.yaml"))
	if err != nil {
		t.Fatalf("reading suricata config: %v", err)
	}
	zeek, err := os.ReadFile(filepath.Join(repoRoot(t), "images/zeek/local.zeek"))
	if err != nil {
		t.Fatalf("reading zeek config: %v", err)
	}

	if !strings.Contains(string(suricata), "community-id-seed: 0") {
		t.Error("Suricata does not pin the Community ID seed to 0")
	}
	if !strings.Contains(string(zeek), "Communityid::seed = 0") {
		t.Error("Zeek does not pin the Community ID seed to 0")
	}
	if !strings.Contains(string(suricata), "community-id: true") {
		t.Error("Suricata does not emit Community ID")
	}
	if !strings.Contains(string(zeek), "community-id-logging") {
		t.Error("Zeek does not load Community ID logging")
	}
}

func TestSuricataIsBuiltWithoutTheInlinePath(t *testing.T) {
	// An analyzer that cannot be built to modify traffic cannot be configured
	// into doing so by accident (Principle I).
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "images/suricata/Containerfile"))
	if err != nil {
		t.Fatalf("reading Containerfile: %v", err)
	}
	if !strings.Contains(string(data), "--disable-nfqueue") {
		t.Error("Suricata is not built with --disable-nfqueue; the inline path would be available")
	}
}

func TestAnalyzerImagesBakeInNoDetectionContent(t *testing.T) {
	// ADR-0005: content arrives at startup so an ET Open update does not need
	// an image rebuild, and the image digest keeps meaning "this software"
	// rather than "this software and that day's rules".
	for _, path := range []string{"images/suricata/Containerfile", "images/zeek/Containerfile"} {
		data, err := os.ReadFile(filepath.Join(repoRoot(t), path))
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		for _, baked := range []string{"emerging.rules", "COPY rules", "COPY scripts"} {
			if strings.Contains(string(data), baked) {
				t.Errorf("%s bakes detection content into the image (%q)", path, baked)
			}
		}
	}
}

func TestSourcesAreCheckedBeforeUnpacking(t *testing.T) {
	// The checksum is where an upstream compromise would otherwise enter the
	// supply chain unnoticed.
	for _, path := range []string{"images/suricata/Containerfile", "images/zeek/Containerfile"} {
		data, err := os.ReadFile(filepath.Join(repoRoot(t), path))
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		if !strings.Contains(string(data), "sha256sum -c") {
			t.Errorf("%s does not verify its source tarball checksum", path)
		}
	}
}
