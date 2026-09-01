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

package integration

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"trawl.cloud/trawl/internal/observation"
)

// These load Trawl's real Zeek configuration into a real Zeek and read what it
// writes. Every property here is Zeek's, not Trawl's, and none of them can be
// checked by inspecting the config as text.
//
// Three defects reached main because the only coverage was string matching.
// local.zeek redef'd Communityid::seed, but the module is CommunityID, and Zeek
// treats a redef of an unknown identifier as a fatal parse error - so the
// analyzer never started, and the contract test asserting the seed was pinned
// passed by matching the misspelling. local.zeek also used
// @load-sigs-ignore-errors, which is not a Zeek directive. And stock
// community-id-logging adds community_id to Conn::Info alone, so the exact
// pivot the whole investigation workflow rests on reached the connection record
// and nothing else.

// zeekImage is pinned to the version images/zeek/SOURCES.lock builds.
const zeekImage = "docker.io/zeek/zeek:8.0"

// zeekPolicyRun parses Trawl's site configuration and reports what Zeek said.
//
// Parsing alone catches the class of failure that stops the analyzer from
// starting, and needs no traffic, so it stays fast enough to run everywhere.
func zeekPolicyRun(t *testing.T, args ...string) (string, error) {
	t.Helper()
	requireDockerFor(t)

	root := repoRootFor(t)
	site := filepath.Join(root, "images", "zeek")

	base := []string{
		"run", "--rm",
		"--volume", site + ":/trawl-site:ro",
		"--workdir", "/tmp",
		zeekImage, "zeek",
	}
	//nolint:gosec // G204: every argument is a test-controlled literal or repo path
	out, err := exec.CommandContext(t.Context(), "docker", append(base, args...)...).CombinedOutput()
	return string(out), err
}

func TestZeekConfigurationParses(t *testing.T) {
	// --parse-only loads every @load in local.zeek and evaluates every redef
	// without needing an interface. A misspelled module, a directive that does
	// not exist, or a script that is not on the image would all fail here.
	out, err := zeekPolicyRun(t, "--parse-only", "/trawl-site/local.zeek")
	if err != nil {
		t.Fatalf("Trawl's Zeek configuration does not load:\n%s", out)
	}
	if strings.Contains(out, "error") || strings.Contains(out, "warning in") {
		t.Errorf("Zeek reported problems loading the configuration:\n%s", out)
	}
}

func TestZeekConfigurationUsesTheRealCommunityIDModule(t *testing.T) {
	// The specific failure that shipped. Asserted separately from the parse
	// test so the diagnosis is in the test name rather than in a diff of Zeek's
	// output.
	out, err := zeekPolicyRun(t, "--parse-only", "/trawl-site/local.zeek")
	if err != nil && strings.Contains(out, "Communityid") {
		t.Fatalf("local.zeek uses the Communityid module, which Zeek does not define:\n%s", out)
	}
	if err != nil {
		t.Fatalf("configuration failed to load:\n%s", out)
	}
}

// zeekPcapLogs runs Zeek over a pcap with Trawl's configuration and returns the
// logs it wrote, keyed by file name.
func zeekPcapLogs(t *testing.T, pcap string) map[string][]map[string]any {
	t.Helper()
	requireDockerFor(t)

	root := repoRootFor(t)
	site := filepath.Join(root, "images", "zeek")
	outDir := t.TempDir()
	// Zeek writes to its working directory as the container's root user, so the
	// directory has to be writable by it.
	if err := os.Chmod(outDir, 0o777); err != nil { //nolint:gosec // G302: container writes as a different uid
		t.Fatalf("chmod: %v", err)
	}

	// -C ignores checksums. The pcap is replayed rather than captured, and on
	// any veth or offloading NIC the checksums are absent; without this Zeek
	// discards the packets and writes no protocol logs at all.
	//nolint:gosec // G204: every argument is a test-controlled literal or repo path
	out, err := exec.CommandContext(t.Context(), "docker", "run", "--rm",
		"--volume", site+":/trawl-site:ro",
		"--volume", pcap+":/capture.pcap:ro",
		"--volume", outDir+":/out",
		"--workdir", "/out",
		zeekImage, "zeek", "-r", "/capture.pcap", "-C", "/trawl-site/local.zeek",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("running Zeek over the pcap: %v\n%s", err, out)
	}

	logs := map[string][]map[string]any{}
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatalf("reading Zeek output: %v", err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".log") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(outDir, e.Name())) //nolint:gosec // G304: test-controlled path
		if err != nil {
			t.Fatalf("reading %s: %v", e.Name(), err)
		}
		var rows []map[string]any
		for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
			if line == "" {
				continue
			}
			var row map[string]any
			if err := json.Unmarshal([]byte(line), &row); err != nil {
				t.Fatalf("%s is not JSON, so json-logs is not in effect: %v", e.Name(), err)
			}
			rows = append(rows, row)
		}
		// Zeek rotates by the capture's own clock when reading a pcap, so one
		// log arrives as both "conn.log" and "conn.2026-08-30-13-59-11.log".
		// Folding them together keeps assertions about a log's records from
		// depending on where the rotation boundary happened to fall.
		logs[baseLogName(e.Name())] = append(logs[baseLogName(e.Name())], rows...)
	}
	return logs
}

// rotatedLog matches the timestamp Zeek inserts when it rotates a log.
var rotatedLog = regexp.MustCompile(`\.\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}\.log$`)

func baseLogName(name string) string {
	return rotatedLog.ReplaceAllString(name, ".log")
}

func TestZeekStampsCommunityIDOnEveryFlowLog(t *testing.T) {
	// The property FR-011 and SC-005 rest on. Suricata stamps community_id on
	// every EVE event; stock Zeek stamps it on conn.log alone. An analyst
	// pivoting from an alert would reach the connection record and stop, and
	// the symptom is an empty result rather than an error.
	pcap := testdataPcap(t)
	logs := zeekPcapLogs(t, pcap)

	// Logs that describe a flow and therefore must carry the pivot key. Absent
	// logs are skipped rather than failed: which protocols appear depends on
	// the pcap, and this asserts a property of the records that exist.
	flowLogs := []string{"conn.log", "dns.log", "http.log", "ssl.log", "files.log", "weird.log"}

	var checked int
	for _, name := range flowLogs {
		rows, ok := logs[name]
		if !ok || len(rows) == 0 {
			continue
		}
		checked++
		for i, row := range rows {
			cid, _ := row["community_id"].(string)
			if cid == "" {
				t.Errorf("%s record %d carries no community_id, so it cannot be reached by an exact pivot", name, i)
				break
			}
		}
	}
	if checked < 2 {
		t.Fatalf("the pcap produced too few flow logs to be meaningful; got %v", keysOf(logs))
	}

	// The value has to be the same one conn.log reports for the flow, not just
	// present. Two records with different IDs for one flow is worse than one
	// record missing an ID: the pivot returns a confidently wrong answer.
	byUID := map[string]string{}
	for _, row := range logs["conn.log"] {
		uid, _ := row["uid"].(string)
		cid, _ := row["community_id"].(string)
		if uid != "" && cid != "" {
			byUID[uid] = cid
		}
	}
	for _, name := range flowLogs {
		if name == "conn.log" {
			continue
		}
		for i, row := range logs[name] {
			uid, _ := row["uid"].(string)
			cid, _ := row["community_id"].(string)
			if want, ok := byUID[uid]; ok && cid != want {
				t.Errorf("%s record %d has community_id %q but conn.log reports %q for the same flow",
					name, i, cid, want)
			}
		}
	}
}

func TestZeekCertificateRecordsNormalizeIntoPopulatedObservations(t *testing.T) {
	// End to end from Zeek's own x509.log through Trawl's normalizer. The
	// parser previously decoded a nested "certificate" object, which the
	// json-logs policy never produces: it flattens a record-valued field to
	// dotted keys, the same way conn.log carries "id.orig_h". That parsed
	// cleanly and produced a certificate with every field empty.
	logs := zeekPcapLogs(t, testdataPcap(t))
	rows, ok := logs["x509.log"]
	if !ok || len(rows) == 0 {
		t.Skip("the pcap contains no certificate in the clear; TLS 1.3 encrypts them")
	}

	n := &observation.ZeekNormalizer{
		Version: observation.StaticVersion("8.0.10"),
		Tap:     &observation.Tap{Namespace: "trawl-system", Name: "t", UID: "u"},
		Target:  observation.Target{Node: "n", Interface: "eth0"},
		Now:     time.Now,
	}

	for i, row := range rows {
		line, err := json.Marshal(row)
		if err != nil {
			t.Fatalf("re-encoding x509 record: %v", err)
		}
		obs, err := n.Normalize(observation.ZeekX509, line)
		if err != nil {
			t.Fatalf("normalizing Zeek's own x509 record %d: %v", i, err)
		}
		if obs.Details.Certificate == nil {
			t.Fatalf("record %d produced no certificate", i)
		}
		cert := obs.Details.Certificate
		if cert.Subject == "" || cert.Issuer == "" {
			t.Errorf("record %d: subject/issuer empty, so the flattened keys were not read: %+v", i, cert)
		}
		if err := observation.Validate(obs); err != nil {
			t.Errorf("record %d does not satisfy the schema: %v", i, err)
		}
	}
}

func keysOf(m map[string][]map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// requireDockerFor skips when Docker is unavailable, matching the harness
// package's policy for container-backed tests.
func requireDockerFor(t *testing.T) {
	t.Helper()
	if os.Getenv("TRAWL_SKIP_CONTAINER_TESTS") != "" {
		t.Skip("TRAWL_SKIP_CONTAINER_TESTS is set")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed; skipping container integration test")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "info").Run(); err != nil {
		t.Skip("docker daemon is not available; skipping container integration test")
	}
}

func repoRootFor(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Join(wd, "..", "..")
}

// testdataPcap returns the shared capture, described in test/testdata/README.md.
func testdataPcap(t *testing.T) string {
	t.Helper()
	path := filepath.Join(repoRootFor(t), "test", "testdata", "investigation.pcap")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("test capture missing: %v", err)
	}
	return path
}
