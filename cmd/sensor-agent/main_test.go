package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trawl.cloud/trawl/internal/observation"
	"trawl.cloud/trawl/internal/telemetry"
)

// Zeek's output was never read. main registered a readiness check on the log
// directory and built no tailer for it, so Zeek observed the interface, wrote
// conn, dns, ssl and the rest, and every record stopped at the disk. The sensor
// stayed ready and emitted nothing, which is indistinguishable from an
// interface carrying no traffic.
func TestZeekTailersAreBuiltForEveryLog(t *testing.T) {
	dir := "/var/log/trawl/zeek"
	emit := func(*observation.Observation, string) error { return nil }
	tailers := zeekTailers(dir, &observation.ZeekNormalizer{}, emit, telemetry.NewMetrics())

	if len(tailers) == 0 {
		t.Fatal("no Zeek tailers built; Zeek's output would never be read")
	}
	if len(tailers) != len(zeekLogTypes) {
		t.Fatalf("built %d tailers for %d log types", len(tailers), len(zeekLogTypes))
	}

	paths := map[string]bool{}
	for _, tl := range tailers {
		if tl.Parse == nil || tl.Emit == nil {
			t.Errorf("tailer %s has no parser or no emitter", tl.Path)
		}
		paths[tl.Path] = true
	}

	// conn carries the connection record every exact pivot resolves to, and
	// x509 the certificates that are reachable no other way.
	for _, required := range []observation.ZeekLogType{observation.ZeekConn, observation.ZeekX509} {
		want := filepath.Join(dir, string(required)+".log")
		if !paths[want] {
			t.Errorf("no tailer for %s", want)
		}
	}
}

// An empty version is not a cosmetic gap. observation.schema.json requires
// source.version with minLength 1, so an empty string fails validation and the
// tailer counts the record malformed - every observation discarded because of a
// missing label about the reader, not anything wrong with what was read.
func TestAnalyzerVersionIsNeverEmpty(t *testing.T) {
	dir := t.TempDir()

	missing := filepath.Join(dir, "absent", ".version")
	if got := analyzerVersion(missing); got == "" {
		t.Error("a missing version file yields an empty version, which fails schema validation")
	}

	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := analyzerVersion(empty); got == "" {
		t.Error("a blank version file yields an empty version")
	}

	real := filepath.Join(dir, "real")
	if err := os.WriteFile(real, []byte("zeek version 8.0.10\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := analyzerVersion(real); got != "zeek version 8.0.10" {
		t.Errorf("analyzerVersion = %q, want the trimmed banner", got)
	}

	long := filepath.Join(dir, "long")
	if err := os.WriteFile(long, []byte(strings.Repeat("v", 200)), 0o600); err != nil {
		t.Fatal(err)
	}
	// The schema caps it at 64.
	if got := analyzerVersion(long); len(got) > 64 {
		t.Errorf("analyzerVersion returned %d characters, over the schema maximum", len(got))
	}
}
