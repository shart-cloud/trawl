package main

import (
	"path/filepath"
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
