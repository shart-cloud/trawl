package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/observation"
	"trawl.cloud/trawl/internal/sensor"
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
	tailers := zeekTailers(dir, &observation.ZeekNormalizer{}, emit, telemetry.NewMetrics(),
		sensor.NewDuplicateCache(sensor.MaxFingerprints))

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

// The renderer switches an analyzer on by passing its log path and expresses
// "not enabled" by leaving the flag off entirely - see
// TestOnlyEnabledAnalyzersAreSwitchedOn in internal/controller. The binary's
// own flag help says the same: "empty disables Suricata".
//
// It did not. An empty path was rewritten to a default under --log-dir before
// anything looked at it, so the disable branch was unreachable. On a Zeek-only
// tap the sensor started a Suricata tailer on a file nothing writes and
// registered a readiness check against it, so /readyz answered 503 for as long
// as the pod lived: the DaemonSet never rolled out and the tap never went
// Active. Both halves of the contract were individually tested and they
// disagreed.
func TestAnAnalyzerTheTapDidNotEnableStaysAbsent(t *testing.T) {
	for _, tc := range []struct {
		name            string
		suricata, zeek  string
		wantSur, wantZk string
		wantErr         bool
	}{
		{name: "zeek only", zeek: "/var/log/trawl/zeek", wantZk: "/var/log/trawl/zeek"},
		{name: "suricata only", suricata: "/var/log/trawl/suricata/eve.json",
			wantSur: "/var/log/trawl/suricata/eve.json"},
		{name: "both", suricata: "/s/eve.json", zeek: "/z",
			wantSur: "/s/eve.json", wantZk: "/z"},
		// A sensor told to read nothing would tail nothing and report no
		// observations, which is indistinguishable from an interface carrying
		// no traffic. Refusing to start says so instead.
		{name: "neither", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sur, zk, err := analyzerLogs(tc.suricata, tc.zeek)
			if tc.wantErr {
				if err == nil {
					t.Fatal("a sensor with no analyzer configured was accepted")
				}
				return
			}
			if err != nil {
				t.Fatalf("analyzerLogs: %v", err)
			}
			if sur != tc.wantSur {
				t.Errorf("suricata log = %q, want %q", sur, tc.wantSur)
			}
			if zk != tc.wantZk {
				t.Errorf("zeek log dir = %q, want %q", zk, tc.wantZk)
			}
		})
	}
}

// StatusReporter has a Duplicates field, reads it, and reports the target's
// duplication state from it. Nothing ever set it. Both caches were created here
// and handed only to the tailers, so a tap whose sensor was actively marking
// records "Suspected" - as the deployed sensor is - reported Duplication:
// Unknown for the whole life of the pod.
//
// That is the same shape as the packet counters and as StatusReporter itself
// before it had a caller: implemented, unit-tested, and never wired. The unit
// tests could not catch it because the omission is in the assembly, which is
// why the reporter is built by a function rather than inline.
func TestStatusReportsTheDuplicationTheSensorMeasured(t *testing.T) {
	duplicates := sensor.NewDuplicateCache(sensor.MaxFingerprints)
	observers := []sensor.AnalyzerObserver{
		&analyzerObserver{name: trawlv1alpha1.AnalyzerZeek},
	}

	r := newStatusReporter("node-01", "enp5s0", "pod-xyz", observers, duplicates)

	if r.Duplicates == nil {
		t.Fatal("the status reporter carries no duplicate cache; duplication can never leave Unknown")
	}
	if r.Duplicates != duplicates {
		t.Error("the status reporter reads a different cache from the one the tailers write")
	}
	if len(r.Analyzers) != len(observers) {
		t.Errorf("the status reporter describes %d analyzers, want %d", len(r.Analyzers), len(observers))
	}
}

// One cache per target, not one per analyzer and certainly not one per Zeek log
// type - which is what there was: eight caches for Zeek plus one for Suricata,
// each bounded to MaxFingerprints, each seeing a ninth of the records, and none
// of them reachable from status.
//
// Duplication is the same packets arriving twice, which is a property of what
// the target receives. The fingerprint includes the source kind and the
// observation type, so one shared cache cannot make Zeek's conn record and
// Suricata's alert for the same flow look like duplicates of each other.
func TestEveryTailerSharesTheTargetsDuplicateCache(t *testing.T) {
	shared := sensor.NewDuplicateCache(sensor.MaxFingerprints)
	emit := func(*observation.Observation, string) error { return nil }

	tailers := zeekTailers("/var/log/trawl/zeek", &observation.ZeekNormalizer{},
		emit, telemetry.NewMetrics(), shared)
	if len(tailers) == 0 {
		t.Fatal("no tailers built")
	}
	for _, tl := range tailers {
		if tl.Duplicates != shared {
			t.Errorf("tailer %s writes to a cache the status reporter does not read", tl.Path)
		}
	}
}
