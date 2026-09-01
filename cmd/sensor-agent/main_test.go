package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

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
//
// readVersionFile reports whether the analyzer has published one yet; turning
// "not yet" into observation.UnknownVersion is the normalizer's job, so that
// one place decides what a record carries.
func TestAnalyzerVersionIsNeverEmpty(t *testing.T) {
	dir := t.TempDir()

	missing := filepath.Join(dir, "absent", ".version")
	if _, ok := readVersionFile(missing); ok {
		t.Error("a missing version file reported a version")
	}

	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := readVersionFile(empty); ok {
		t.Error("a blank version file reported a version")
	}
	// Whatever the file said, what reaches a record is never empty.
	if got := versionFile(empty).Resolve(); got != observation.UnknownVersion {
		t.Errorf("an unwritten version file yields %q on a record, want %q",
			got, observation.UnknownVersion)
	}

	real := filepath.Join(dir, "real")
	if err := os.WriteFile(real, []byte("zeek version 8.0.10\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, ok := readVersionFile(real); !ok || got != "zeek version 8.0.10" {
		t.Errorf("readVersionFile = %q, %v, want the trimmed banner", got, ok)
	}

	long := filepath.Join(dir, "long")
	if err := os.WriteFile(long, []byte(strings.Repeat("v", 200)), 0o600); err != nil {
		t.Fatal(err)
	}
	// The schema caps it at 64.
	if got, _ := readVersionFile(long); len(got) > 64 {
		t.Errorf("readVersionFile returned %d characters, over the schema maximum", len(got))
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
// That is the same shape as StatusReporter itself before it had a caller, and
// as the packet counters were until the test below covered them: implemented,
// unit-tested, and never wired. Three instances of one defect in one file. The
// unit tests could not catch any of them because the omission is in the
// assembly, which is why the reporter is built by a function rather than
// inline, and why every field it fills has a test here and not only in
// internal/sensor.
func TestStatusReportsTheDuplicationTheSensorMeasured(t *testing.T) {
	duplicates := sensor.NewDuplicateCache(sensor.MaxFingerprints)
	observers := []sensor.AnalyzerObserver{
		&analyzerObserver{name: trawlv1alpha1.AnalyzerZeek},
	}

	r := newStatusReporter("node-01", "enp5s0", "pod-xyz", observers, duplicates,
		sensor.NewPacketMeter(sensor.DiscardPackets))

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

// The counters the analyzer reports have to reach the status the tap publishes.
//
// This is the omission main_test.go's duplication test named as still open:
// SuricataNormalizer lifted kernel_packets and kernel_drops out of every EVE
// stats record, StatusReporter had a Packets hook that filled in
// PacketsObserved, KernelDrops and LastPacketTime, and between them the sensor
// returned an empty struct from a closure that explained why it was empty. A
// tap capturing traffic perfectly well reported PacketsObserved=False for the
// life of the pod.
//
// Both halves had unit tests and both passed. The defect was the assembly,
// which is what this tests.
func TestStatusReportsThePacketsTheSensorMeasured(t *testing.T) {
	meter := sensor.NewPacketMeter(sensor.DiscardPackets)
	observers := []sensor.AnalyzerObserver{
		&analyzerObserver{name: trawlv1alpha1.AnalyzerSuricata},
	}

	r := newStatusReporter("node-01", "enp5s0", "pod-xyz", observers,
		sensor.NewDuplicateCache(sensor.MaxFingerprints), meter)

	if r.Packets == nil {
		t.Fatal("the status reporter has no packet source; PacketsObserved can never leave zero")
	}

	drops := int64(7)
	meter.Observe(&observation.SuricataStats{
		KernelPackets: &drops, KernelDrops: &drops,
		Timestamp: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC),
	})

	got := r.Packets()
	if got.PacketsObserved != 7 {
		t.Errorf("the reporter reads %d packets from a meter that measured 7; "+
			"it is reading a different meter from the one the tailer writes",
			got.PacketsObserved)
	}
	if got.KernelDrops == nil || *got.KernelDrops != 7 {
		t.Errorf("kernel drops = %v, want 7", got.KernelDrops)
	}
}

// The Suricata parse path must hand its stats records to the meter.
//
// SuricataNormalizer.Normalize returns (observation, stats, error) and the
// sensor's closure discarded the middle value with `_`. Nothing downstream
// could tell, because a stats record legitimately produces no observation - so
// dropping it looked exactly like handling it.
func TestTheSuricataParserFeedsTheMeterItsStatsRecords(t *testing.T) {
	meter := sensor.NewPacketMeter(sensor.DiscardPackets)
	parse := suricataParser(&observation.SuricataNormalizer{Version: observation.StaticVersion("8.0.6")}, meter)

	stats := []byte(`{"timestamp":"2026-09-01T12:00:00.000000+0000",` +
		`"event_type":"stats","stats":{"capture":{"kernel_packets":4096,` +
		`"kernel_drops":0}}}`)

	obs, err := parse(stats)
	if err != nil {
		t.Fatalf("parsing a stats record: %v", err)
	}
	if obs != nil {
		t.Errorf("a stats record produced an observation: %+v", obs)
	}

	got := meter.Counters()
	if got.PacketsObserved != 4096 {
		t.Errorf("the meter saw %d packets after a stats record reporting 4096; "+
			"the parser is still discarding its stats value", got.PacketsObserved)
	}
	if got.KernelDrops == nil || *got.KernelDrops != 0 {
		t.Errorf("kernel drops = %v, want an explicit 0", got.KernelDrops)
	}
}

// Every Zeek tailer must count what it accepts, not only what it rejects.
//
// Suricata's tailer was given an OnAccept and Zeek's was not, so
// trawl_sensor_records_total carried zeek rejections and never a single zeek
// acceptance: the counter was silent precisely when Zeek was working. That is
// the defect tailer.go's OnAccept doc comment describes as already fixed - the
// fix reached one of the two call sites.
func TestEveryZeekTailerCountsAcceptancesAndRejections(t *testing.T) {
	metrics := telemetry.NewMetrics()
	tailers := zeekTailers("/var/log/trawl/zeek", &observation.ZeekNormalizer{},
		func(*observation.Observation, string) error { return nil },
		metrics, sensor.NewDuplicateCache(sensor.MaxFingerprints))

	if len(tailers) == 0 {
		t.Fatal("no zeek tailers built")
	}
	for _, tl := range tailers {
		if tl.OnAccept == nil {
			t.Errorf("tailer for %s counts rejections but not acceptances", tl.Path)
		}
		if tl.OnReject == nil {
			t.Errorf("tailer for %s counts acceptances but not rejections", tl.Path)
		}
	}
}

// The packets the meter measures must reach the metrics the sensor exports.
//
// trawl_sensor_packets_total, trawl_sensor_kernel_drops_total and
// trawl_sensor_last_packet_timestamp_seconds were declared, registered, and
// pre-initialised with zero-valued label sets - and never incremented by
// anything. The pre-initialisation is what made it invisible: a permanently
// zero counter is indistinguishable from a working one on a quiet interface.
func TestMeasuredPacketsReachTheExportedMetrics(t *testing.T) {
	metrics := telemetry.NewMetrics()
	meter := sensor.NewPacketMeter(packetMetrics(metrics, telemetry.SourceTypeNodeInterface))

	drops := int64(4)
	meter.Observe(&observation.SuricataStats{
		KernelPackets: ptrTo(int64(1500)), KernelDrops: &drops,
		Timestamp: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC),
	})

	packets := testutil.ToFloat64(metrics.SensorPacketsTotal.WithLabelValues(
		telemetry.SourceTypeNodeInterface, telemetry.AnalyzerSuricata))
	if packets != 1500 {
		t.Errorf("trawl_sensor_packets_total = %v after measuring 1500 packets, want 1500", packets)
	}

	dropped := testutil.ToFloat64(metrics.SensorKernelDropsTotal.WithLabelValues(
		telemetry.SourceTypeNodeInterface, telemetry.AnalyzerSuricata))
	if dropped != 4 {
		t.Errorf("trawl_sensor_kernel_drops_total = %v, want 4", dropped)
	}

	last := testutil.ToFloat64(metrics.SensorLastPacketSeconds.WithLabelValues(
		telemetry.SourceTypeNodeInterface, telemetry.AnalyzerSuricata))
	if want := float64(time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC).Unix()); last != want {
		t.Errorf("trawl_sensor_last_packet_timestamp_seconds = %v, want %v", last, want)
	}
}

func ptrTo[T any](v T) *T { return &v }

// The analyzer writes .version from its own entrypoint, immediately before it
// execs, in a sibling container that starts concurrently with the sensor. The
// sensor reaches this read within milliseconds; Zeek and Suricata take seconds
// to initialise. Reading once while building the normalizers therefore lost the
// race every time, and every observation for the life of the pod carried
// source.version "unknown" - which is the failure the version was added to
// prevent, wearing the fallback's clothes.
func TestAnalyzerVersionIsResolvedWhenTheAnalyzerHasWrittenIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".version")

	src := versionFile(path)
	if got := src(); got != "" {
		t.Errorf("version = %q before the analyzer wrote the file, want the empty string the normalizer maps to unknown", got)
	}

	if err := os.WriteFile(path, []byte("zeek version 8.0.10\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := src(); got != "zeek version 8.0.10" {
		t.Errorf("version = %q once the analyzer wrote the file, want it picked up", got)
	}

	// Once read it is cached, so the steady state is not a file read per record.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if got := src(); got != "zeek version 8.0.10" {
		t.Errorf("version = %q after the file went away, want the cached value", got)
	}
}
