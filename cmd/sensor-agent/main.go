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

// Command sensor-agent runs beside each analyzer, normalizing its output into
// the Trawl observation envelope and reporting target health.
//
// It writes observations to stdout for Alloy to collect, rather than shipping
// them itself. That keeps the sensor out of the delivery path: an Alloy or Loki
// outage backs up in the log pipeline instead of blocking the process that is
// reading analyzer output, and the sensor has no Loki credentials to leak.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/observation"
	"trawl.cloud/trawl/internal/sanitize"
	"trawl.cloud/trawl/internal/sensor"
	"trawl.cloud/trawl/internal/telemetry"
)

func main() {
	var (
		tapNamespace = flag.String("tap-namespace", "", "Namespace of the owning NetworkTap.")
		tapName      = flag.String("tap-name", "", "Name of the owning NetworkTap.")
		tapUID       = flag.String("tap-uid", "", "UID of the owning NetworkTap.")
		iface        = flag.String("interface", "", "Interface being observed.")
		sourceType   = flag.String("source-type", telemetry.SourceTypeNodeInterface,
			"Traffic source type this sensor observes, for metric labelling.")
		// The shared mount root the renderer creates. Nothing here derives
		// paths from it any more - each enabled analyzer's path is passed
		// explicitly, so that an analyzer the tap did not enable stays absent -
		// but the flag is still accepted, because the renderer passes it and an
		// unknown flag makes the binary exit 2 before doing anything.
		_           = flag.String("log-dir", "/var/log/trawl", "Directory holding analyzer output.")
		contentDir  = flag.String("content-dir", "/var/lib/trawl/content", "Directory holding analyzer content.")
		probeAddr   = flag.String("probe-addr", ":9100", "Address for health and metrics endpoints.")
		suricataLog = flag.String("suricata-log", "", "Suricata EVE JSON path; empty disables Suricata.")
		zeekLogDir  = flag.String("zeek-log-dir", "", "Zeek JSON log directory; empty disables Zeek.")
		tokenDir    = flag.String("token-dir", "/var/run/secrets/trawl", "Directory holding the projected API token and CA.")
	)
	flag.Parse()

	if *tapUID == "" || *iface == "" {
		fmt.Fprintln(os.Stderr, "sensor-agent requires --tap-uid and --interface")
		os.Exit(2)
	}

	resolvedSuricataLog, resolvedZeekLogDir, err := analyzerLogs(*suricataLog, *zeekLogDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sensor-agent: %v\n", err)
		os.Exit(2)
	}
	suricataLog, zeekLogDir = &resolvedSuricataLog, &resolvedZeekLogDir

	nodeName := os.Getenv("TRAWL_NODE_NAME")
	if nodeName == "" {
		fmt.Fprintln(os.Stderr, "sensor-agent requires TRAWL_NODE_NAME (set from spec.nodeName)")
		os.Exit(2)
	}

	tap := &observation.Tap{Namespace: *tapNamespace, Name: *tapName, UID: *tapUID}
	target := observation.Target{Node: nodeName, Interface: *iface}

	metrics := telemetry.NewMetrics()
	registry := prometheus.NewRegistry()
	if err := metrics.Register(registry); err != nil {
		fmt.Fprintf(os.Stderr, "registering metrics: %v\n", sanitize.Error(err))
		os.Exit(1)
	}

	health := telemetry.NewHealth()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	emitter := newEmitter()

	// One cache for this target, shared by every tailer and read by the status
	// reporter. Duplication is the same packets arriving twice, which is a
	// property of what the target receives - not of an analyzer, and certainly
	// not of a Zeek log type.
	duplicates := sensor.NewDuplicateCache(sensor.MaxFingerprints)

	// One meter for this target, for the same reason: packets at the capture
	// boundary are a property of the target. Only Suricata reports them today -
	// Zeek's logs describe traffic it parsed, not what the kernel handed it -
	// so a Zeek-only tap still reports no packets, which is honest rather than
	// zero pretending to be a measurement.
	packets := sensor.NewPacketMeter(packetMetrics(metrics, *sourceType))

	var wg sync.WaitGroup

	// Kept so the status reporter can read their counters. The reporter
	// describes the analyzers, and the tailers are what observed them.
	var suricataTailer *sensor.Tailer
	var zeekTailerSet []*sensor.Tailer
	var observers []sensor.AnalyzerObserver

	if *suricataLog != "" {
		n := &observation.SuricataNormalizer{
			Tap:     tap,
			Target:  target,
			Version: analyzerVersion(filepath.Join(filepath.Dir(*suricataLog), ".version")),
		}
		suricataTailer = &sensor.Tailer{
			Path:       *suricataLog,
			Parse:      suricataParser(n, packets),
			Emit:       emitter.emit,
			Duplicates: duplicates,
			OnAccept: func() {
				metrics.SensorRecordsTotal.
					WithLabelValues(telemetry.AnalyzerSuricata, "signature", string(sensor.ResultAccepted)).Inc()
			},
			OnReject: func(result sensor.RecordResult, _ string) {
				metrics.SensorRecordsTotal.
					WithLabelValues(telemetry.AnalyzerSuricata, "unknown", string(result)).Inc()
			},
		}
		tailer := suricataTailer
		wg.Go(func() {
			if err := tailer.Run(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "suricata tailer: %v\n", sanitize.Error(err))
			}
		})
		health.AddReadinessCheck("suricata-log", fileReadable(*suricataLog))
		observers = append(observers, &analyzerObserver{
			name:       trawlv1alpha1.AnalyzerSuricata,
			version:    n.Version,
			contentDir: filepath.Join(*contentDir, string(trawlv1alpha1.AnalyzerSuricata)),
			tailers:    []*sensor.Tailer{suricataTailer},
		})
	}

	if *zeekLogDir != "" {
		// Zeek's output was never read. The directory was checked for
		// readability and nothing tailed it, so Zeek observed the interface,
		// wrote conn, dns, ssl and the rest, and every record stopped at the
		// disk. The normalizer and the tailer both already existed; only this
		// loop was missing.
		//
		// One tailer per log, because Zeek writes a file per protocol rather
		// than one stream, and creates each only when it first has something to
		// record - which is why Tailer waits for a file that is not there yet
		// instead of treating it as an error.
		n := &observation.ZeekNormalizer{
			Tap:     tap,
			Target:  target,
			Version: analyzerVersion(filepath.Join(*zeekLogDir, ".version")),
		}
		zeekTailerSet = zeekTailers(*zeekLogDir, n, emitter.emit, metrics, duplicates)
		for _, tailer := range zeekTailerSet {
			wg.Go(func() {
				if err := tailer.Run(ctx); err != nil {
					fmt.Fprintf(os.Stderr, "zeek tailer %s: %v\n", tailer.Path, sanitize.Error(err))
				}
			})
		}
		health.AddReadinessCheck("zeek-logs", dirReadable(*zeekLogDir))
		observers = append(observers, &analyzerObserver{
			name:       trawlv1alpha1.AnalyzerZeek,
			version:    n.Version,
			contentDir: filepath.Join(*contentDir, string(trawlv1alpha1.AnalyzerZeek)),
			tailers:    zeekTailerSet,
		})
	}

	// Content currency is read from the file the init container wrote, so the
	// sensor does not need to re-walk the content tree on every heartbeat.
	health.AddReadinessCheck("analyzer-content", func() error {
		if _, err := os.Stat(*contentDir); err != nil {
			return sanitize.Errorf("analyzer content is not available: %v", err)
		}
		return nil
	})

	// The tap reported "no sensor has reported yet" for as long as the sensor
	// existed, because StatusReporter had no caller. Started only when there is
	// an analyzer to describe: a sensor with neither would otherwise publish an
	// empty target and claim to be observing nothing on purpose.
	if len(observers) > 0 {
		reporter := newStatusReporter(nodeName, *iface, os.Getenv("POD_NAME"),
			observers, duplicates, packets)
		wg.Go(func() {
			if err := publishStatus(ctx, reporter, *tapNamespace, *tapName, *tokenDir); err != nil {
				fmt.Fprintf(os.Stderr, "status reporter: %v\n", sanitize.Error(err))
			}
		})
	}

	mux := http.NewServeMux()
	mux.Handle("/healthz", health.HealthzHandler())
	mux.Handle("/readyz", health.ReadyzHandler())
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))

	server := &http.Server{
		Addr:              *probeAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "probe server: %v\n", sanitize.Error(err))
		}
	}()

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
	wg.Wait()
}

// zeekLogTypes are the logs Trawl reads. Zeek writes a file per protocol rather
// than one stream, and creates each only when it first has something to record.
var zeekLogTypes = []observation.ZeekLogType{
	observation.ZeekConn,
	observation.ZeekDNS,
	observation.ZeekHTTP,
	observation.ZeekSSL,
	observation.ZeekX509,
	observation.ZeekFiles,
	observation.ZeekNotice,
	observation.ZeekWeird,
}

// zeekTailers builds one tailer per Zeek log.
//
// Separate from main so a test can assert it builds any at all. Nothing tailed
// Zeek's output: the directory was checked for readability and left at that, so
// Zeek observed the interface, wrote conn, dns, ssl and the rest, and every
// record stopped at the disk. The normalizer and the tailer both already
// existed; only the construction was missing.
// newStatusReporter assembles what the sensor tells its NetworkTap.
//
// It is a function rather than a struct literal in main because the omission
// this guards against is an assembly mistake: StatusReporter read a Duplicates
// field that nothing ever set, so a sensor actively marking records "Suspected"
// reported Duplication: Unknown for the life of the pod. A unit test of the
// reporter cannot see that; a test of this can.
func newStatusReporter(
	nodeName, iface, instanceID string,
	observers []sensor.AnalyzerObserver,
	duplicates *sensor.DuplicateCache,
	packets *sensor.PacketMeter,
) *sensor.StatusReporter {
	return &sensor.StatusReporter{
		NodeName:   nodeName,
		Interface:  iface,
		InstanceID: instanceID,
		Analyzers:  observers,
		Duplicates: duplicates,
		Packets:    packets.Counters,
	}
}

// packetMetrics reports each measurement to the sensor's exported metrics.
//
// trawl_sensor_packets_total, trawl_sensor_kernel_drops_total and
// trawl_sensor_last_packet_timestamp_seconds were declared, registered, and
// pre-initialised with zero-valued label sets, and nothing ever incremented
// them. The pre-initialisation is what hid it: a permanently zero counter reads
// exactly like a working one on a quiet interface, which is the same confusion
// between "unmeasured" and "zero" the record-level model is careful to avoid.
//
// Only Suricata reports capture-boundary counters, so the analyzer label is
// fixed. Zeek's logs describe traffic it parsed, not what the kernel handed it.
func packetMetrics(metrics *telemetry.Metrics, sourceType string) sensor.PacketObserver {
	// Drops arrive as the analyzer's running total, and a Prometheus counter
	// takes increments, so the last reported total is kept here to difference
	// against. The meter reports measurements from one tailer goroutine, so
	// this needs no lock.
	var reported int64

	return func(inc sensor.Increment) {
		labels := []string{sourceType, telemetry.AnalyzerSuricata}

		if inc.Packets > 0 {
			metrics.SensorPacketsTotal.WithLabelValues(labels...).Add(float64(inc.Packets))
		}

		if inc.Drops != nil {
			added := *inc.Drops - reported
			if added < 0 {
				// Suricata restarted and its counter went back to zero. The
				// drops it counted before the reset were real, so the new run
				// is added rather than the difference, which would be negative
				// and would silently do nothing.
				added = *inc.Drops
			}
			if added > 0 {
				metrics.SensorKernelDropsTotal.WithLabelValues(labels...).Add(float64(added))
			}
			reported = *inc.Drops
		}

		if !inc.LastPacket.IsZero() {
			metrics.SensorLastPacketSeconds.WithLabelValues(labels...).
				Set(float64(inc.LastPacket.Unix()))
		}
	}
}

// suricataParser adapts the normalizer to the tailer, keeping the stats records
// the tailer itself has no use for.
//
// Normalize returns three values and this closure used to discard the middle
// one. Nothing downstream could notice: a stats record legitimately yields no
// observation, so throwing its counters away looked exactly like handling it,
// and the tailer's own accounting called the line consumed either way.
func suricataParser(n *observation.SuricataNormalizer, packets *sensor.PacketMeter) sensor.ParseFunc {
	return func(line []byte) (*observation.Observation, error) {
		obs, stats, err := n.Normalize(line)
		packets.Observe(stats)
		return obs, err
	}
}

func zeekTailers(
	dir string,
	n *observation.ZeekNormalizer,
	emit sensor.EmitFunc,
	metrics *telemetry.Metrics,
	duplicates *sensor.DuplicateCache,
) []*sensor.Tailer {
	out := make([]*sensor.Tailer, 0, len(zeekLogTypes))
	for _, logType := range zeekLogTypes {
		out = append(out, &sensor.Tailer{
			Path: filepath.Join(dir, string(logType)+".log"),
			Parse: func(line []byte) (*observation.Observation, error) {
				return n.Normalize(logType, line)
			},
			Emit:       emit,
			Duplicates: duplicates,
			OnAccept: func() {
				metrics.SensorRecordsTotal.
					WithLabelValues(telemetry.AnalyzerZeek, string(logType),
						string(sensor.ResultAccepted)).Inc()
			},
			OnReject: func(result sensor.RecordResult, _ string) {
				metrics.SensorRecordsTotal.
					WithLabelValues(telemetry.AnalyzerZeek, string(logType), string(result)).Inc()
			},
		})
	}
	return out
}

// analyzerVersion reads the version an analyzer recorded beside its logs.
//
// observation.schema.json requires source.version with minLength 1, and the
// normalizers take it from a field nothing set: every Zeek and Suricata record
// was produced correctly, failed validation on /source, and was counted as
// malformed. The sensor stayed ready and emitted nothing while the analyzers
// worked perfectly.
//
// A missing or unreadable file falls back to "unknown" rather than propagating
// an empty string, because an empty one reproduces exactly that failure - every
// observation dropped for want of a label about the reader rather than anything
// wrong with what was read. "unknown" is what the Hubble path already records
// when the relay does not report a version.
func analyzerVersion(path string) string {
	const unknown = "unknown"

	raw, err := os.ReadFile(path) //nolint:gosec // G304: path is built from the sensor's own flags.
	if err != nil {
		return unknown
	}
	v := strings.TrimSpace(string(raw))
	if v == "" {
		return unknown
	}
	// The schema caps this at 64 characters, and a version banner can be
	// longer than the version.
	if len(v) > 64 {
		v = v[:64]
	}
	return v
}

// emitter serializes observations to stdout.
//
// Writes are serialized because several tailers share the stream and a torn
// line would be an unparseable record for Alloy — one malformed line for a
// reason that has nothing to do with the analyzer that produced it.
type emitter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func newEmitter() *emitter {
	return &emitter{enc: json.NewEncoder(os.Stdout)}
}

func (e *emitter) emit(obs *observation.Observation, duplication string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// The duplication marker travels beside the record rather than inside the
	// envelope: it is Trawl's assessment of the observation, not part of what
	// the analyzer observed.
	return e.enc.Encode(struct {
		*observation.Observation
		DuplicationSuspected string `json:"duplication,omitempty"`
	}{Observation: obs, DuplicationSuspected: duplication})
}

// analyzerLogs resolves which analyzer output this sensor reads.
//
// An empty path means the analyzer is not present on this tap. That is how the
// renderer expresses "not enabled": it passes a log path for each analyzer the
// NetworkTap enables and leaves the flag off for the others
// (internal/controller.TestOnlyEnabledAnalyzersAreSwitchedOn).
//
// This used to default an empty path under --log-dir, which made the disable
// branch unreachable. A Zeek-only tap started a Suricata tailer on a file
// nothing writes and registered a readiness check against it, so the pod never
// became ready and the tap never went Active.
//
// A sensor with no analyzer at all is refused rather than started. It would
// tail nothing and report no observations, which is indistinguishable from an
// interface carrying no traffic.
func analyzerLogs(suricataLog, zeekLogDir string) (suricata, zeek string, err error) {
	if suricataLog == "" && zeekLogDir == "" {
		return "", "", errors.New("no analyzer configured: pass --suricata-log, --zeek-log-dir, or both")
	}
	return suricataLog, zeekLogDir, nil
}

func fileReadable(path string) func() error {
	return func() error {
		if _, err := os.Stat(path); err != nil {
			return sanitize.Errorf("analyzer log is not readable: %v", err)
		}
		return nil
	}
}

func dirReadable(path string) func() error {
	return func() error {
		info, err := os.Stat(path)
		if err != nil {
			return sanitize.Errorf("analyzer log directory is not readable: %v", err)
		}
		if !info.IsDir() {
			return fmt.Errorf("analyzer log path is not a directory")
		}
		return nil
	}
}
