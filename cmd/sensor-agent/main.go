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
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

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
		logDir       = flag.String("log-dir", "/var/log/trawl", "Directory holding analyzer output.")
		contentDir   = flag.String("content-dir", "/var/lib/trawl/content", "Directory holding analyzer content.")
		probeAddr    = flag.String("probe-addr", ":9100", "Address for health and metrics endpoints.")
		suricataLog  = flag.String("suricata-log", "", "Suricata EVE JSON path; empty disables Suricata.")
		zeekLogDir   = flag.String("zeek-log-dir", "", "Zeek JSON log directory; empty disables Zeek.")
	)
	flag.Parse()

	if *tapUID == "" || *iface == "" {
		fmt.Fprintln(os.Stderr, "sensor-agent requires --tap-uid and --interface")
		os.Exit(2)
	}

	// Analyzer paths default under the shared log directory, so the operator
	// renders one mount rather than a path per analyzer.
	if *suricataLog == "" {
		*suricataLog = filepath.Join(*logDir, "suricata", "eve.json")
	}
	if *zeekLogDir == "" {
		*zeekLogDir = filepath.Join(*logDir, "zeek")
	}

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
	var wg sync.WaitGroup

	if *suricataLog != "" {
		n := &observation.SuricataNormalizer{Tap: tap, Target: target}
		tailer := &sensor.Tailer{
			Path: *suricataLog,
			Parse: func(line []byte) (*observation.Observation, error) {
				obs, _, err := n.Normalize(line)
				return obs, err
			},
			Emit:       emitter.emit,
			Duplicates: sensor.NewDuplicateCache(sensor.MaxFingerprints),
			OnReject: func(result sensor.RecordResult, _ string) {
				metrics.SensorRecordsTotal.
					WithLabelValues(telemetry.AnalyzerSuricata, "unknown", string(result)).Inc()
			},
		}
		wg.Go(func() {
			if err := tailer.Run(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "suricata tailer: %v\n", sanitize.Error(err))
			}
		})
		health.AddReadinessCheck("suricata-log", fileReadable(*suricataLog))
	}

	if *zeekLogDir != "" {
		health.AddReadinessCheck("zeek-logs", dirReadable(*zeekLogDir))
	}

	// Content currency is read from the file the init container wrote, so the
	// sensor does not need to re-walk the content tree on every heartbeat.
	health.AddReadinessCheck("analyzer-content", func() error {
		if _, err := os.Stat(*contentDir); err != nil {
			return sanitize.Errorf("analyzer content is not available: %v", err)
		}
		return nil
	})

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
