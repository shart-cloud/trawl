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

// Command event-worker consumes cluster and analyzer events.
//
// In US2 it runs in observation mode: it streams Hubble flows, normalizes them
// into cluster-flow observations, and writes them to stdout for Alloy. Policy
// evaluation and CaptureJob creation arrive in US4 and run in the same process,
// which is why it is leader-elected from the start — two workers evaluating the
// same policy would create duplicate captures.
//
// It is a separate binary from the controller manager so that its failure
// cannot stop tap reconciliation. Consuming a live gRPC stream is a different
// availability profile from reconciling declarative state, and the constitution
// requires one component's failure not to take out independent monitoring.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	ctrl "sigs.k8s.io/controller-runtime"

	"trawl.cloud/trawl/internal/config"
	"trawl.cloud/trawl/internal/events/hubble"
	"trawl.cloud/trawl/internal/observation"
	"trawl.cloud/trawl/internal/sanitize"
	"trawl.cloud/trawl/internal/telemetry"
)

func main() {
	var (
		configPath    = flag.String("config", "/etc/trawl/config.yaml", "Installation configuration path.")
		probeAddr     = flag.String("probe-addr", ":9110", "Health and metrics address.")
		leaderElect   = flag.Bool("leader-elect", true, "Enable leader election.")
		hubbleVersion = flag.String("hubble-version", "", "Hubble version reported on observations.")
	)
	flag.Parse()

	//nolint:gosec // configPath is an operator-supplied flag on this process's own command line
	raw, err := os.ReadFile(*configPath)
	if err != nil {
		fatal("reading installation configuration", err)
	}
	cfg, err := config.Load(raw)
	if err != nil {
		fatal("invalid installation configuration", err)
	}

	metrics := telemetry.NewMetrics()
	registry := prometheus.NewRegistry()
	if err := metrics.Register(registry); err != nil {
		fatal("registering metrics", err)
	}

	health := telemetry.NewHealth()
	emitter := newEmitter()

	normalizer := &hubble.Normalizer{
		Version: *hubbleVersion,
		Node:    os.Getenv("TRAWL_NODE_NAME"),
	}

	client, err := hubble.NewClient(cfg.Hubble, normalizer)
	if err != nil {
		fatal("creating hubble client", err)
	}

	client.OnConnectionChange = func(connected bool) {
		v := 0.0
		if connected {
			v = 1
		}
		metrics.TriggerSourceConnected.WithLabelValues(telemetry.TriggerSourceHubbleRelay).Set(v)
	}
	client.OnReject = func(reason string) {
		// A record Trawl cannot store is counted, not dropped quietly. Without
		// this the only evidence of a contract mismatch is that an
		// investigation returns fewer records than the traffic warrants
		// (FR-016).
		metrics.TriggerEventsTotal.
			WithLabelValues(telemetry.TriggerSourceHubbleRelay, telemetry.RecordMalformed).Inc()
		fmt.Fprintf(os.Stderr, "event-worker: dropped a flow: %s\n", reason)
	}
	client.OnGap = func(reason string) {
		// A gap is counted, not swallowed. Silently thinner evidence is the
		// failure an analyst cannot detect (FR-039).
		metrics.TriggerGapTotal.WithLabelValues(telemetry.TriggerSourceHubbleRelay, reason).Inc()
	}

	// Readiness reflects the flow stream. A worker that reports ready while
	// disconnected would hide the fact that denied-flow evidence is not being
	// collected.
	health.AddReadinessCheck("hubble-relay", func() error {
		if !client.Connected() {
			return fmt.Errorf("hubble flow stream is not connected")
		}
		return nil
	})

	serveProbes(*probeAddr, health, registry)

	ctx := ctrl.SetupSignalHandler()

	run := func(ctx context.Context) {
		err := client.Run(ctx, func(_ context.Context, flow *hubble.ParsedFlow) error {
			metrics.TriggerEventsTotal.
				WithLabelValues(telemetry.TriggerSourceHubbleRelay, "accepted").Inc()
			metrics.TriggerLagSeconds.
				WithLabelValues(telemetry.TriggerSourceHubbleRelay).
				Set(time.Since(flow.EventTime).Seconds())
			return emitter.emit(flow.Observation)
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "hubble stream: %v\n", sanitize.Error(err))
		}
	}

	if !*leaderElect {
		run(ctx)
		return
	}

	if err := runWithLeaderElection(ctx, cfg, run); err != nil {
		fatal("leader election", err)
	}
}

// runWithLeaderElection ensures exactly one worker consumes the stream.
//
// In US2 a second consumer would only duplicate observations, which the stable
// record IDs would collapse. It matters from US4 onward, where two workers
// evaluating the same policy would create two captures for one event — so the
// election is in place before the code that depends on it.
func runWithLeaderElection(ctx context.Context, cfg *config.Config, run func(context.Context)) error {
	restCfg, err := ctrl.GetConfig()
	if err != nil {
		return err
	}
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return err
	}

	identity := os.Getenv("POD_NAME")
	if identity == "" {
		identity, _ = os.Hostname()
	}

	lock := &resourcelock.LeaseLock{
		LeaseMeta:  metav1.ObjectMeta{Namespace: cfg.SystemNamespace, Name: "trawl-event-worker"},
		Client:     clientset.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{Identity: identity},
	}

	leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
		Lock:            lock,
		ReleaseOnCancel: true,
		LeaseDuration:   15 * time.Second,
		RenewDeadline:   10 * time.Second,
		RetryPeriod:     2 * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: run,
			OnStoppedLeading: func() {
				// Losing the lease means another worker may already be
				// consuming. Exiting is the safe response: continuing would
				// mean two consumers, which from US4 means duplicate captures.
				fmt.Fprintln(os.Stderr, "event-worker: lost leadership, exiting")
				os.Exit(0)
			},
		},
	})
	return nil
}

// emitter serializes observations to stdout for Alloy.
type emitter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func newEmitter() *emitter { return &emitter{enc: json.NewEncoder(os.Stdout)} }

func (e *emitter) emit(obs *observation.Observation) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.enc.Encode(obs)
}

func serveProbes(addr string, health *telemetry.Health, registry *prometheus.Registry) {
	mux := http.NewServeMux()
	mux.Handle("/healthz", health.HealthzHandler())
	mux.Handle("/readyz", health.ReadyzHandler())
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))

	server := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "probe server: %v\n", sanitize.Error(err))
		}
	}()
}

func fatal(what string, err error) {
	fmt.Fprintf(os.Stderr, "event-worker: %s: %v\n", what, sanitize.Error(err))
	os.Exit(1)
}
