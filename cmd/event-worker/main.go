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

// Command event-worker consumes cluster and analyzer events and acts on them.
//
// It streams Hubble flows and polls Suricata alerts back out of the observation
// pipeline, evaluates both against the armed CapturePolicies, and creates the
// CaptureJobs they ask for. The flows are also written to stdout for Alloy,
// which is US2's contract and does not depend on any policy being armed.
//
// It is leader-elected because two workers evaluating the same policy would
// create two captures for one event, and it is a separate binary from the
// controller manager so that its failure cannot stop tap reconciliation.
// Consuming a live gRPC stream is a different availability profile from
// reconciling declarative state, and the constitution requires one component's
// failure not to take out independent monitoring.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/audit"
	"trawl.cloud/trawl/internal/config"
	"trawl.cloud/trawl/internal/controller"
	"trawl.cloud/trawl/internal/events/hubble"
	"trawl.cloud/trawl/internal/events/loki"
	"trawl.cloud/trawl/internal/observation"
	"trawl.cloud/trawl/internal/sanitize"
	"trawl.cloud/trawl/internal/telemetry"
)

var scheme = runtime.NewScheme()

func init() {
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		fatal("registering the core scheme", err)
	}
	if err := trawlv1alpha1.AddToScheme(scheme); err != nil {
		fatal("registering the Trawl scheme", err)
	}
}

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

	flows, err := hubble.NewClient(cfg.Hubble, normalizer)
	if err != nil {
		fatal("creating hubble client", err)
	}

	flows.OnConnectionChange = func(connected bool) {
		v := 0.0
		if connected {
			v = 1
		}
		metrics.TriggerSourceConnected.WithLabelValues(telemetry.TriggerSourceHubbleRelay).Set(v)
	}
	flows.OnReject = func(reason string) {
		// A record Trawl cannot store is counted, not dropped quietly. Without
		// this the only evidence of a contract mismatch is that an
		// investigation returns fewer records than the traffic warrants
		// (FR-016).
		metrics.TriggerEventsTotal.
			WithLabelValues(telemetry.TriggerSourceHubbleRelay, telemetry.RecordMalformed).Inc()
		logf("dropped a flow: %s", sanitize.String(reason))
	}
	flows.OnGap = func(reason string) {
		// A gap is counted, not swallowed. Silently thinner evidence is the
		// failure an analyst cannot detect (FR-039).
		metrics.TriggerGapTotal.WithLabelValues(telemetry.TriggerSourceHubbleRelay, reason).Inc()
	}

	// Readiness reflects the flow stream. A worker that reports ready while
	// disconnected would hide the fact that denied-flow evidence is not being
	// collected.
	health.AddReadinessCheck("hubble-relay", func() error {
		if !flows.Connected() {
			return fmt.Errorf("hubble flow stream is not connected")
		}
		return nil
	})

	// Served from this process rather than the manager's own probe and metrics
	// servers, so a standby that holds no lease still answers probes and still
	// reports why it is standing by.
	serveProbes(*probeAddr, health, registry)

	restCfg, err := ctrl.GetConfig()
	if err != nil {
		fatal("reading the kubeconfig", err)
	}

	mgr, err := ctrl.NewManager(restCfg, ctrl.Options{
		Scheme: scheme,
		// The cache is what makes evaluation affordable: every armed policy is
		// consulted per event, and uncached reads would put that load on the
		// API server. It is restricted to the configured system namespace for
		// the same reason the manager's is - a policy elsewhere is one the
		// admission gate already refuses, and the worker must not be able to
		// act on it even if one exists (FR-001).
		Cache: cache.Options{
			DefaultNamespaces: map[string]cache.Config{cfg.SystemNamespace: {}},
		},
		// Both disabled: this process serves its own, above.
		Metrics:                 metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress:  "0",
		LeaderElection:          *leaderElect,
		LeaderElectionID:        "trawl-event-worker",
		LeaderElectionNamespace: cfg.SystemNamespace,
		// Safe here: the process ends when the manager stops, so releasing the
		// lease on the way out only shortens the gap in which nothing is
		// evaluating. Holding it to expiry would leave denied flows uncollected
		// for a lease duration on every rollout.
		LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		fatal("creating the manager", err)
	}

	auditClient, err := audit.NewClient(audit.ClientOptions{
		Endpoint:   cfg.EventWorker.AuditClient.Endpoint,
		ServerName: cfg.EventWorker.AuditClient.ServerName,
		CAFile:     cfg.EventWorker.AuditClient.CAFile,
		CertFile:   cfg.EventWorker.AuditClient.CertFile,
		KeyFile:    cfg.EventWorker.AuditClient.KeyFile,
	})
	if err != nil {
		// Fatal rather than degraded. The worker holds no ledger credentials of
		// its own (ADR-0003), so without this it can never record that a policy
		// asked for a capture - and FR-036 means it must then never create one.
		// A worker that starts and silently declines every trigger is worse
		// than one that does not start.
		fatal("creating the audit client", err)
	}

	engine := &controller.PolicyEngine{
		Client:    mgr.GetClient(),
		Audit:     auditClient,
		Actor:     workerActor(cfg),
		Namespace: cfg.SystemNamespace,
		Metrics:   metrics,
	}
	tracker := &controller.PolicyStatusTracker{
		Client:    mgr.GetClient(),
		Namespace: cfg.SystemNamespace,
		Metrics:   metrics,
	}

	worker := &worker{
		engine:  engine,
		tracker: tracker,
		emitter: emitter,
		flows:   flows,
		alerts:  loki.NewClient(cfg.Loki.Endpoint, cfg.Loki.TenantID, nil),
		cursors: &loki.ConfigMapStore{
			Client:    mgr.GetClient(),
			Namespace: cfg.SystemNamespace,
		},
		reader:         mgr.GetClient(),
		namespace:      cfg.SystemNamespace,
		metrics:        metrics,
		pollInterval:   time.Duration(cfg.EventWorker.AlertPollInterval),
		statusInterval: time.Duration(cfg.EventWorker.StatusInterval),
	}
	if err := mgr.Add(worker); err != nil {
		fatal("registering the worker", err)
	}

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		fatal("running the worker", err)
	}
}

// workerActor is the identity the worker records its own actions under.
//
// The workload identity, not the policy's: the act was the worker's, on the
// policy's behalf, and impersonating the policy would make the ledger say a
// rule wrote a record it has no way to write.
func workerActor(cfg *config.Config) audit.Actor {
	return audit.Actor{
		Username: fmt.Sprintf("system:serviceaccount:%s:%s",
			cfg.SystemNamespace, cfg.Capture.EventWorkerServiceAccount),
	}
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
			logf("probe server: %v", sanitize.Error(err))
		}
	}()
}

func fatal(what string, err error) {
	fmt.Fprintf(os.Stderr, "event-worker: %s: %v\n", what, sanitize.Error(err))
	os.Exit(1)
}
