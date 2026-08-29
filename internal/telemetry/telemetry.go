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

// Package telemetry provides the metrics, health endpoints, structured logging,
// and build information shared by every Trawl binary.
//
// The metric set is a contract (contracts/telemetry.md), not a convenience. Its
// names and label sets are asserted by a test, because dashboards and alerts
// group by them and because an unbounded label is a cardinality incident that
// only appears under production load.
//
// Health follows the split Kubernetes expects and operators rely on: /healthz is
// process liveness alone, so a Loki or MinIO outage cannot trigger a restart
// loop, while /readyz reports dependency readiness with sanitized reasons.
package telemetry

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"trawl.cloud/trawl/internal/sanitize"
)

// Latency buckets chosen against the success criteria rather than defaults, so
// the histograms can answer the questions the spec asks.

// reconcileBuckets straddle SC-002 (95% of reconciliations truthful within 2m).
var reconcileBuckets = []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300}

// captureStartBuckets straddle SC-006 (95% of captures start within 10s).
var captureStartBuckets = []float64{0.1, 0.25, 0.5, 1, 2, 5, 10, 20, 30, 60}

// captureStoreBuckets straddle SC-006 (downloadable within 60s of capture end).
var captureStoreBuckets = []float64{0.5, 1, 2, 5, 10, 20, 30, 60, 120, 300}

// captureSizeBuckets span 1 MiB to 8 GiB; SC-007 bounds overshoot at 1 MiB.
var captureSizeBuckets = prometheus.ExponentialBuckets(1<<20, 2, 14)

// expiryLagBuckets straddle SC-010 (removal within 24h of the deadline).
var expiryLagBuckets = []float64{60, 300, 900, 3600, 7200, 21600, 43200, 86400, 172800}

// Metrics is the complete Trawl metric set.
//
// It is a struct rather than package-level globals so tests can register a fresh
// set against their own registry, and so a binary registers exactly the metrics
// it uses.
type Metrics struct {
	// Audit ledger and replay.
	AuditCommitTotal           *prometheus.CounterVec
	AuditConflictTotal         prometheus.Counter
	AuditReplayTotal           *prometheus.CounterVec
	AuditBacklogObjects        prometheus.Gauge
	AuditOldestUnforwardedSecs prometheus.Gauge

	// Controller and reconciliation.
	ReconcileTotal           *prometheus.CounterVec
	ReconcileDurationSeconds *prometheus.HistogramVec
	WorkqueueDepth           *prometheus.GaugeVec
	StatusUpdateFailures     *prometheus.CounterVec
	FinalizerFailures        *prometheus.CounterVec

	// Sensor and ingestion.
	SensorPacketsTotal      *prometheus.CounterVec
	SensorKernelDropsTotal  *prometheus.CounterVec
	SensorRecordsTotal      *prometheus.CounterVec
	SensorLastPacketSeconds *prometheus.GaugeVec
	AlloyDeliveryFailures   *prometheus.CounterVec

	// Trigger evaluation.
	TriggerEventsTotal     *prometheus.CounterVec
	PolicyDecisionsTotal   *prometheus.CounterVec
	TriggerSourceConnected *prometheus.GaugeVec
	TriggerLagSeconds      *prometheus.GaugeVec
	TriggerGapTotal        *prometheus.CounterVec

	// Capture and artifact.
	CaptureRequestsTotal     *prometheus.CounterVec
	CaptureTransitionsTotal  *prometheus.CounterVec
	CaptureStartLatency      *prometheus.HistogramVec
	CaptureStoreLatency      *prometheus.HistogramVec
	CaptureSizeBytes         *prometheus.HistogramVec
	CaptureBoundStopTotal    *prometheus.CounterVec
	ArtifactOperationsTotal  *prometheus.CounterVec
	ArtifactExpiryLagSeconds prometheus.Histogram
	ArtifactDownloadTotal    *prometheus.CounterVec
}

// NewMetrics builds the contract metric set. Nothing is registered yet, so a
// caller chooses its registry.
func NewMetrics() *Metrics {
	return &Metrics{
		AuditCommitTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trawl_audit_commit_total",
			Help: "Conditional audit-ledger commits and idempotent retries.",
		}, []string{"decision", "result"}),
		AuditConflictTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "trawl_audit_conflict_total",
			Help: "Audit records where the same stable key was observed with different content.",
		}),
		AuditReplayTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trawl_audit_replay_total",
			Help: "Audit ledger records forwarded to the searchable stream.",
		}, []string{"result"}),
		AuditBacklogObjects: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "trawl_audit_backlog_objects",
			Help: "Audit ledger objects not yet covered by the persisted replay cursor.",
		}),
		AuditOldestUnforwardedSecs: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "trawl_audit_oldest_unforwarded_seconds",
			Help: "Age of the oldest audit replay backlog object.",
		}),

		ReconcileTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trawl_reconcile_total",
			Help: "Reconciliations by controller and result.",
		}, []string{"controller", "result"}),
		ReconcileDurationSeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "trawl_reconcile_duration_seconds",
			Help:    "Reconcile latency.",
			Buckets: reconcileBuckets,
		}, []string{"controller"}),
		WorkqueueDepth: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "trawl_workqueue_depth",
			Help: "Pending reconcile work per controller.",
		}, []string{"controller"}),
		StatusUpdateFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trawl_status_update_failures_total",
			Help: "Failed status writes.",
		}, []string{"resource_kind", "reason"}),
		FinalizerFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trawl_finalizer_failures_total",
			Help: "External cleanup failures during finalization.",
		}, []string{"resource_kind", "reason"}),

		SensorPacketsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trawl_sensor_packets_total",
			Help: "Packets reported at the capture/analyzer boundary.",
		}, []string{"source_type", "analyzer"}),
		SensorKernelDropsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trawl_sensor_kernel_drops_total",
			Help: "Kernel packet drops where the analyzer reports them.",
		}, []string{"source_type", "analyzer"}),
		SensorRecordsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trawl_sensor_records_total",
			Help: "Normalized, unsupported, or malformed analyzer records.",
		}, []string{"source_kind", "observation_type", "result"}),
		SensorLastPacketSeconds: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "trawl_sensor_last_packet_timestamp_seconds",
			Help: "Latest packet time observed by this sensor process.",
		}, []string{"source_type", "analyzer"}),
		AlloyDeliveryFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trawl_alloy_delivery_failures_total",
			Help: "Downstream log delivery failures observed by Trawl.",
		}, []string{"reason"}),

		TriggerEventsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trawl_trigger_events_total",
			Help: "Trigger events processed, replayed, malformed, or lost.",
		}, []string{"source", "result"}),
		PolicyDecisionsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trawl_policy_decisions_total",
			Help: "Capture policy match outcomes.",
		}, []string{"trigger_type", "decision"}),
		TriggerSourceConnected: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "trawl_trigger_source_connected",
			Help: "1 when the trigger source connection or query path is healthy.",
		}, []string{"source"}),
		TriggerLagSeconds: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "trawl_trigger_lag_seconds",
			Help: "Now minus the latest fully processed observation.",
		}, []string{"source"}),
		TriggerGapTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trawl_trigger_gap_total",
			Help: "Known trigger coverage gaps.",
		}, []string{"source", "reason"}),

		CaptureRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trawl_capture_requests_total",
			Help: "Manual and policy capture requests by admission or resolution outcome.",
		}, []string{"request_type", "result"}),
		CaptureTransitionsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trawl_capture_transitions_total",
			Help: "Capture lifecycle transitions.",
		}, []string{"from", "to"}),
		CaptureStartLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "trawl_capture_start_latency_seconds",
			Help:    "Request time to actual capture start.",
			Buckets: captureStartBuckets,
		}, []string{"request_type"}),
		CaptureStoreLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "trawl_capture_store_latency_seconds",
			Help:    "Capture end to verified terminal storage result.",
			Buckets: captureStoreBuckets,
		}, []string{"result"}),
		CaptureSizeBytes: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "trawl_capture_size_bytes",
			Help:    "Completed artifact sizes.",
			Buckets: captureSizeBuckets,
		}, []string{"request_type"}),
		CaptureBoundStopTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trawl_capture_bound_stop_total",
			Help: "Which bound stopped collection: duration, size, cancellation, or error.",
		}, []string{"bound"}),
		ArtifactOperationsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trawl_artifact_operations_total",
			Help: "Artifact upload, verify, presign, and delete operations.",
		}, []string{"operation", "result"}),
		ArtifactExpiryLagSeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "trawl_artifact_expiry_lag_seconds",
			Help:    "Verified deletion time minus retention deadline.",
			Buckets: expiryLagBuckets,
		}),
		ArtifactDownloadTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "trawl_artifact_download_total",
			Help: "Gateway download authorization outcomes.",
		}, []string{"decision"}),
	}
}

// collectors lists every metric so Register and the contract test agree on the
// set without either of them enumerating it twice.
func (m *Metrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{
		m.AuditCommitTotal, m.AuditConflictTotal, m.AuditReplayTotal,
		m.AuditBacklogObjects, m.AuditOldestUnforwardedSecs,
		m.ReconcileTotal, m.ReconcileDurationSeconds, m.WorkqueueDepth,
		m.StatusUpdateFailures, m.FinalizerFailures,
		m.SensorPacketsTotal, m.SensorKernelDropsTotal, m.SensorRecordsTotal,
		m.SensorLastPacketSeconds, m.AlloyDeliveryFailures,
		m.TriggerEventsTotal, m.PolicyDecisionsTotal, m.TriggerSourceConnected,
		m.TriggerLagSeconds, m.TriggerGapTotal,
		m.CaptureRequestsTotal, m.CaptureTransitionsTotal, m.CaptureStartLatency,
		m.CaptureStoreLatency, m.CaptureSizeBytes, m.CaptureBoundStopTotal,
		m.ArtifactOperationsTotal, m.ArtifactExpiryLagSeconds, m.ArtifactDownloadTotal,
	}
}

// Register adds every metric to reg.
//
// Vector metrics are pre-initialized across their enum values so a series exists
// at zero before the first event. Without that, `rate()` over a counter that has
// never fired returns nothing rather than zero, and an alert on "no successful
// commits" silently never evaluates.
func (m *Metrics) Register(reg prometheus.Registerer) error {
	for _, c := range m.collectors() {
		if err := reg.Register(c); err != nil {
			return sanitize.Errorf("registering metrics: %v", err)
		}
	}
	m.initSeries()
	return nil
}

func (m *Metrics) initSeries() {
	for _, d := range auditDecisions {
		for _, r := range auditResults {
			m.AuditCommitTotal.WithLabelValues(d, r)
		}
	}
	for _, r := range auditResults {
		m.AuditReplayTotal.WithLabelValues(r)
	}
	for _, c := range controllers {
		m.ReconcileDurationSeconds.WithLabelValues(c)
		m.WorkqueueDepth.WithLabelValues(c)
		for _, r := range reconcileResults {
			m.ReconcileTotal.WithLabelValues(c, r)
		}
	}
	for _, st := range sourceTypes {
		for _, a := range analyzers {
			m.SensorPacketsTotal.WithLabelValues(st, a)
			m.SensorKernelDropsTotal.WithLabelValues(st, a)
			m.SensorLastPacketSeconds.WithLabelValues(st, a)
		}
	}
	for _, s := range triggerSources {
		m.TriggerSourceConnected.WithLabelValues(s)
		m.TriggerLagSeconds.WithLabelValues(s)
	}
	for _, d := range policyDecisions {
		m.PolicyDecisionsTotal.WithLabelValues("suricata", d)
	}
	// Metrics whose label values are not fully enumerable ahead of time
	// (resource kinds, reasons, operations) are left to first use.
	m.StatusUpdateFailures.WithLabelValues("NetworkTap", "Unknown")
	m.FinalizerFailures.WithLabelValues("NetworkTap", "Unknown")
	m.SensorRecordsTotal.WithLabelValues(AnalyzerSuricata, "signature", RecordAccepted)
	m.AlloyDeliveryFailures.WithLabelValues("Unknown")
	for _, s := range triggerSources {
		m.TriggerEventsTotal.WithLabelValues(s, "accepted")
		m.TriggerGapTotal.WithLabelValues(s, "Unknown")
	}
	m.CaptureRequestsTotal.WithLabelValues("manual", "accepted")
	m.CaptureTransitionsTotal.WithLabelValues("Pending", "Capturing")
	m.CaptureStartLatency.WithLabelValues("manual")
	m.CaptureStoreLatency.WithLabelValues("success")
	m.CaptureSizeBytes.WithLabelValues("manual")
	m.CaptureBoundStopTotal.WithLabelValues("duration")
	m.ArtifactOperationsTotal.WithLabelValues("upload", "success")
	m.ArtifactDownloadTotal.WithLabelValues(AuditDecisionAllowed)
}

// Health serves the liveness and readiness endpoints.
//
// The distinction is load-bearing. /healthz answers "is this process alive",
// and nothing else: if it consulted Loki or MinIO, an outage in either would
// make Kubernetes restart healthy pods and turn a dependency blip into a
// monitoring outage. /readyz answers "can this process do its job right now".
type Health struct {
	mu     sync.RWMutex
	checks map[string]func() error
}

// NewHealth returns a Health with no readiness checks registered.
func NewHealth() *Health {
	return &Health{checks: make(map[string]func() error)}
}

// AddReadinessCheck registers a named dependency check. The name must be a
// bounded, non-secret identifier; it appears in the /readyz body.
func (h *Health) AddReadinessCheck(name string, check func() error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checks[name] = check
}

// HealthzHandler reports process liveness only.
func (h *Health) HealthzHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
}

// ReadyzHandler reports dependency readiness with sanitized reasons.
//
// A dependency error commonly carries a presigned URL or a token, so every
// reason is sanitized before it reaches the response body.
func (h *Health) ReadyzHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		h.mu.RLock()
		names := make([]string, 0, len(h.checks))
		for name := range h.checks {
			names = append(names, name)
		}
		checks := h.checks
		h.mu.RUnlock()
		slices.Sort(names)

		var failures []string
		for _, name := range names {
			if err := checks[name](); err != nil {
				failures = append(failures, fmt.Sprintf("%s: %s", name, sanitize.String(err.Error())))
			}
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if len(failures) > 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(strings.Join(failures, "\n") + "\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	})
}

// BuildInfo identifies the running build.
type BuildInfo struct {
	Version string
	Commit  string
	Dirty   bool
}

// mutableTags are refs that can be repointed after review, so they cannot
// identify a build.
var mutableTags = map[string]struct{}{
	"latest": {}, "main": {}, "master": {}, "edge": {}, "dev": {}, "nightly": {},
}

var versionRE = regexp.MustCompile(`^v?\d+\.\d+\.\d+`)

// NewBuildInfo validates and returns build identification.
//
// A mutable tag is rejected: "which version is running" must have an answer that
// does not change underneath the person asking.
func NewBuildInfo(version, commit string, dirty bool) (BuildInfo, error) {
	if version == "" {
		return BuildInfo{}, errors.New("build version is required")
	}
	if _, mutable := mutableTags[strings.ToLower(version)]; mutable {
		return BuildInfo{}, fmt.Errorf("build version %q is a mutable tag", version)
	}
	if !versionRE.MatchString(version) {
		return BuildInfo{}, fmt.Errorf("build version %q is not a semantic version", version)
	}
	if commit == "" {
		return BuildInfo{}, errors.New("build commit is required")
	}
	return BuildInfo{Version: version, Commit: commit, Dirty: dirty}, nil
}
