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

package telemetry

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// contracts/telemetry.md fixes these metric names, label sets, and enums. A
// change here is a contract change: dashboards and alerts group by these labels,
// and an unbounded one is a cardinality incident in a live cluster.

func TestMetricNamesMatchContract(t *testing.T) {
	want := []string{
		"trawl_audit_commit_total",
		"trawl_audit_conflict_total",
		"trawl_audit_replay_total",
		"trawl_audit_backlog_objects",
		"trawl_audit_oldest_unforwarded_seconds",
		"trawl_reconcile_total",
		"trawl_reconcile_duration_seconds",
		"trawl_workqueue_depth",
		"trawl_status_update_failures_total",
		"trawl_finalizer_failures_total",
		"trawl_sensor_packets_total",
		"trawl_sensor_kernel_drops_total",
		"trawl_sensor_records_total",
		"trawl_sensor_last_packet_timestamp_seconds",
		"trawl_alloy_delivery_failures_total",
		"trawl_trigger_events_total",
		"trawl_policy_decisions_total",
		"trawl_trigger_source_connected",
		"trawl_trigger_lag_seconds",
		"trawl_trigger_gap_total",
		"trawl_capture_requests_total",
		"trawl_capture_transitions_total",
		"trawl_capture_start_latency_seconds",
		"trawl_capture_store_latency_seconds",
		"trawl_capture_size_bytes",
		"trawl_capture_bound_stop_total",
		"trawl_artifact_operations_total",
		"trawl_artifact_expiry_lag_seconds",
		"trawl_artifact_download_total",
	}

	reg := prometheus.NewRegistry()
	m := NewMetrics()
	if err := m.Register(reg); err != nil {
		t.Fatalf("Register: %v", err)
	}

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	got := make([]string, 0, len(families))
	for _, f := range families {
		got = append(got, f.GetName())
	}

	for _, name := range want {
		if !slices.Contains(got, name) {
			t.Errorf("contract metric %q is not registered", name)
		}
	}
	for _, name := range got {
		if !slices.Contains(want, name) {
			t.Errorf("metric %q is registered but not in the telemetry contract", name)
		}
	}
}

func TestMetricLabelsMatchContract(t *testing.T) {
	want := map[string][]string{
		"trawl_audit_commit_total":                   {"decision", "result"},
		"trawl_audit_conflict_total":                 {},
		"trawl_audit_replay_total":                   {"result"},
		"trawl_audit_backlog_objects":                {},
		"trawl_audit_oldest_unforwarded_seconds":     {},
		"trawl_reconcile_total":                      {"controller", "result"},
		"trawl_reconcile_duration_seconds":           {"controller"},
		"trawl_workqueue_depth":                      {"controller"},
		"trawl_status_update_failures_total":         {"reason", "resource_kind"},
		"trawl_finalizer_failures_total":             {"reason", "resource_kind"},
		"trawl_sensor_packets_total":                 {"analyzer", "source_type"},
		"trawl_sensor_kernel_drops_total":            {"analyzer", "source_type"},
		"trawl_sensor_records_total":                 {"observation_type", "result", "source_kind"},
		"trawl_sensor_last_packet_timestamp_seconds": {"analyzer", "source_type"},
		"trawl_alloy_delivery_failures_total":        {"reason"},
		"trawl_trigger_events_total":                 {"result", "source"},
		"trawl_policy_decisions_total":               {"decision", "trigger_type"},
		"trawl_trigger_source_connected":             {"source"},
		"trawl_trigger_lag_seconds":                  {"source"},
		"trawl_trigger_gap_total":                    {"reason", "source"},
		"trawl_capture_requests_total":               {"request_type", "result"},
		"trawl_capture_transitions_total":            {"from", "to"},
		"trawl_capture_start_latency_seconds":        {"request_type"},
		"trawl_capture_store_latency_seconds":        {"result"},
		"trawl_capture_size_bytes":                   {"request_type"},
		"trawl_capture_bound_stop_total":             {"bound"},
		"trawl_artifact_operations_total":            {"operation", "result"},
		"trawl_artifact_expiry_lag_seconds":          {},
		"trawl_artifact_download_total":              {"decision"},
	}

	reg := prometheus.NewRegistry()
	m := NewMetrics()
	if err := m.Register(reg); err != nil {
		t.Fatalf("Register: %v", err)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	for _, f := range families {
		wantLabels, ok := want[f.GetName()]
		if !ok {
			continue // covered by TestMetricNamesMatchContract
		}
		got := labelNames(f.GetMetric())
		slices.Sort(got)
		if !slices.Equal(got, wantLabels) {
			t.Errorf("%s labels = %v, want %v", f.GetName(), got, wantLabels)
		}
	}
}

func labelNames(metrics []*dto.Metric) []string {
	if len(metrics) == 0 {
		return []string{}
	}
	names := make([]string, 0, len(metrics[0].GetLabel()))
	for _, lp := range metrics[0].GetLabel() {
		names = append(names, lp.GetName())
	}
	return names
}

func TestHighCardinalityLabelsAreRejected(t *testing.T) {
	// Constitution IV: addresses, ports, rule identifiers, and unique flow
	// values stay structured fields. If one of these ever appears as a label
	// name, it is a cardinality bug that will only show up under load.
	forbidden := []string{
		"source_ip", "destination_ip", "src_ip", "dst_ip",
		"source_port", "destination_port", "port",
		"rule_id", "signature_id", "community_id", "flow_id", "zeek_uid",
		"tap_name", "tap_uid", "capture_job", "capturejob", "policy",
		"policy_name", "policy_uid", "node", "target_node", "namespace",
		"username", "user", "request_id", "object_key", "url",
	}

	reg := prometheus.NewRegistry()
	m := NewMetrics()
	if err := m.Register(reg); err != nil {
		t.Fatalf("Register: %v", err)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}

	for _, f := range families {
		for _, name := range labelNames(f.GetMetric()) {
			if slices.Contains(forbidden, name) {
				t.Errorf("%s uses high-cardinality label %q", f.GetName(), name)
			}
		}
	}
}

func TestLabelValueEnumsAreClosed(t *testing.T) {
	// The enums are what make the label sets bounded. A caller passing an
	// arbitrary string must be caught, not silently create a new series.
	cases := []struct {
		name  string
		valid []string
		check func(string) bool
	}{
		{"audit decision", []string{"allowed", "denied", "succeeded", "failed"}, IsValidAuditDecision},
		{"audit result", []string{"success", "retry", "unavailable", "conflict"}, IsValidAuditResult},
		{"controller", []string{"networktap", "capturejob", "retention"}, IsValidController},
		{"reconcile result", []string{"success", "requeue", "invalid", "dependency_unavailable", "error"}, IsValidReconcileResult},
		{"source type", []string{"mirror_interface", "node_interface"}, IsValidSourceType},
		{"analyzer", []string{"suricata", "zeek"}, IsValidAnalyzer},
		{"record result", []string{"accepted", "unsupported", "malformed"}, IsValidRecordResult},
		{"trigger source", []string{"suricata_loki", "hubble_relay"}, IsValidTriggerSource},
		{"policy decision", []string{"not_matched", "created", "duplicate", "rate_limited", "disarmed", "failed"}, IsValidPolicyDecision},
		{"request type", []string{"manual", "policy"}, IsValidRequestType},
		{"request result", []string{"accepted", "rejected", "started", "failed"}, IsValidRequestResult},
		{"bound", []string{"duration", "size", "cancelled", "error"}, IsValidBound},
		{"artifact operation", []string{"upload", "verify", "presign", "delete"}, IsValidArtifactOp},
		{"artifact result", []string{"success", "failure", "unavailable"}, IsValidArtifactResult},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, v := range tc.valid {
				if !tc.check(v) {
					t.Errorf("%q rejected but is in the contract enum", v)
				}
			}
			for _, v := range []string{"", "unknown", "SUCCESS", "10.0.0.1", "arbitrary"} {
				if tc.check(v) {
					t.Errorf("%q accepted but is not in the contract enum", v)
				}
			}
		})
	}
}

func TestHealthzReportsLivenessOnly(t *testing.T) {
	// /healthz must not depend on Loki, MinIO, or Hubble: a dependency outage
	// must not cause Kubernetes to restart an otherwise healthy process.
	h := NewHealth()
	h.AddReadinessCheck("minio", func() error { return errDependency })

	rec := httptest.NewRecorder()
	h.HealthzHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("/healthz = %d with a failing dependency, want %d", rec.Code, http.StatusOK)
	}
}

func TestReadyzReflectsDependenciesWithSafeReasons(t *testing.T) {
	h := NewHealth()
	h.AddReadinessCheck("audit-ledger", func() error {
		// A real client error of this shape carries a presigned URL.
		return errWithSecret
	})

	rec := httptest.NewRecorder()
	h.ReadyzHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("/readyz = %d with a failing dependency, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "audit-ledger") {
		t.Errorf("/readyz does not name the failing dependency: %s", body)
	}
	if strings.Contains(body, "X-Amz-Signature") || strings.Contains(body, "deadbeef") {
		t.Errorf("/readyz leaked credential material: %s", body)
	}
}

func TestReadyzOKWhenAllChecksPass(t *testing.T) {
	h := NewHealth()
	h.AddReadinessCheck("loki", func() error { return nil })

	rec := httptest.NewRecorder()
	h.ReadyzHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("/readyz = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestBuildInfoRejectsMutableTag(t *testing.T) {
	// contracts/telemetry.md: build information carries version, commit, and a
	// dirty boolean, never a mutable tag like `latest`.
	if _, err := NewBuildInfo("latest", "abc123", false); err == nil {
		t.Error("NewBuildInfo accepted the mutable tag 'latest'")
	}
	if _, err := NewBuildInfo("v0.1.0", "", false); err == nil {
		t.Error("NewBuildInfo accepted an empty commit")
	}
	bi, err := NewBuildInfo("v0.1.0", "9f3c2a1", true)
	if err != nil {
		t.Fatalf("NewBuildInfo rejected a valid build: %v", err)
	}
	if bi.Version != "v0.1.0" || bi.Commit != "9f3c2a1" || !bi.Dirty {
		t.Errorf("build info round trip mismatch: %+v", bi)
	}
}
