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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/audit"
	"trawl.cloud/trawl/internal/controller"
	"trawl.cloud/trawl/internal/events/loki"
	"trawl.cloud/trawl/internal/observation"
	"trawl.cloud/trawl/internal/status"
	"trawl.cloud/trawl/internal/telemetry"
)

const (
	testNamespace = "trawl-system"
	testTapUID    = types.UID("00000000-0000-4000-8000-000000000001")
	testNode      = "talos-node"
)

// silentCommitter accepts every audit record. The ledger's own behavior is
// tested where it lives; here it must only not be the thing under test.
type silentCommitter struct{}

func (silentCommitter) Commit(context.Context, audit.Record) (audit.CommitResult, error) {
	return audit.CommitResult{Result: audit.ResultSuccess}, nil
}

// alertObservation is one Suricata signature record as the pipeline stores it.
func alertObservation(id string, at time.Time) *observation.Observation {
	port := func(v int32) *int32 { return &v }
	return &observation.Observation{
		SchemaVersion:   observation.SchemaVersion,
		ID:              id,
		EventTime:       at,
		ObservedAt:      at,
		Source:          observation.Source{Kind: observation.SourceSuricata, Version: "8.0.6"},
		Tap:             &observation.Tap{Namespace: testNamespace, Name: "node-eno1", UID: string(testTapUID)},
		Target:          observation.Target{Node: testNode, Interface: "eno1"},
		ObservationType: observation.TypeSignature,
		Flow: &observation.Flow{
			Protocol:    "tcp",
			Source:      observation.Endpoint{IP: "192.0.2.10", Port: port(39510)},
			Destination: observation.Endpoint{IP: "198.51.100.20", Port: port(22)},
		},
		Details: observation.Details{Signature: &observation.Signature{
			RuleID: 2038968, Severity: 2, Category: "Misc activity", Message: "ET INFO example",
		}},
	}
}

// serveAlerts answers query_range with these records, in Loki's shape.
func serveAlerts(t *testing.T, records ...*observation.Observation) *httptest.Server {
	t.Helper()

	type stream struct {
		Values [][]any `json:"values"`
	}
	var s stream
	for _, obs := range records {
		line, err := json.Marshal(obs)
		if err != nil {
			t.Fatalf("encoding a fixture observation: %v", err)
		}
		s.Values = append(s.Values, []any{strconv.FormatInt(obs.EventTime.UnixNano(), 10), string(line)})
	}
	body := map[string]any{"data": map[string]any{"result": []stream{s}}}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(body); err != nil {
			t.Errorf("writing the alert response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// armedTapAndPolicy is a tap observing on testNode and a policy armed against
// severity 2 alerts on it.
func armedTapAndPolicy() []client.Object {
	tap := &trawlv1alpha1.NetworkTap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace, Name: "node-eno1", UID: testTapUID, Generation: 1,
		},
		Status: trawlv1alpha1.NetworkTapStatus{
			ObservedGeneration: 1,
			Phase:              trawlv1alpha1.TapPhaseActive,
			Targets: []trawlv1alpha1.TargetStatus{{
				NodeName: testNode, Interface: "eno1", HeartbeatTime: metav1.Now(),
			}},
			Conditions: []metav1.Condition{{
				Type: status.TypeAccepted, Status: metav1.ConditionTrue,
				Reason: status.ReasonAccepted, ObservedGeneration: 1,
				LastTransitionTime: metav1.Now(),
			}},
		},
	}
	policy := &trawlv1alpha1.CapturePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace, Name: "ssh-scan",
			UID: types.UID("11111111-1111-4111-8111-111111111111"), Generation: 1,
		},
		Spec: trawlv1alpha1.CapturePolicySpec{
			TapRef: corev1.LocalObjectReference{Name: "node-eno1"},
			Armed:  true,
			Trigger: trawlv1alpha1.CapturePolicyTrigger{
				Type:          trawlv1alpha1.CaptureTriggerSuricataAlert,
				SuricataAlert: &trawlv1alpha1.SuricataAlertTrigger{Severities: []int32{1, 2}},
			},
			Capture: trawlv1alpha1.PolicyCaptureBounds{
				Duration: "30s", MaxSize: resource.MustParse("64Mi"),
			},
			Retention: "7d",
			RateLimit: trawlv1alpha1.CaptureRateLimit{
				MaxCapturesPerHour: 5,
				Cooldown:           metav1.Duration{Duration: 5 * time.Minute},
			},
		},
	}
	return []client.Object{tap, policy}
}

func newTestWorker(t *testing.T, lokiURL string, objs ...client.Object) *worker {
	t.Helper()

	scheme := clientgoscheme.Scheme
	if err := trawlv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("adding the Trawl scheme: %v", err)
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(&trawlv1alpha1.NetworkTap{}, &trawlv1alpha1.CapturePolicy{}, &trawlv1alpha1.CaptureJob{}).
		Build()

	return &worker{
		engine: &controller.PolicyEngine{
			Client: c, Audit: silentCommitter{}, Namespace: testNamespace,
		},
		tracker: &controller.PolicyStatusTracker{Client: c, Namespace: testNamespace},
		alerts:  loki.NewClient(lokiURL, "", nil),
		cursors: &loki.ConfigMapStore{Client: c, Namespace: testNamespace},
		reader:  c,
		metrics: telemetry.NewMetrics(),
	}
}

func (w *worker) jobs(t *testing.T) []trawlv1alpha1.CaptureJob {
	t.Helper()
	var list trawlv1alpha1.CaptureJobList
	if err := w.cursors.Client.List(context.Background(), &list); err != nil {
		t.Fatalf("listing capture jobs: %v", err)
	}
	return list.Items
}

func TestPollingAlertsEvaluatesThemAndPersistsTheCursor(t *testing.T) {
	// The alert path end to end inside the worker: query the window, hand each
	// record to the policies, and write down where it got to. The cursor is the
	// half that is easy to leave out and impossible to notice missing until a
	// restart re-triggers everything it had already handled.
	at := time.Now().Add(-time.Minute)
	srv := serveAlerts(t, alertObservation("4125e22fe6fad350aa771423a45c643e", at))
	w := newTestWorker(t, srv.URL, armedTapAndPolicy()...)

	var cursor loki.Cursor
	if err := w.pollAlerts(context.Background(), &cursor); err != nil {
		t.Fatalf("polling alerts: %v", err)
	}

	if jobs := w.jobs(t); len(jobs) != 1 {
		t.Fatalf("got %d capture jobs, want 1 - the alert reached no policy", len(jobs))
	}
	if !cursor.Handled("4125e22fe6fad350aa771423a45c643e") {
		t.Error("the cursor did not record the record it handled")
	}

	var cm corev1.ConfigMap
	key := types.NamespacedName{Namespace: testNamespace, Name: loki.DefaultCursorConfigMap}
	if err := w.cursors.Client.Get(context.Background(), key, &cm); err != nil {
		t.Fatalf("the cursor was not persisted: %v", err)
	}
	if cm.Data["cursor.json"] == "" {
		t.Error("the persisted cursor is empty; a restart would re-read the whole lookback")
	}
}

func TestARecordTheOverlapRedeliversIsNotEvaluatedTwice(t *testing.T) {
	// The query deliberately overlaps, because the pipeline orders records by
	// the producer's clock and a late write can carry an older event time.
	// Suppression by identity is what keeps that from manufacturing a second
	// capture every poll.
	at := time.Now().Add(-time.Minute)
	obs := alertObservation("4125e22fe6fad350aa771423a45c643e", at)
	srv := serveAlerts(t, obs)
	w := newTestWorker(t, srv.URL, armedTapAndPolicy()...)
	ctx := context.Background()

	var cursor loki.Cursor
	for range 3 {
		if err := w.pollAlerts(ctx, &cursor); err != nil {
			t.Fatalf("polling alerts: %v", err)
		}
	}

	// Asserted on the counters rather than on the capture, deliberately. One
	// capture would also be the answer with no suppression at all, because the
	// deduplication key collapses the repeats downstream - so counting jobs
	// tests the wrong mechanism and passes either way.
	if got := events(t, w, telemetry.RecordAccepted); got != 1 {
		t.Errorf("accepted %v records, want 1 - the record was evaluated again", got)
	}
	if got := events(t, w, eventReplayed); got != 2 {
		t.Errorf("suppressed %v redeliveries, want 2", got)
	}
	if jobs := w.jobs(t); len(jobs) != 1 {
		t.Errorf("got %d capture jobs after three polls of one record, want 1", len(jobs))
	}
}

// events reads one trigger-event counter for the alert source.
func events(t *testing.T, w *worker, result string) float64 {
	t.Helper()
	return testutil.ToFloat64(
		w.metrics.TriggerEventsTotal.WithLabelValues(telemetry.TriggerSourceSuricataLoki, result))
}

func TestAFailedAlertQueryLeavesTheCursorWhereItWas(t *testing.T) {
	// Advancing over a window that was never read would turn a transient Loki
	// outage into permanently unexamined coverage - and nothing would ever say
	// so, because the records would simply never be queried again.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "loki is unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	w := newTestWorker(t, srv.URL, armedTapAndPolicy()...)

	before := time.Now().Add(-2 * time.Minute)
	cursor := loki.Cursor{}
	cursor.Advance(before, "earlier-record")

	if err := w.pollAlerts(context.Background(), &cursor); err == nil {
		t.Fatal("a failed alert query was reported as success")
	}

	if !cursor.Timestamp.Equal(before) {
		t.Errorf("cursor moved to %v, want it left at %v", cursor.Timestamp, before)
	}
	health := w.alertSourceHealth()
	if health.Connected {
		t.Error("the alert source is still reported connected after the query failed")
	}
	if health.Reason != status.ReasonSourceDisconnected {
		t.Errorf("reason = %q, want SourceDisconnected", health.Reason)
	}
}

func TestTheReplayWindowIsTheWidestArmedThresholdWindow(t *testing.T) {
	// The Hubble stream resumes far enough back to rebuild every armed
	// policy's rolling window. Short of that, a threshold that was one flow
	// from firing rebuilds from almost nothing and never fires - with no error
	// anywhere, which is the failure an operator cannot see.
	policies := []trawlv1alpha1.CapturePolicy{
		thresholdPolicy("narrow", true, 30*time.Second),
		thresholdPolicy("wide", true, 5*time.Minute),
		// Disarmed, and deliberately the widest. Nothing is waiting on its
		// window, and letting it hold the replay open would make arming free
		// and disarming ineffective.
		thresholdPolicy("disarmed", false, time.Hour),
	}

	if got, want := widestThresholdWindow(policies), 5*time.Minute; got != want {
		t.Errorf("replay window = %s, want %s", got, want)
	}
}

func TestAPolicyWithNoThresholdAsksForNoReplay(t *testing.T) {
	// A drop policy that fires on a single flow rebuilds nothing, so it must
	// not lengthen every reconnect's replay on everyone else's behalf.
	policies := []trawlv1alpha1.CapturePolicy{thresholdPolicy("single", true, 0)}

	if got := widestThresholdWindow(policies); got != 0 {
		t.Errorf("replay window = %s, want none", got)
	}
}

// thresholdPolicy is a Hubble drop policy, optionally with a rolling window.
func thresholdPolicy(name string, armed bool, window time.Duration) trawlv1alpha1.CapturePolicy {
	trigger := &trawlv1alpha1.HubbleDropTrigger{Reasons: []string{"POLICY_DENIED"}}
	if window > 0 {
		trigger.Threshold = &trawlv1alpha1.DropThreshold{
			Count: 5, Window: metav1.Duration{Duration: window},
		}
	}
	return trawlv1alpha1.CapturePolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace, Name: name, UID: types.UID(fmt.Sprintf("uid-%s", name)),
		},
		Spec: trawlv1alpha1.CapturePolicySpec{
			Armed: armed,
			Trigger: trawlv1alpha1.CapturePolicyTrigger{
				Type:       trawlv1alpha1.CaptureTriggerHubbleDrop,
				HubbleDrop: trigger,
			},
		},
	}
}
