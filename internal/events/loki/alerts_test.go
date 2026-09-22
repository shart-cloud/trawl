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

package loki_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trawl.cloud/trawl/internal/events/loki"
	"trawl.cloud/trawl/internal/observation"
)

// serveFixture answers any query with the recorded response body.
//
// testdata/query_range_signature.json is a real query_range response captured
// from the cluster, with addresses and identifiers replaced by documentation
// values. Recording the shape rather than writing one by hand is deliberate:
// the decoder's job is to accept what Loki actually returns, and the previous
// attempt at this component was written against a Loki that had never carried
// an alert.
func serveFixture(t *testing.T, name string) *httptest.Server {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAlertsDecodesTheEnvelopeFromTheLogLine(t *testing.T) {
	// The pipeline promotes a bounded set of fields to labels and structured
	// metadata, but the log line keeps the whole envelope and is authoritative
	// (config/alloy/trawl-observations.alloy says so). Decoding the line rather
	// than reassembling the record from labels is what keeps the matcher
	// working on the same shape the sensor emitted.
	srv := serveFixture(t, "query_range_signature.json")
	client := loki.NewClient(srv.URL, "", srv.Client())

	got, err := client.Alerts(context.Background(), time.Now().Add(-time.Minute), time.Now())
	if err != nil {
		t.Fatalf("querying alerts: %v", err)
	}

	if len(got.Observations) != 1 {
		t.Fatalf("decoded %d observations, want 1", len(got.Observations))
	}
	obs := got.Observations[0]
	if obs.ObservationType != observation.TypeSignature {
		t.Errorf("observation type = %q, want %q", obs.ObservationType, observation.TypeSignature)
	}
	if obs.Source.Kind != observation.SourceSuricata {
		t.Errorf("source kind = %q, want %q", obs.Source.Kind, observation.SourceSuricata)
	}
	if obs.Details.Signature == nil {
		t.Fatal("the signature body did not survive decoding")
	}
	if obs.Details.Signature.Severity != 3 || obs.Details.Signature.RuleID != 2038968 {
		t.Errorf("severity/rule = %d/%d, want 3/2038968",
			obs.Details.Signature.Severity, obs.Details.Signature.RuleID)
	}
	if obs.Flow == nil || obs.Flow.Source.IP != "192.0.2.10" {
		t.Errorf("flow did not survive decoding: %+v", obs.Flow)
	}
}

// serveBody answers any query with this exact body and status.
func serveBody(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAMalformedRecordIsSkippedAndCountedNotFatal(t *testing.T) {
	// A record the decoder cannot read is quarantined with a count, per the
	// spec's edge case: malformed records "must not stop valid records from
	// being processed". One unreadable line between two alerts must not cost
	// the alerts.
	body := `{"status":"success","data":{"resultType":"streams","result":[{"stream":{},"values":[
	  ["1","{\"schema_version\":\"trawl.observation/v1alpha1\",\"id\":\"a\",\"observation_type\":\"signature\",\"source\":{\"kind\":\"Suricata\"},\"details\":{\"signature\":{\"rule_id\":1,\"severity\":2}}}"],
	  ["2","{this is not json"],
	  ["3","{\"schema_version\":\"trawl.observation/v1alpha1\",\"id\":\"b\",\"observation_type\":\"signature\",\"source\":{\"kind\":\"Suricata\"},\"details\":{\"signature\":{\"rule_id\":2,\"severity\":2}}}"]
	]}]}}`
	client := loki.NewClient(serveBody(t, http.StatusOK, body).URL, "", nil)

	got, err := client.Alerts(context.Background(), time.Now().Add(-time.Minute), time.Now())
	if err != nil {
		t.Fatalf("a malformed record made the whole query fail: %v", err)
	}

	if len(got.Observations) != 2 {
		t.Errorf("decoded %d observations, want the 2 valid ones", len(got.Observations))
	}
	if got.Malformed != 1 {
		t.Errorf("malformed count = %d, want 1", got.Malformed)
	}
	if len(got.Rows) != 3 {
		t.Fatalf("retained cursor facts for %d rows, want all 3 consumed rows", len(got.Rows))
	}
	malformed := got.Rows[1]
	if malformed.Observation != nil {
		t.Error("malformed row unexpectedly carries a decoded observation")
	}
	if !malformed.Timestamp.Equal(time.Unix(0, 2).UTC()) {
		t.Errorf("malformed row timestamp = %s, want Loki timestamp 2", malformed.Timestamp)
	}
	if malformed.ID == "" || strings.Contains(malformed.ID, "this is not json") {
		t.Errorf("malformed row cursor identity is absent or leaked payload: %q", malformed.ID)
	}
}

func TestARowWithoutAUsableLokiTimestampFailsThePage(t *testing.T) {
	// Without a stream timestamp there is no position the cursor can advance
	// to. Calling the row merely malformed and returning success would claim
	// the page was consumed while guaranteeing it is read again forever.
	body := `{"status":"success","data":{"resultType":"streams","result":[{"stream":{},"values":[
	  ["not-a-loki-timestamp","{this is not json"]
	]}]}}`
	client := loki.NewClient(serveBody(t, http.StatusOK, body).URL, "", nil)

	got, err := client.Alerts(context.Background(), time.Now().Add(-time.Minute), time.Now())
	if err == nil {
		t.Fatalf("row with unusable timestamp returned success and %+v", got)
	}
	if len(got.Rows) != 0 || len(got.Observations) != 0 {
		t.Errorf("failed page returned consumed data: %+v", got)
	}
}

func TestAQueryFailureIsReportedRatherThanReadAsNoAlerts(t *testing.T) {
	// Loki being unreachable and Loki holding no alerts both produce zero
	// records. Only one of them means the policies are unevaluated, so the
	// difference has to reach the caller - a silent empty result would let a
	// worker report itself healthy while triggering nothing.
	client := loki.NewClient(serveBody(t, http.StatusInternalServerError, "boom").URL, "", nil)

	got, err := client.Alerts(context.Background(), time.Now().Add(-time.Minute), time.Now())

	if err == nil {
		t.Fatalf("a 500 from Loki returned %d observations and no error", len(got.Observations))
	}
	if len(got.Observations) != 0 {
		t.Error("a failed query returned observations")
	}
}

func TestTheQueryIsBoundedAndAsksForTheContractLabels(t *testing.T) {
	// The bounds are what stop one poll becoming unbounded work on a busy
	// sensor. The label selector is the one the pipeline actually writes -
	// getting it wrong is how the previous attempt at this component would have
	// passed its tests while matching nothing in the real cluster.
	var got *url.URL
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL
		_, _ = w.Write([]byte(`{"status":"success","data":{"result":[]}}`))
	}))
	t.Cleanup(srv.Close)

	client := loki.NewClient(srv.URL, "", srv.Client())
	client.Limit = 250
	start := time.Date(2026, 9, 9, 21, 36, 25, 0, time.UTC)
	end := start.Add(time.Minute)

	if _, err := client.Alerts(context.Background(), start, end); err != nil {
		t.Fatalf("querying: %v", err)
	}

	q := got.Query()
	if q.Get("limit") != "250" {
		t.Errorf("limit = %q, want 250", q.Get("limit"))
	}
	if q.Get("start") != "1788989785000000000" {
		t.Errorf("start = %q, want the range start in nanoseconds", q.Get("start"))
	}
	if q.Get("direction") != "forward" {
		t.Errorf("direction = %q, want forward so a truncated page is the front of the window", q.Get("direction"))
	}
	for _, label := range []string{`service_name="trawl-observation"`, `observation_type="signature"`, `source_kind="Suricata"`} {
		if !strings.Contains(q.Get("query"), label) {
			t.Errorf("query %q does not select on %s", q.Get("query"), label)
		}
	}
}

func TestATruncatedPageIsReportedSoTheGapIsVisible(t *testing.T) {
	// Hitting the limit means records in the window were not returned. If that
	// were silent the cursor would advance past them and the alerts would never
	// be evaluated - lost coverage that looks exactly like quiet traffic.
	body := `{"status":"success","data":{"result":[{"stream":{},"values":[
	  ["1","{\"id\":\"a\"}"],["2","{\"id\":\"b\"}"]
	]}]}}`
	client := loki.NewClient(serveBody(t, http.StatusOK, body).URL, "", nil)
	client.Limit = 2

	got, err := client.Alerts(context.Background(), time.Now().Add(-time.Minute), time.Now())
	if err != nil {
		t.Fatalf("querying: %v", err)
	}

	if !got.Truncated {
		t.Error("a full page was not reported as truncated")
	}
}
