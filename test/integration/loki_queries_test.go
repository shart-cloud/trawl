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

package integration

import (
	"strings"
	"testing"
	"time"

	"trawl.cloud/trawl/internal/observation"
	fixtures "trawl.cloud/trawl/test/fixtures/observations"
	"trawl.cloud/trawl/test/integration/harness"
)

// These run against a real Loki because the properties they check are Loki's,
// not Trawl's: whether structured metadata is actually queryable, whether label
// selection behaves as the dashboards assume, and whether the schema and
// feature flags Trawl requires are really in effect. A mock would confirm only
// that the test's own assumptions are self-consistent.

// recentOffset shifts fixture timestamps into a window Loki will serve.
//
// The fixtures are anchored to a fixed calendar date so unit tests are
// reproducible. Loki, though, only queries its ingesters for recent data and
// has not yet flushed anything to the store during a short test, so a
// fourteen-hour-old record pushes successfully and then returns nothing.
//
// Shifting by a constant preserves the relative spacing the correlation tests
// depend on while putting the records where Loki will actually serve them. The
// alternative - configuring Loki to serve old data - would mean testing against
// a configuration no real deployment uses.
func recentOffset() time.Duration {
	return time.Since(fixtures.BaseTime) - 5*time.Minute
}

// pushSession normalizes a fixture and writes it to Loki the way Alloy would.
func pushSession(t *testing.T, loki *harness.Loki, session fixtures.Session) {
	t.Helper()

	offset := recentOffset()

	tap := &observation.Tap{Namespace: "trawl-system", Name: "fixture-tap", UID: "fixture-uid"}
	target := observation.Target{Node: "sensor-01", Interface: "enp5s0"}
	now := func() time.Time { return fixtures.BaseTime.Add(time.Minute) }

	suricata := &observation.SuricataNormalizer{Version: "8.0.6", Tap: tap, Target: target, Now: now}
	zeek := &observation.ZeekNormalizer{Version: "8.0.10", Tap: tap, Target: target, Now: now}

	var records []*observation.Observation
	for _, line := range session.SuricataEVE {
		obs, _, err := suricata.Normalize([]byte(line))
		if err != nil {
			t.Fatalf("normalizing EVE: %v", err)
		}
		if obs != nil {
			records = append(records, obs)
		}
	}
	for _, log := range session.ZeekLogs {
		obs, err := zeek.Normalize(observation.ZeekLogType(log.Type), []byte(log.Line))
		if err != nil {
			t.Fatalf("normalizing zeek %s: %v", log.Type, err)
		}
		records = append(records, obs)
	}

	// One stream per label combination, exactly as the Alloy config produces.
	// The rendering lives in the harness so this test and the e2e investigation
	// test cannot drift into asserting against different shapes.
	streams := harness.ObservationStreams(records, "homelab", offset)
	if err := loki.Push(t.Context(), streams); err != nil {
		t.Fatalf("pushing to Loki: %v", err)
	}
}

// fixtureRange spans the shifted window the records were written into.
func fixtureRange() (start, end time.Time) {
	anchor := fixtures.BaseTime.Add(recentOffset())
	return anchor.Add(-30 * time.Minute), anchor.Add(30 * time.Minute)
}

func TestLokiAcceptsTheStructuredMetadataTrawlDependsOn(t *testing.T) {
	// The whole label discipline rests on structured metadata being queryable.
	// If Loki were configured without it, Trawl would have to promote these to
	// labels and take the cardinality hit.
	loki := harness.RequireLoki(t)
	pushSession(t, loki, fixtures.TLSSessionWithAlert())

	start, end := fixtureRange()
	results, err := loki.Query(t.Context(),
		`{service_name="trawl-observation", cluster="homelab"} | community_id != ""`,
		start, end)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if harness.CountEntries(results) == 0 {
		t.Fatal("no records matched a structured-metadata filter; structured metadata is not queryable")
	}
}

func TestExactPivotByCommunityIDReturnsTheWholeFlow(t *testing.T) {
	// The SC-005 path, run against real Loki: one query, no tuple
	// reconstruction, every record in the flow.
	loki := harness.RequireLoki(t)
	session := fixtures.TLSSessionWithAlert()
	pushSession(t, loki, session)

	start, end := fixtureRange()
	results, err := loki.Query(t.Context(),
		`{service_name="trawl-observation", cluster="homelab"} | community_id = "`+session.CommunityID+`"`,
		start, end)
	if err != nil {
		t.Fatalf("query: %v", err)
	}

	if got := harness.CountEntries(results); got != session.ExactMatches {
		t.Errorf("exact pivot returned %d records, want %d", got, session.ExactMatches)
	}
}

func TestPivotSpansBothAnalyzers(t *testing.T) {
	// The point of the shared Community ID: one pivot crosses from Suricata's
	// alert to Zeek's protocol records.
	loki := harness.RequireLoki(t)
	session := fixtures.TLSSessionWithAlert()
	pushSession(t, loki, session)

	start, end := fixtureRange()
	results, err := loki.Query(t.Context(),
		`{service_name="trawl-observation", cluster="homelab"} | community_id = "`+session.CommunityID+`"`,
		start, end)
	if err != nil {
		t.Fatalf("query: %v", err)
	}

	kinds := map[string]bool{}
	for _, r := range results {
		kinds[r.Labels["source_kind"]] = true
	}
	if !kinds["Suricata"] || !kinds["Zeek"] {
		t.Errorf("pivot returned only %v; it must span both analyzers", kinds)
	}
}

func TestFilterByObservationTypeUsesALabel(t *testing.T) {
	// observation_type is an indexed label, so this filter selects streams
	// rather than scanning them. It is the cheapest and most common filter the
	// dashboards apply.
	loki := harness.RequireLoki(t)
	pushSession(t, loki, fixtures.TLSSessionWithAlert())

	start, end := fixtureRange()
	results, err := loki.Query(t.Context(),
		`{service_name="trawl-observation", cluster="homelab", observation_type="signature"}`,
		start, end)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if harness.CountEntries(results) != 1 {
		t.Errorf("got %d signature records, want 1", harness.CountEntries(results))
	}
	for _, r := range results {
		if r.Labels["observation_type"] != "signature" {
			t.Errorf("a non-signature record matched: %v", r.Labels)
		}
	}
}

func TestFilterBySeverityAndRuleID(t *testing.T) {
	// FR-013 requires searching by severity and rule identity. Both are
	// structured metadata, so this proves the filter works without them being
	// labels.
	loki := harness.RequireLoki(t)
	pushSession(t, loki, fixtures.TLSSessionWithAlert())

	start, end := fixtureRange()
	for _, query := range []string{
		`{service_name="trawl-observation", cluster="homelab", observation_type="signature"} | severity = "2"`,
		`{service_name="trawl-observation", cluster="homelab", observation_type="signature"} | rule_id = "2019401"`,
	} {
		results, err := loki.Query(t.Context(), query, start, end)
		if err != nil {
			t.Fatalf("query %q: %v", query, err)
		}
		if harness.CountEntries(results) == 0 {
			t.Errorf("query returned nothing: %s", query)
		}
	}
}

func TestApproximatePivotMatchesEitherDirection(t *testing.T) {
	// The analyzers disagree about which endpoint originated a flow, so a
	// one-directional query silently misses half the matches.
	loki := harness.RequireLoki(t)
	pushSession(t, loki, fixtures.SessionWithoutCommunityID())

	start, end := fixtureRange()
	query := `{service_name="trawl-observation", cluster="homelab"} | protocol = "tcp" | ` +
		`(source_ip = "10.1.1.5" and destination_ip = "10.1.1.9") or ` +
		`(source_ip = "10.1.1.9" and destination_ip = "10.1.1.5")`

	results, err := loki.Query(t.Context(), query, start, end)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if harness.CountEntries(results) < 2 {
		t.Errorf("approximate pivot returned %d records, want both sides of the session",
			harness.CountEntries(results))
	}
}

func TestFilterByTapAndTargetNode(t *testing.T) {
	// FR-013: an analyst narrows to one tap or one node when several are
	// running.
	loki := harness.RequireLoki(t)
	pushSession(t, loki, fixtures.TLSSessionWithAlert())

	start, end := fixtureRange()
	for _, query := range []string{
		`{service_name="trawl-observation", cluster="homelab"} | tap_uid = "fixture-uid"`,
		`{service_name="trawl-observation", cluster="homelab"} | target_node = "sensor-01"`,
	} {
		results, err := loki.Query(t.Context(), query, start, end)
		if err != nil {
			t.Fatalf("query %q: %v", query, err)
		}
		if harness.CountEntries(results) == 0 {
			t.Errorf("query returned nothing: %s", query)
		}
	}
}

func TestStoredRecordsCarryNoQueryStringToken(t *testing.T) {
	// End of the pipeline, which is what actually matters: the token must not
	// be recoverable from what Loki stored.
	loki := harness.RequireLoki(t)
	pushSession(t, loki, fixtures.HTTPSessionWithCredentialInQuery())

	start, end := fixtureRange()
	results, err := loki.Query(t.Context(),
		`{service_name="trawl-observation", cluster="homelab", observation_type="http"}`,
		start, end)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if harness.CountEntries(results) == 0 {
		t.Fatal("no HTTP records were stored")
	}

	for _, r := range results {
		for _, v := range r.Values {
			line := v[1]
			if strings.Contains(line, "s3cr3t-session-value") {
				t.Errorf("a stored record contains the session token: %s", line)
			}
			if strings.Contains(line, "token=") {
				t.Errorf("a stored record contains a query string: %s", line)
			}
		}
	}
}

func TestTimeRangeQueriesUseEventTime(t *testing.T) {
	// Records are indexed at the time the traffic happened. A range query that
	// excludes the event time must return nothing, or an investigation timeline
	// would be built on ingestion order instead.
	loki := harness.RequireLoki(t)
	pushSession(t, loki, fixtures.TLSSessionWithAlert())

	anchor := fixtures.BaseTime.Add(recentOffset())
	before := anchor.Add(-6 * time.Hour)
	results, err := loki.Query(t.Context(),
		`{service_name="trawl-observation", cluster="homelab"}`,
		before, before.Add(time.Hour))
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if harness.CountEntries(results) != 0 {
		t.Errorf("a range before the event time returned %d records", harness.CountEntries(results))
	}
}
