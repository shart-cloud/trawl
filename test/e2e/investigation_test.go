//go:build investigation

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

// The end-to-end investigation test (T056).
//
// This is the only test that exercises the path an analyst actually uses: a
// deployed sensor reading a real interface, a deployed event worker reading the
// Hubble stream, the deployed Alloy pipeline, and the cluster's shared Loki. It
// is built behind its own tag because it needs all of that, and it runs against
// the shared monitoring Loki rather than a throwaway one on purpose - what it
// measures is a property of the deployed ingestion path, and a private Loki
// would measure a pipeline nobody uses.
//
// Sharing Loki means these records sit alongside everyone else's. Every fixture
// this test writes is stamped with a tap name unique to the run, and every
// query over fixture data filters on it, so a concurrent run cannot be mistaken
// for this one's evidence.
//
//	go test -tags=investigation ./test/e2e/ -v
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"trawl.cloud/trawl/internal/observation"
	fixtures "trawl.cloud/trawl/test/fixtures/observations"
	"trawl.cloud/trawl/test/integration/harness"
)

const (
	// searchabilityBudget is SC-004: at least 95% of valid observations become
	// searchable within thirty seconds of being emitted by an analyzer.
	searchabilityBudget = 30 * time.Second

	// searchabilityTarget is the proportion SC-004 requires inside that budget.
	searchabilityTarget = 0.95

	// fixtureAge places pushed fixtures far enough in the past that Loki serves
	// them immediately, and near enough that a short query range finds them.
	fixtureAge = 2 * time.Minute
)

// investigation holds the cluster-backed environment the specs share.
type investigation struct {
	loki    *harness.Loki
	cluster string
	runID   string
	skip    string
}

var (
	envOnce sync.Once
	env     investigation
)

// requireCluster attaches to the deployed Loki, skipping when there is none.
//
// A missing cluster is a skip rather than a failure: this test is meaningful
// only against a running Trawl, and turning its absence into a red build would
// train people to ignore it.
func requireCluster(t *testing.T) *investigation {
	t.Helper()
	envOnce.Do(setupInvestigation)
	if env.skip != "" {
		t.Skip(env.skip)
	}
	return &env
}

func setupInvestigation() {
	env.cluster = envOr("TRAWL_CLUSTER_ID", "homelab")
	env.runID = fmt.Sprintf("%d", time.Now().UnixNano())

	if url := os.Getenv("TRAWL_E2E_LOKI"); url != "" {
		env.loki = harness.AttachLoki(url)
		return
	}

	url, err := portForwardLoki()
	if err != nil {
		env.skip = fmt.Sprintf("no deployed Loki to investigate against: %v; "+
			"set TRAWL_E2E_LOKI to address one directly", err)
		return
	}
	env.loki = harness.AttachLoki(url)
}

// portForwardLoki opens a tunnel to the cluster's Loki for the whole run.
//
// The forward is deliberately not torn down per test: every spec in this file
// shares it, and Go gives a package-level fixture no cleanup hook. The process
// dies with the test binary.
func portForwardLoki() (string, error) {
	const localPort = 31000
	// #nosec G204 -- every argument is a constant of this file; nothing here
	// comes from the environment or from evidence.
	cmd := exec.Command("kubectl", "port-forward", "-n", "monitoring",
		"svc/loki", fmt.Sprintf("%d:3100", localPort))
	cmd.Stdout, cmd.Stderr = nil, nil
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("starting kubectl port-forward: %w", err)
	}

	url := fmt.Sprintf("http://127.0.0.1:%d", localPort)
	loki := harness.AttachLoki(url)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		now := time.Now()
		if _, err := loki.Query(context.Background(), `{service_name="trawl-observation"}`,
			now.Add(-time.Minute), now); err == nil {
			return url, nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	return "", fmt.Errorf("Loki did not answer on %s within 30s", url)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// --- Talking to the deployed pipeline ---------------------------------------

// selector is the stream selector every investigation query starts from.
//
// The order is the reviewed one: the four indexed labels first, structured
// metadata only afterwards. A query that starts from a metadata predicate makes
// Loki scan every stream in the range, which on a shared Loki is an outage for
// whoever else is using it.
func (in *investigation) selector(extra ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `{service_name="trawl-observation", cluster=%q`, in.cluster)
	for _, e := range extra {
		b.WriteString(", " + e)
	}
	b.WriteString("}")
	return b.String()
}

// fixtureFilter narrows a query to the records this spec pushed.
func (in *investigation) fixtureFilter(t *testing.T) string {
	return fmt.Sprintf(` | tap_name = %q`, in.tapName(t))
}

// tapName scopes fixtures to one spec of one run.
//
// The run alone is not enough. Every spec in this file pushes into the same
// shared Loki, so a tap name shared across them would let one spec's fixtures
// be counted as another's - which is not a hypothetical: it made the subtype
// counts wrong and made the fallback fixture appear to carry Community IDs it
// had never been given.
func (in *investigation) tapName(t *testing.T) string {
	return "e2e-" + in.runID + "-" + strings.Map(func(r rune) rune {
		if r == '/' || r == ' ' {
			return '-'
		}
		return r
	}, t.Name())
}

// query runs a LogQL query over the recent window and decodes the envelopes.
func (in *investigation) query(t *testing.T, q string) []map[string]any {
	t.Helper()
	now := time.Now()
	results, err := in.loki.Query(t.Context(), q, now.Add(-15*time.Minute), now)
	if err != nil {
		t.Fatalf("querying %s: %v", q, err)
	}

	var records []map[string]any
	for _, r := range results {
		for _, v := range r.Values {
			var doc map[string]any
			if err := json.Unmarshal([]byte(v[1]), &doc); err != nil {
				t.Errorf("stored record is not JSON: %v", err)
				continue
			}
			records = append(records, doc)
		}
	}
	return records
}

// pushFixtures normalizes a session with the real normalizers and writes it the
// way Alloy would.
//
// The fixtures are raw analyzer output rather than pre-built envelopes, so this
// exercises normalization too. An envelope fixture would pass even if the
// normalizers were broken, which is the failure this whole file exists to
// catch.
func (in *investigation) pushFixtures(t *testing.T, sessions ...fixtures.Session) []*observation.Observation {
	t.Helper()

	tap := &observation.Tap{Namespace: "trawl-system", Name: in.tapName(t), UID: in.runID}
	target := observation.Target{Node: "e2e", Interface: "e2e0"}
	now := func() time.Time { return fixtures.BaseTime.Add(time.Minute) }

	suricata := &observation.SuricataNormalizer{Version: "8.0.6", Tap: tap, Target: target, Now: now}
	zeek := &observation.ZeekNormalizer{Version: "8.0.10", Tap: tap, Target: target, Now: now}

	var records []*observation.Observation
	for _, session := range sessions {
		for _, line := range session.SuricataEVE {
			obs, _, err := suricata.Normalize([]byte(line))
			if err != nil {
				t.Fatalf("normalizing EVE for %s: %v", session.Name, err)
			}
			if obs != nil {
				records = append(records, obs)
			}
		}
		for _, log := range session.ZeekLogs {
			obs, err := zeek.Normalize(observation.ZeekLogType(log.Type), []byte(log.Line))
			if err != nil {
				t.Fatalf("normalizing zeek %s for %s: %v", log.Type, session.Name, err)
			}
			records = append(records, obs)
		}
	}

	offset := time.Since(fixtures.BaseTime) - fixtureAge
	if err := in.loki.Push(t.Context(),
		harness.ObservationStreams(records, in.cluster, offset)); err != nil {
		t.Fatalf("pushing fixtures: %v", err)
	}
	return records
}

// waitForFixtures blocks until the run's pushed records are queryable.
func (in *investigation) waitForFixtures(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if got := len(in.query(t, in.selector()+in.fixtureFilter(t))); got >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d pushed records became queryable within 30s",
				len(in.query(t, in.selector()+in.fixtureFilter(t))), want)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func recordString(doc map[string]any, path ...string) string {
	var cur any = doc
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = m[p]
	}
	s, _ := cur.(string)
	return s
}

// --- The investigation ------------------------------------------------------

func TestOverviewShowsObservationsAndNothingElse(t *testing.T) {
	// The overview an analyst opens first. Trawl's promise is that it is built
	// entirely from observations: structured records about traffic, never the
	// traffic itself. Packet content belongs to CaptureJob, under its own
	// authorization and retention boundary, and a payload that leaked into the
	// observation stream would sit in a shared Loki with neither.
	in := requireCluster(t)

	// Sampled per source rather than with one query, because a single query
	// fills its entry limit with whichever source is noisiest - here Hubble, by
	// two orders of magnitude - and a defect confined to Zeek's records would
	// never be sampled at all.
	records := in.liveRecords(t)
	if len(records) == 0 {
		t.Fatal("the deployed pipeline has produced no observations in the last 15 minutes; " +
			"there is no investigation to run")
	}

	schema, err := observation.Schema()
	if err != nil {
		t.Fatalf("compiling the observation schema: %v", err)
	}

	// Validate the stored document, not a struct decoded from it. Decoding into
	// observation.Observation would silently drop any field the envelope does
	// not declare, which is exactly the kind of drift this asserts against.
	invalid := 0
	for _, doc := range records {
		if err := schema.Validate(doc); err != nil {
			if invalid < 3 {
				t.Errorf("a stored %s record from %s does not satisfy the schema: %v",
					recordString(doc, "observation_type"), recordString(doc, "source", "kind"), err)
			}
			invalid++
		}
	}
	if invalid > 3 {
		t.Errorf("%d of %d stored records do not satisfy the schema", invalid, len(records))
	}

	// A payload-shaped key anywhere in a stored record, at any depth. The
	// schema forbids these at the top level; this catches one that arrived
	// nested inside details, where a future normalizer could put it.
	for _, doc := range records {
		if key := payloadShapedKey(doc); key != "" {
			t.Fatalf("a stored %s record carries a %q field; observations must not hold traffic content",
				recordString(doc, "observation_type"), key)
		}
	}

	if invalid == 0 {
		t.Logf("overview: %d observations in the last 15 minutes, all schema-valid", len(records))
	}
}

// payloadShapedKey reports the first key that would carry traffic content.
func payloadShapedKey(v any) string {
	forbidden := map[string]bool{
		"payload": true, "body": true, "headers": true, "packet": true,
		"raw_packet": true, "raw": true, "request_body": true, "response_body": true,
	}
	switch t := v.(type) {
	case map[string]any:
		for _, k := range slices.Sorted(maps.Keys(t)) {
			if forbidden[k] {
				return k
			}
			if found := payloadShapedKey(t[k]); found != "" {
				return found
			}
		}
	case []any:
		for _, e := range t {
			if found := payloadShapedKey(e); found != "" {
				return found
			}
		}
	}
	return ""
}

func TestExactPivotReachesTheWholeFlowFromEitherEnd(t *testing.T) {
	// SC-005, the central claim: from any record in a flow, one query returns
	// every other record in that flow, with no tuple reconstruction by hand.
	//
	// Both directions are asserted because they fail differently. Suricata
	// stamps Community ID on every EVE event, so a pivot that starts at an
	// alert works even when Zeek's side is broken; Zeek only carries it on
	// conn.log unless the community-id-all overlay is loaded. A test that
	// pivoted one way would have passed throughout the period when the reverse
	// pivot reached the connection record and stopped.
	in := requireCluster(t)
	session := fixtures.TLSSessionWithAlert()
	pushed := in.pushFixtures(t, session)
	in.waitForFixtures(t, len(pushed))

	pivot := in.selector() + in.fixtureFilter(t) +
		fmt.Sprintf(" | community_id = %q", session.CommunityID)

	records := in.query(t, pivot)
	if len(records) != session.ExactMatches {
		t.Fatalf("the exact pivot returned %d records, want %d", len(records), session.ExactMatches)
	}

	kinds := map[string]bool{}
	types := map[string]bool{}
	for _, doc := range records {
		kinds[recordString(doc, "source", "kind")] = true
		types[recordString(doc, "observation_type")] = true
	}
	for _, want := range []string{"Suricata", "Zeek"} {
		if !kinds[want] {
			t.Errorf("the pivot returned no %s record; it did not cross both analyzers", want)
		}
	}

	// Starting from the alert and starting from a protocol record are the two
	// directions. Both are the same query because Community ID is symmetric -
	// which is the property being asserted.
	if !types["signature"] {
		t.Error("the pivot did not reach Suricata's alert")
	}
	if len(types) < 2 {
		t.Error("the pivot reached only one kind of record; it did not leave the record it started from")
	}

	// And the correlator agrees with Loki about why these are the same flow.
	c := &observation.Correlator{}
	var signature, protocol *observation.Observation
	for _, obs := range pushed {
		if obs.ObservationType == observation.TypeSignature {
			signature = obs
		} else if obs.Flow != nil && obs.Flow.CommunityID == session.CommunityID {
			protocol = obs
		}
	}
	if signature == nil || protocol == nil {
		t.Fatal("the fixture did not produce both a signature and a protocol record")
	}
	if got := c.Match(signature, protocol); got != observation.MatchExact {
		t.Errorf("correlating the alert with the protocol record gave %q, want %q",
			got, observation.MatchExact)
	}
	if got := c.Match(protocol, signature); got != observation.MatchExact {
		t.Errorf("correlating in reverse gave %q, want %q", got, observation.MatchExact)
	}

	t.Logf("exact pivot: %d records across %d analyzers and %d subtypes",
		len(records), len(kinds), len(types))
}

func TestFallbackPivotWhenNoCommunityIDIsAvailable(t *testing.T) {
	// Not every record carries a Community ID. When one does not, the pivot
	// falls back to a normalized endpoint pair, the protocol, and a bounded
	// time window - and it must say that is what it did. An approximate match
	// presented as an exact one is worse than no match: it is a claim about
	// evidence that the evidence does not support.
	in := requireCluster(t)
	session := fixtures.SessionWithoutCommunityID()
	pushed := in.pushFixtures(t, session)
	in.waitForFixtures(t, len(pushed))

	// The exact pivot must find nothing. If it found something, these records
	// carry a Community ID and the fixture is no longer exercising the fallback.
	exact := in.query(t, in.selector()+in.fixtureFilter(t)+` | community_id != ""`)
	if len(exact) != 0 {
		t.Fatalf("the fallback fixture produced %d records carrying a Community ID; "+
			"it is no longer testing the fallback", len(exact))
	}

	// The fallback query: the same stream selector, endpoints as structured
	// metadata. Derived from the records rather than written here, so a change
	// in the fixture cannot leave this asserting against addresses it no longer
	// uses.
	var subject *observation.Observation
	for _, obs := range pushed {
		if obs.Flow != nil && obs.Flow.Source.IP != "" {
			subject = obs
			break
		}
	}
	if subject == nil {
		t.Fatal("the fallback fixture produced no record with endpoints to pivot on")
	}

	fallback := in.selector() + in.fixtureFilter(t) +
		fmt.Sprintf(" | source_ip = %q | destination_ip = %q",
			subject.Flow.Source.IP, subject.Flow.Destination.IP)
	records := in.query(t, fallback)
	if len(records) < 2 {
		t.Fatalf("the fallback pivot returned %d records; it did not reach beyond the one it started from",
			len(records))
	}

	// The classification is the part that must not be overstated.
	c := &observation.Correlator{}
	var partner *observation.Observation
	for _, obs := range pushed {
		if obs != subject && obs.Flow != nil {
			partner = obs
			break
		}
	}
	if partner == nil {
		t.Fatal("the fallback fixture produced only one record with a flow")
	}
	got := c.Match(subject, partner)
	if got == observation.MatchExact {
		t.Errorf("correlation reported %q for records with no Community ID; "+
			"an approximate match must never be presented as an exact one", got)
	}
	if got != observation.MatchAttributeTime && got != observation.MatchAmbiguous {
		t.Errorf("correlation reported %q, want %q or %q",
			got, observation.MatchAttributeTime, observation.MatchAmbiguous)
	}

	t.Logf("fallback pivot: %d records, classified %q", len(records), got)
}

func TestEveryProtocolSubtypeIsPresentAndFilterable(t *testing.T) {
	// An analyst narrows an investigation by subtype. A subtype that the
	// normalizers produce but a label filter cannot select is invisible in
	// practice, however well it is stored.
	in := requireCluster(t)
	pushed := in.pushFixtures(t, fixtures.All()...)
	in.waitForFixtures(t, len(pushed))

	want := map[string]int{}
	for _, obs := range pushed {
		want[string(obs.ObservationType)]++
	}
	if len(want) < 2 {
		t.Fatalf("the fixtures produced only %d subtype(s); this asserts nothing", len(want))
	}

	types := slices.Sorted(maps.Keys(want))

	for _, subtype := range types {
		q := in.selector(fmt.Sprintf("observation_type=%q", subtype)) + in.fixtureFilter(t)
		got := len(in.query(t, q))
		if got != want[subtype] {
			t.Errorf("filtering on observation_type=%q returned %d records, want %d",
				subtype, got, want[subtype])
		}
	}
	t.Logf("subtypes: %s", strings.Join(types, ", "))

	// The certificate caveat, asserted rather than worked around.
	//
	// Zeek's X509::Info has no uid and no conn_id: a certificate is reported as
	// an object the handshake referenced, not as an event on a flow. So a
	// certificate record can never be correlated by Community ID or by
	// endpoint, and the only route from a flow to it is the fingerprint carried
	// in ssl.log's cert_chain_fps. The correct behaviour is to report no match,
	// and the temptation this guards against is inventing a flow to make the
	// pivot look complete.
	flowless, withFlow := 0, 0
	var anchor *observation.Observation
	for _, obs := range pushed {
		if obs.Flow == nil {
			flowless++
		} else {
			withFlow++
			if anchor == nil {
				anchor = obs
			}
		}
	}
	if flowless == 0 {
		t.Fatal("no fixture produced a flowless record; the certificate caveat is untested")
	}

	c := &observation.Correlator{}
	for _, obs := range pushed {
		if obs.Flow != nil {
			continue
		}
		if got := c.Match(anchor, obs); got != observation.MatchNone {
			t.Errorf("a flowless %s record correlated as %q; it carries no flow to match on",
				obs.ObservationType, got)
		}
	}
	t.Logf("flowless records: %d of %d carry no flow and correctly report no match",
		flowless, flowless+withFlow)
}

func TestHubbleFlowsProvideWorkloadContext(t *testing.T) {
	// The context an analyst needs that packets alone cannot give: which
	// workload was at each end. Zeek and Suricata see addresses; on a cluster
	// those are ephemeral pod IPs that mean nothing an hour later. The event
	// worker's cluster_flow records are what turn an address into a namespace
	// and a workload name.
	//
	// This runs against live records rather than fixtures, because the property
	// being checked is that the deployed worker is connected and its output is
	// reaching Loki - which is exactly what silently was not true until the
	// Alloy pipeline was taught to collect it.
	in := requireCluster(t)

	records := in.query(t, in.selector(`source_kind="Hubble"`))
	if len(records) == 0 {
		t.Fatal("no Hubble observations in the last 15 minutes; the event worker's records " +
			"are not reaching Loki, so no investigation has cluster context")
	}

	attributed := 0
	for _, doc := range records {
		if recordString(doc, "observation_type") != "cluster_flow" {
			t.Errorf("a Hubble record has observation_type %q, want cluster_flow",
				recordString(doc, "observation_type"))
		}
		src := recordString(doc, "flow", "source", "workload")
		dst := recordString(doc, "flow", "destination", "workload")
		if src != "" || dst != "" {
			attributed++
		}
	}

	// Not every flow has a workload at both ends - traffic to an address
	// outside the cluster has none, and that is correct rather than missing.
	// What would be wrong is none of them having one.
	if attributed == 0 {
		t.Errorf("none of %d cluster_flow records carry workload attribution; "+
			"they add no context an address does not already give", len(records))
	}
	t.Logf("hubble: %d cluster_flow records, %d with workload attribution", len(records), attributed)
}

func TestObservationsBecomeSearchableWithinThirtySeconds(t *testing.T) {
	// SC-004: at least 95% of valid observations become searchable within
	// thirty seconds of being emitted by an analyzer.
	//
	// "Emitted by an analyzer" is the clock that matters, and it is observed_at
	// - the moment the sensor read the record - not event_time. The difference
	// is not pedantry. A Zeek conn record's event_time is when the connection
	// started, and the record cannot exist until the connection ends, so
	// measuring from event_time would report a minute of latency for a
	// well-behaved pipeline and would be reporting the duration of the traffic.
	// Measured that way against this cluster, Zeek's records show a median of
	// roughly twelve seconds for connections and twenty for DNS, none of which
	// is time Trawl controls.
	//
	// The measurement is an upper bound: a record is credited with the latency
	// to the poll that first returned it, so the poll interval is included and
	// the true figure is lower.
	in := requireCluster(t)

	// Traffic of our own, so the measurement does not depend on the cluster
	// happening to be busy. A DNS query for a name that cannot resolve is the
	// cheapest observable thing to produce and leaves nothing behind.
	//
	// It runs in the background because generating it means scheduling a pod
	// and waiting for an image, which takes tens of seconds. Doing that between
	// the warm-up and the first poll would stall polling, and every record that
	// arrived during the stall would be credited with the whole of it - which
	// is exactly the shape of a pipeline problem, and would be a fiction.
	marker := "trawle2e" + in.runID
	trafficDone := make(chan struct{})
	go func() {
		defer close(trafficDone)
		generateTraffic(t, in.runID, marker)
	}()
	defer func() { <-trafficDone }()

	// Warm-up. Everything already in Loki when polling starts would be credited
	// with the latency to the first poll, which reflects when this test began
	// rather than when the record became searchable.
	warm := map[string]bool{}
	for _, doc := range in.liveRecords(t) {
		warm[recordString(doc, "id")] = true
	}
	t.Logf("warm-up: %d records already searchable, excluded from the measurement", len(warm))

	type sample struct {
		latency time.Duration
		kind    string
		subtype string
	}
	samples := map[string]sample{}

	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		now := time.Now()
		for _, doc := range in.liveRecords(t) {
			id := recordString(doc, "id")
			if id == "" || warm[id] || samples[id].latency != 0 {
				continue
			}
			observedAt, err := time.Parse(time.RFC3339Nano, recordString(doc, "observed_at"))
			if err != nil {
				t.Errorf("a stored record has an unparseable observed_at: %v", err)
				continue
			}
			samples[id] = sample{
				latency: now.Sub(observedAt),
				kind:    recordString(doc, "source", "kind"),
				subtype: recordString(doc, "observation_type"),
			}
		}
		if len(samples) > 200 && time.Now().After(deadline.Add(-60*time.Second)) {
			break
		}
		time.Sleep(time.Second)
	}

	if len(samples) == 0 {
		t.Fatal("no observation became searchable during the measurement window; " +
			"either the pipeline has stopped or nothing is being observed")
	}

	latencies := make([]time.Duration, 0, len(samples))
	byKind := map[string][]time.Duration{}
	within := 0
	for _, s := range samples {
		latencies = append(latencies, s.latency)
		byKind[s.kind+"/"+s.subtype] = append(byKind[s.kind+"/"+s.subtype], s.latency)
		if s.latency <= searchabilityBudget {
			within++
		}
	}
	slices.Sort(latencies)

	proportion := float64(within) / float64(len(latencies))
	p95 := percentile(latencies, 0.95)

	if proportion < searchabilityTarget {
		t.Errorf("only %.2f%% of %d observations became searchable within %s; SC-004 requires %.0f%%",
			proportion*100, len(latencies), searchabilityBudget, searchabilityTarget*100)
	}
	if p95 > searchabilityBudget {
		t.Errorf("95th percentile searchability was %s, over the %s budget", p95, searchabilityBudget)
	}

	// The marker confirms the measurement covered traffic this test caused, not
	// only whatever the cluster was doing anyway. It is not itself an assertion
	// about latency: which subtype a DNS query produces, and when, is Zeek's
	// decision.
	if found := in.query(t, in.selector()+fmt.Sprintf(" |= %q", marker)); len(found) == 0 {
		t.Logf("note: the generated DNS query for %s was not observed within the window; "+
			"the measurement covers ambient traffic only", marker)
	} else {
		t.Logf("generated traffic observed: %d records matching %s", len(found), marker)
	}

	writeSearchabilityEvidence(t, latencies, byKind, proportion)
}

// liveRecords returns the deployed pipeline's recent output.
func (in *investigation) liveRecords(t *testing.T) []map[string]any {
	t.Helper()
	kinds := []string{"Zeek", "Suricata", "Hubble"}
	all := make([]map[string]any, 0, len(kinds)*256)
	// One query per source kind. A single query would fill its entry limit with
	// whichever source is noisiest - on this cluster, Hubble by two orders of
	// magnitude - and the quieter sources would never be sampled at all.
	for _, kind := range kinds {
		all = append(all, in.query(t, in.selector(fmt.Sprintf("source_kind=%q", kind)))...)
	}
	return all
}

func percentile(sorted []time.Duration, q float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := int(q * float64(len(sorted)))
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

// generateTraffic produces one observable exchange and returns its marker.
//
// A DNS lookup for a name under .invalid cannot resolve anywhere, which makes
// it safe to emit and unambiguous to find: the marker appears in the query name
// and nowhere else. The pod runs under the restricted Pod Security standard
// because the cluster enforces it.
func generateTraffic(t *testing.T, runID, marker string) {
	name := marker + ".trawl-e2e.invalid"
	overrides := fmt.Sprintf(`{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":65534,`+
		`"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"probe",`+
		`"image":%q,"securityContext":{"allowPrivilegeEscalation":false,`+
		`"capabilities":{"drop":["ALL"]}},"command":["sh","-c","nslookup %s || true"]}]}}`,
		trafficImage, name)

	// #nosec G204 -- runID is this process's start time in nanoseconds and the
	// image is a constant; no argument derives from the environment or from
	// observed traffic.
	cmd := exec.Command("kubectl", "run", "trawl-e2e-probe-"+runID,
		"-n", "default", "--restart=Never", "--rm", "--attach=true", "--quiet",
		"--image="+trafficImage, "--overrides="+overrides)
	if out, err := cmd.CombinedOutput(); err != nil {
		// Traffic generation is a convenience, not the measurement. The cluster
		// is never idle, so ambient observations still give SC-004 a sample.
		t.Logf("could not generate traffic (%v); measuring ambient observations only: %s",
			err, strings.TrimSpace(string(out)))
	}
}

// trafficImage is pinned like every other image the tests run.
const trafficImage = "docker.io/library/busybox:1.37"

// writeSearchabilityEvidence records the measurement for the task list.
//
// Only aggregates are written. A per-record file would carry addresses and
// query names from live traffic into the repository, which is the kind of
// content observations exist to avoid storing.
func writeSearchabilityEvidence(t *testing.T, sorted []time.Duration,
	byKind map[string][]time.Duration, proportion float64) {
	t.Helper()

	dir := filepath.Join("results")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Errorf("creating results directory: %v", err)
		return
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# SC-004 searchability\n\n")
	fmt.Fprintf(&b, "Measured %s by `TestObservationsBecomeSearchableWithinThirtySeconds`\n",
		time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "against the deployed pipeline. Latency is from `observed_at` - when the\n")
	fmt.Fprintf(&b, "sensor read the analyzer's record - to the first query that returned it,\n")
	fmt.Fprintf(&b, "so each figure includes the one-second poll interval and is an upper bound.\n\n")
	fmt.Fprintf(&b, "Budget: 95%% within %s.\n\n", searchabilityBudget)
	fmt.Fprintf(&b, "| source / subtype | n | p50 | p95 | max |\n")
	fmt.Fprintf(&b, "|---|---:|---:|---:|---:|\n")

	for _, k := range slices.Sorted(maps.Keys(byKind)) {
		v := byKind[k]
		slices.Sort(v)
		fmt.Fprintf(&b, "| %s | %d | %s | %s | %s |\n", k, len(v),
			percentile(v, 0.5).Round(10*time.Millisecond),
			percentile(v, 0.95).Round(10*time.Millisecond),
			v[len(v)-1].Round(10*time.Millisecond))
	}
	fmt.Fprintf(&b, "| **all** | %d | %s | %s | %s |\n", len(sorted),
		percentile(sorted, 0.5).Round(10*time.Millisecond),
		percentile(sorted, 0.95).Round(10*time.Millisecond),
		sorted[len(sorted)-1].Round(10*time.Millisecond))
	fmt.Fprintf(&b, "\nWithin budget: %.2f%% of %d observations.\n", proportion*100, len(sorted))

	path := filepath.Join(dir, "sc-004-searchability.md")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Errorf("writing evidence: %v", err)
		return
	}
	t.Logf("evidence written to test/e2e/%s", path)
}
