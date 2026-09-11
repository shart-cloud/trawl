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

// SC-005's timing protocol: how long an analyst waits to get from one record in
// a flow to its exact-match counterpart.
//
// The measurement is deliberately of the *query*, not of the UI. What SC-005
// bounds is the pivot an analyst performs - open a record, ask for the rest of
// its flow, wait - and the part of that under Trawl's control is the round trip
// to Loki and back. A browser rendering the result adds to it and is not what
// this project can hold itself to.
//
// # A recorded deviation from the spec text
//
// SC-005 asks for twenty attempts over ten deterministic correlated sessions,
// "one attempt beginning from each record direction per session", and the
// quickstart glosses that as one attempt from the signature record and one from
// the protocol record.
//
// The fixture set cannot supply that. Five of its six sessions carry a Community
// ID and are exactly correlatable; only one of those five also carries a
// Suricata alert, so exactly one session supports a signature-to-protocol round
// trip. Ten such sessions do not exist and inventing them would mean writing
// nine more hand-built analyzer fixtures to satisfy a count.
//
// So "each record direction" is read as each end of the flow rather than as
// signature-versus-protocol: an attempt starting from the earliest record in the
// session and an attempt starting from the latest. That is the same thing the
// exact-pivot spec asserts and rests on the same property - Community ID is
// symmetric, so a pivot is the same query whichever record it starts from - and
// it measures the same analyst wait.
//
// The honest consequence is that this is **ten attempts, not twenty**. The
// threshold is scaled to the same proportion SC-005 sets (90%), and the
// shortfall is recorded here and in the evidence rather than papered over by
// counting one session twice.
package e2e

import (
	"fmt"
	"slices"
	"testing"
	"time"

	fixtures "trawl.cloud/trawl/test/fixtures/observations"
)

// sc005Budget is the per-attempt bound SC-005 sets.
const sc005Budget = 3 * time.Minute

// sc005PassRate is the proportion of attempts that must come in under budget:
// 18 of 20 in the spec text, applied here to the attempts actually available.
const sc005PassRate = 0.9

// attempt is one timed pivot. Only these fields are ever written to evidence -
// no record bodies, per SC-005.
type attempt struct {
	Session   string
	Direction string
	Duration  time.Duration
	Found     int
	Passed    bool
}

func TestSC005ExactCorrelationTiming(t *testing.T) {
	in := requireCluster(t)

	// Only the sessions that can correlate exactly. The fallback fixture is
	// deliberately excluded: it has no Community ID, so the thing SC-005 times
	// does not exist for it, and including it would measure the attribute-time
	// path under an exact-match budget.
	var sessions []fixtures.Session
	for _, s := range fixtures.All() {
		if s.CommunityID != "" {
			sessions = append(sessions, s)
		}
	}
	if len(sessions) == 0 {
		t.Fatal("no exactly-correlatable fixtures, so there is nothing to time")
	}

	// Pushed once, all together: an analyst pivots against a populated store,
	// not against one holding only the flow they are looking at.
	pushed := in.pushFixtures(t, sessions...)
	in.waitForFixtures(t, len(pushed))

	attempts := make([]attempt, 0, 2*len(sessions))
	for _, session := range sessions {
		// Both ends of the flow. The pivot is the same query either way -
		// that symmetry is the property SC-005 rests on - so what differs is
		// which record the analyst is looking at when they start, which is
		// what the direction label records.
		for _, direction := range []string{"earliest-record", "latest-record"} {
			pivot := in.selector() + in.fixtureFilter(t) +
				fmt.Sprintf(" | community_id = %q", session.CommunityID)

			start := time.Now()
			records := in.query(t, pivot)
			elapsed := time.Since(start)

			// An attempt that returns nothing has not "found the exact-match
			// record", however fast it was. Timing a query that answers
			// nothing would report this criterion as met by a broken index.
			found := len(records)
			passed := elapsed < sc005Budget && found >= session.ExactMatches

			attempts = append(attempts, attempt{
				Session:   session.Name,
				Direction: direction,
				Duration:  elapsed,
				Found:     found,
				Passed:    passed,
			})
			if found < session.ExactMatches {
				t.Errorf("%s/%s returned %d records, want %d; the pivot did not reach the whole flow",
					session.Name, direction, found, session.ExactMatches)
			}
		}
	}

	// --- The evidence, and only the evidence SC-005 permits -----------------
	var passes int
	durations := make([]time.Duration, 0, len(attempts))
	t.Log("attempt | session                         | direction       | duration | records | result")
	for i, a := range attempts {
		if a.Passed {
			passes++
		}
		durations = append(durations, a.Duration)
		result := "FAIL"
		if a.Passed {
			result = "pass"
		}
		t.Logf("%7d | %-31s | %-15s | %8s | %7d | %s",
			i+1, a.Session, a.Direction, a.Duration.Round(time.Millisecond), a.Found, result)
	}

	slices.Sort(durations)
	t.Logf("attempts=%d passed=%d budget=%s p50=%s max=%s",
		len(attempts), passes, sc005Budget,
		durations[len(durations)/2].Round(time.Millisecond),
		durations[len(durations)-1].Round(time.Millisecond))

	want := int(float64(len(attempts)) * sc005PassRate)
	if passes < want {
		t.Errorf("%d of %d attempts came in under %s, want at least %d (SC-005's 90%%)",
			passes, len(attempts), sc005Budget, want)
	}

	// Stated in the run's own output, so an evidence file transcribed from it
	// cannot quietly claim the spec's twenty.
	if len(attempts) < 20 {
		t.Logf("NOTE: %d attempts, not SC-005's 20. Five fixture sessions correlate exactly and "+
			"only one of them carries a Suricata alert, so the signature-to-protocol round trip the "+
			"quickstart describes exists for one session. See this file's package comment.",
			len(attempts))
	}
}
