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

package observation

import (
	"testing"
	"time"
)

func p32(v int32) *int32 { return &v }

func obsWithFlow(at time.Time, communityID, proto string, sIP string, sPort int32, dIP string, dPort int32) *Observation {
	return &Observation{
		EventTime:       at,
		ObservationType: TypeConnection,
		Flow: &Flow{
			CommunityID: communityID,
			Protocol:    proto,
			Source:      Endpoint{IP: sIP, Port: p32(sPort)},
			Destination: Endpoint{IP: dIP, Port: p32(dPort)},
		},
	}
}

func baseTime() time.Time { return time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC) }

func TestSharedCommunityIDIsAnExactMatch(t *testing.T) {
	// FR-011/FR-015. Both analyzers derived the ID independently from the same
	// packets, so agreement is evidence rather than inference.
	c := &Correlator{}
	id := "1:LQU9qZlK+B5F3KDmev6m5PMibrg="

	a := obsWithFlow(baseTime(), id, "tcp", "10.0.0.1", 1234, "10.0.0.2", 443)
	b := obsWithFlow(baseTime().Add(400*time.Millisecond), id, "tcp", "10.0.0.1", 1234, "10.0.0.2", 443)

	if got := c.Match(a, b); got != MatchExact {
		t.Errorf("match = %q, want %q", got, MatchExact)
	}
}

func TestExactMatchIgnoresDirectionAndTimeSkew(t *testing.T) {
	// Community ID is direction-independent by construction, and the analyzers'
	// clocks may differ. Neither should weaken an exact match.
	c := &Correlator{}
	id := "1:abcdefghijklmnop="

	a := obsWithFlow(baseTime(), id, "tcp", "10.0.0.1", 1234, "10.0.0.2", 443)
	b := obsWithFlow(baseTime().Add(-45*time.Second), id, "tcp", "10.0.0.2", 443, "10.0.0.1", 1234)

	if got := c.Match(a, b); got != MatchExact {
		t.Errorf("match = %q, want %q even with reversed direction and skew", got, MatchExact)
	}
}

func TestDifferingCommunityIDsAreNotAMatch(t *testing.T) {
	// Both analyzers computed an ID and they disagree. That is a positive
	// statement that these are different flows, so falling back to weaker
	// attribute matching would manufacture a pairing the stronger signal
	// already ruled out.
	c := &Correlator{}

	a := obsWithFlow(baseTime(), "1:aaa=", "tcp", "10.0.0.1", 1234, "10.0.0.2", 443)
	b := obsWithFlow(baseTime(), "1:bbb=", "tcp", "10.0.0.1", 1234, "10.0.0.2", 443)

	if got := c.Match(a, b); got != MatchNone {
		t.Errorf("match = %q, want %q; identical tuples must not override disagreeing Community IDs", got, MatchNone)
	}
}

func TestAttributeMatchWhenCommunityIDIsAbsent(t *testing.T) {
	// FR-011 says "whenever both analysis modes can derive one". When one
	// cannot, correlation must still work, and must say so.
	c := &Correlator{}

	a := obsWithFlow(baseTime(), "", "tcp", "10.0.0.1", 1234, "10.0.0.2", 443)
	b := obsWithFlow(baseTime().Add(500*time.Millisecond), "", "tcp", "10.0.0.1", 1234, "10.0.0.2", 443)

	if got := c.Match(a, b); got != MatchAttributeTime {
		t.Errorf("match = %q, want %q", got, MatchAttributeTime)
	}
}

func TestAttributeMatchNormalizesDirection(t *testing.T) {
	// Suricata reports the packet's direction, Zeek the connection's. An
	// analyst pivoting between them should not have to know which convention
	// produced the record in front of them.
	c := &Correlator{}

	a := obsWithFlow(baseTime(), "", "tcp", "10.0.0.1", 1234, "10.0.0.2", 443)
	b := obsWithFlow(baseTime(), "", "tcp", "10.0.0.2", 443, "10.0.0.1", 1234)

	if got := c.Match(a, b); got != MatchAttributeTime {
		t.Errorf("match = %q, want %q for a reversed tuple", got, MatchAttributeTime)
	}
}

func TestAttributeMatchIsBoundedInTime(t *testing.T) {
	// The window absorbs analyzer clock skew but must stay far shorter than a
	// plausible reconnect on the same ephemeral port. Otherwise two unrelated
	// connections become one piece of evidence.
	c := &Correlator{Window: 2 * time.Second}

	a := obsWithFlow(baseTime(), "", "tcp", "10.0.0.1", 1234, "10.0.0.2", 443)

	inside := obsWithFlow(baseTime().Add(1500*time.Millisecond), "", "tcp", "10.0.0.1", 1234, "10.0.0.2", 443)
	if got := c.Match(a, inside); got != MatchAttributeTime {
		t.Errorf("inside window: match = %q, want %q", got, MatchAttributeTime)
	}

	outside := obsWithFlow(baseTime().Add(10*time.Second), "", "tcp", "10.0.0.1", 1234, "10.0.0.2", 443)
	if got := c.Match(a, outside); got != MatchNone {
		t.Errorf("outside window: match = %q, want %q", got, MatchNone)
	}
}

func TestAttributeMatchRequiresTheSameProtocol(t *testing.T) {
	c := &Correlator{}

	a := obsWithFlow(baseTime(), "", "tcp", "10.0.0.1", 1234, "10.0.0.2", 443)
	b := obsWithFlow(baseTime(), "", "udp", "10.0.0.1", 1234, "10.0.0.2", 443)

	if got := c.Match(a, b); got != MatchNone {
		t.Errorf("match = %q across protocols, want %q", got, MatchNone)
	}
}

func TestAttributeMatchIsCaseInsensitiveOnProtocol(t *testing.T) {
	// Analyzers disagree on casing; that is not a semantic difference.
	c := &Correlator{}

	a := obsWithFlow(baseTime(), "", "TCP", "10.0.0.1", 1234, "10.0.0.2", 443)
	b := obsWithFlow(baseTime(), "", "tcp", "10.0.0.1", 1234, "10.0.0.2", 443)

	if got := c.Match(a, b); got != MatchAttributeTime {
		t.Errorf("match = %q, want %q", got, MatchAttributeTime)
	}
}

func TestDifferentPortsAreNotAMatch(t *testing.T) {
	c := &Correlator{}

	a := obsWithFlow(baseTime(), "", "tcp", "10.0.0.1", 1234, "10.0.0.2", 443)
	b := obsWithFlow(baseTime(), "", "tcp", "10.0.0.1", 9999, "10.0.0.2", 443)

	if got := c.Match(a, b); got != MatchNone {
		t.Errorf("match = %q for differing source ports, want %q", got, MatchNone)
	}
}

func TestObservationsWithoutFlowNeverMatch(t *testing.T) {
	// A certificate or file record has no tuple. Matching on anything else
	// would be guessing.
	c := &Correlator{}

	withFlow := obsWithFlow(baseTime(), "1:a=", "tcp", "10.0.0.1", 1234, "10.0.0.2", 443)
	noFlow := &Observation{EventTime: baseTime(), ObservationType: TypeCertificate}

	if got := c.Match(withFlow, noFlow); got != MatchNone {
		t.Errorf("match = %q, want %q", got, MatchNone)
	}
	if got := c.Match(noFlow, noFlow); got != MatchNone {
		t.Errorf("match = %q, want %q", got, MatchNone)
	}
}

func TestNilObservationsAreHandled(t *testing.T) {
	c := &Correlator{}
	a := obsWithFlow(baseTime(), "1:a=", "tcp", "10.0.0.1", 1234, "10.0.0.2", 443)

	if got := c.Match(a, nil); got != MatchNone {
		t.Errorf("match with nil = %q, want %q", got, MatchNone)
	}
	if got := c.Match(nil, nil); got != MatchNone {
		t.Errorf("match of two nils = %q, want %q", got, MatchNone)
	}
}

func TestCandidatesPrefersExactOverAttribute(t *testing.T) {
	// When a confident answer exists, weaker candidates must not dilute it.
	c := &Correlator{}
	id := "1:exact="

	subject := obsWithFlow(baseTime(), id, "tcp", "10.0.0.1", 1234, "10.0.0.2", 443)
	exact := obsWithFlow(baseTime(), id, "tcp", "10.0.0.1", 1234, "10.0.0.2", 443)
	attribute := obsWithFlow(baseTime(), "", "tcp", "10.0.0.1", 1234, "10.0.0.2", 443)

	kind, matches := c.Candidates(subject, []*Observation{exact, attribute})
	if kind != MatchExact {
		t.Errorf("kind = %q, want %q", kind, MatchExact)
	}
	if len(matches) != 1 || matches[0] != exact {
		t.Errorf("matches = %v, want only the exact record", matches)
	}
}

func TestSeveralRecordsSharingACommunityIDAreAllExact(t *testing.T) {
	// A connection, its DNS lookup, and an alert are all one flow. That is not
	// ambiguity, and collapsing it to one record would hide evidence.
	c := &Correlator{}
	id := "1:shared="

	subject := obsWithFlow(baseTime(), id, "tcp", "10.0.0.1", 1234, "10.0.0.2", 443)
	conn := obsWithFlow(baseTime(), id, "tcp", "10.0.0.1", 1234, "10.0.0.2", 443)
	alert := obsWithFlow(baseTime().Add(time.Second), id, "tcp", "10.0.0.1", 1234, "10.0.0.2", 443)

	kind, matches := c.Candidates(subject, []*Observation{conn, alert})
	if kind != MatchExact {
		t.Errorf("kind = %q, want %q", kind, MatchExact)
	}
	if len(matches) != 2 {
		t.Errorf("got %d matches, want both records", len(matches))
	}
}

func TestSeveralAttributeCandidatesAreAmbiguous(t *testing.T) {
	// Presenting one of several equally plausible candidates as "the" match
	// would be a fabricated conclusion. FR-015 requires the distinction be
	// visible to the analyst.
	c := &Correlator{}

	subject := obsWithFlow(baseTime(), "", "tcp", "10.0.0.1", 1234, "10.0.0.2", 443)
	first := obsWithFlow(baseTime().Add(100*time.Millisecond), "", "tcp", "10.0.0.1", 1234, "10.0.0.2", 443)
	second := obsWithFlow(baseTime().Add(200*time.Millisecond), "", "tcp", "10.0.0.1", 1234, "10.0.0.2", 443)

	kind, matches := c.Candidates(subject, []*Observation{first, second})
	if kind != MatchAmbiguous {
		t.Errorf("kind = %q, want %q", kind, MatchAmbiguous)
	}
	if len(matches) != 2 {
		t.Errorf("got %d candidates, want both retained for the analyst to judge", len(matches))
	}
}

func TestCandidatesExcludesTheSubjectItself(t *testing.T) {
	c := &Correlator{}
	subject := obsWithFlow(baseTime(), "1:a=", "tcp", "10.0.0.1", 1234, "10.0.0.2", 443)

	kind, matches := c.Candidates(subject, []*Observation{subject})
	if kind != MatchNone || len(matches) != 0 {
		t.Errorf("a record matched itself: kind=%q matches=%d", kind, len(matches))
	}
}

func TestCandidatesReturnsNoneForAnEmptyPool(t *testing.T) {
	c := &Correlator{}
	subject := obsWithFlow(baseTime(), "1:a=", "tcp", "10.0.0.1", 1234, "10.0.0.2", 443)

	if kind, matches := c.Candidates(subject, nil); kind != MatchNone || matches != nil {
		t.Errorf("kind=%q matches=%v, want none", kind, matches)
	}
}

func TestCrossAnalyzerPivotWorksInBothDirections(t *testing.T) {
	// SC-005 times pivots starting from each record direction, so the
	// classifier must be symmetric.
	c := &Correlator{}

	suricata := suricataNormalizer()
	alert, _, err := suricata.Normalize([]byte(eveAlert))
	if err != nil {
		t.Fatalf("normalizing alert: %v", err)
	}

	zeek := zeekNormalizer()
	conn, err := zeek.Normalize(ZeekConn, []byte(`{`+zeekFlowFields+`, "service":"ssl","conn_state":"SF"}`))
	if err != nil {
		t.Fatalf("normalizing conn: %v", err)
	}

	if got := c.Match(alert, conn); got != MatchExact {
		t.Errorf("alert -> conn = %q, want %q", got, MatchExact)
	}
	if got := c.Match(conn, alert); got != MatchExact {
		t.Errorf("conn -> alert = %q, want %q", got, MatchExact)
	}
}
