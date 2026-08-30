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
	"strings"
	"time"
)

// MatchKind classifies how confidently two observations describe the same flow.
//
// FR-015 requires investigation results to distinguish these. The distinction
// is not cosmetic: an analyst acting on an exact match is reading one flow's
// evidence, while an analyst acting on an attribute match may be reading two
// different connections that happened to share a tuple in the same second. A
// UI that presented both identically would invite the second to be mistaken for
// the first.
type MatchKind string

const (
	// MatchExact means both records carry the same Community ID. Both analyzers
	// derived it independently from the same packets.
	MatchExact MatchKind = "exact"

	// MatchAttributeTime means the records share a normalized endpoint pair,
	// protocol, and fall inside a bounded time window, but no Community ID was
	// available to confirm it.
	MatchAttributeTime MatchKind = "attribute-time"

	// MatchAmbiguous means the attributes align but several candidates match
	// equally well, so no single pairing can be asserted.
	MatchAmbiguous MatchKind = "ambiguous"

	// MatchNone means the records do not describe the same flow.
	MatchNone MatchKind = "none"
)

// DefaultCorrelationWindow bounds attribute-based matching.
//
// It absorbs the clock skew between two analyzers observing the same packet
// while staying far shorter than the interval at which a client would plausibly
// reconnect on the same ephemeral port. Widening it trades false pairings for
// recall, which is the wrong direction for evidence.
const DefaultCorrelationWindow = 2 * time.Second

// Correlator classifies the relationship between observations.
type Correlator struct {
	// Window bounds attribute-time matching. Zero uses
	// DefaultCorrelationWindow.
	Window time.Duration
}

// Match reports how a and b relate.
func (c *Correlator) Match(a, b *Observation) MatchKind {
	if a == nil || b == nil || a.Flow == nil || b.Flow == nil {
		return MatchNone
	}

	// Community ID is authoritative when both sides have it. It is derived from
	// the packets themselves, so agreement is evidence rather than inference.
	if a.Flow.CommunityID != "" && b.Flow.CommunityID != "" {
		if a.Flow.CommunityID == b.Flow.CommunityID {
			return MatchExact
		}
		// Both analyzers computed an ID and they disagree. That is a positive
		// statement that these are different flows, not a reason to fall back
		// to weaker attribute matching and produce a pairing the stronger
		// signal already ruled out.
		return MatchNone
	}

	if !sameFlowAttributes(a.Flow, b.Flow) {
		return MatchNone
	}
	if !withinWindow(a.EventTime, b.EventTime, c.window()) {
		return MatchNone
	}
	return MatchAttributeTime
}

// Candidates classifies one record against a set, returning the best available
// match kind and the records that achieved it.
//
// When several records tie on attribute-time matching the result is Ambiguous
// rather than an arbitrary pick. Presenting one of several equally plausible
// candidates as "the" match would be a fabricated conclusion.
func (c *Correlator) Candidates(subject *Observation, pool []*Observation) (MatchKind, []*Observation) {
	var exact, attribute []*Observation

	for _, candidate := range pool {
		if candidate == subject {
			continue
		}
		switch c.Match(subject, candidate) {
		case MatchExact:
			exact = append(exact, candidate)
		case MatchAttributeTime:
			attribute = append(attribute, candidate)
		case MatchAmbiguous, MatchNone:
			// Not a candidate.
		}
	}

	if len(exact) > 0 {
		// Several records legitimately share a Community ID: a connection, its
		// DNS lookup, and an alert are all one flow. That is not ambiguity.
		return MatchExact, exact
	}
	switch len(attribute) {
	case 0:
		return MatchNone, nil
	case 1:
		return MatchAttributeTime, attribute
	default:
		return MatchAmbiguous, attribute
	}
}

func (c *Correlator) window() time.Duration {
	if c.Window > 0 {
		return c.Window
	}
	return DefaultCorrelationWindow
}

// sameFlowAttributes compares protocol and the direction-normalized endpoint
// pair.
//
// Direction is normalized because the two analyzers may disagree about which
// endpoint originated a flow — Suricata reports the packet's direction, Zeek
// reports the connection's — and an analyst pivoting from one to the other
// should not have to know which convention produced the record in front of them.
func sameFlowAttributes(a, b *Flow) bool {
	// An absent protocol does not discriminate. Zeek names the transport in
	// conn.log and dns.log but not in http.log, ssl.log or files.log, so
	// treating "" as a value would make an HTTP record fail to match the
	// connection it belongs to - ruling out a pairing on the strength of a
	// field neither analyzer claimed to observe. The result is still reported
	// as attribute-time rather than exact, so nothing here asserts more
	// confidence than the endpoints and window support.
	if a.Protocol != "" && b.Protocol != "" && !strings.EqualFold(a.Protocol, b.Protocol) {
		return false
	}
	aLow, aHigh := normalizedPair(a)
	bLow, bHigh := normalizedPair(b)
	if aLow == "" || aHigh == "" {
		return false
	}
	return aLow == bLow && aHigh == bHigh
}

// normalizedPair returns the flow's endpoints in a stable order.
func normalizedPair(f *Flow) (low, high string) {
	x := endpointString(f.Source)
	y := endpointString(f.Destination)
	if x > y {
		x, y = y, x
	}
	return x, y
}

func endpointString(e Endpoint) string {
	var b strings.Builder
	b.WriteString(e.IP)
	b.WriteByte('/')
	if e.Port != nil {
		b.WriteString(itoa32(*e.Port))
	}
	return b.String()
}

func withinWindow(a, b time.Time, window time.Duration) bool {
	d := a.Sub(b)
	if d < 0 {
		d = -d
	}
	return d <= window
}

func itoa32(v int32) string {
	if v == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	neg := v < 0
	u := v
	if neg {
		u = -v
	}
	for u > 0 {
		i--
		buf[i] = byte('0' + u%10)
		u /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
