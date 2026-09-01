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

package contract

import (
	"strings"
	"testing"
	"time"

	"trawl.cloud/trawl/internal/observation"
	fixtures "trawl.cloud/trawl/test/fixtures/observations"
)

// These drive the real normalizers over raw analyzer output, so a normalizer
// that silently stopped preserving Community ID would fail here rather than
// quietly reducing an analyst's recall.

func normalizeSession(t *testing.T, s fixtures.Session) []*observation.Observation {
	t.Helper()

	tap := &observation.Tap{Namespace: "trawl-system", Name: "fixture-tap", UID: "fixture-uid"}
	target := observation.Target{Node: "sensor-01", Interface: "enp5s0"}
	now := func() time.Time { return fixtures.BaseTime.Add(time.Minute) }

	suricata := &observation.SuricataNormalizer{
		Version: observation.StaticVersion("8.0.6"), Tap: tap, Target: target, Now: now,
	}
	zeek := &observation.ZeekNormalizer{Version: observation.StaticVersion("8.0.10"), Tap: tap, Target: target, Now: now}

	var out []*observation.Observation
	for _, line := range s.SuricataEVE {
		obs, _, err := suricata.Normalize([]byte(line))
		if err != nil {
			t.Fatalf("%s: normalizing EVE: %v", s.Name, err)
		}
		if obs != nil {
			out = append(out, obs)
		}
	}
	for _, log := range s.ZeekLogs {
		obs, err := zeek.Normalize(observation.ZeekLogType(log.Type), []byte(log.Line))
		if err != nil {
			t.Fatalf("%s: normalizing zeek %s: %v", s.Name, log.Type, err)
		}
		out = append(out, obs)
	}
	return out
}

func TestFixtureSessionsNormalizeAndValidate(t *testing.T) {
	for _, session := range fixtures.All() {
		t.Run(session.Name, func(t *testing.T) {
			records := normalizeSession(t, session)
			if len(records) == 0 {
				t.Fatal("session produced no records")
			}
			for _, obs := range records {
				if err := observation.Normalize(obs); err != nil {
					t.Errorf("Normalize: %v", err)
				}
				if err := observation.Validate(obs); err != nil {
					t.Errorf("record violates the schema: %v", err)
				}
			}
		})
	}
}

func TestExactPivotFindsEveryRecordInASession(t *testing.T) {
	// The SC-005 path: one pivot on Community ID returns the whole flow, with
	// no tuple reconstruction by the analyst.
	for _, session := range fixtures.All() {
		if session.CommunityID == "" {
			continue
		}
		t.Run(session.Name, func(t *testing.T) {
			records := normalizeSession(t, session)
			c := &observation.Correlator{}

			// Pivot from every record in turn: SC-005 times attempts starting
			// from each direction, so the property must hold from all of them.
			flowless := 0
			for i, subject := range records {
				kind, matches := c.Candidates(subject, records)

				// A record with no flow cannot be correlated, and saying so is
				// the point. Zeek's x509.log carries no uid, no conn_id and no
				// Community ID, so a certificate is reachable only through the
				// fingerprint in ssl.log's cert_chain_fps. Asserting MatchNone
				// here keeps that limitation visible: if correlation ever
				// started returning a match for one of these, it would be
				// inventing a link the evidence does not contain.
				if subject.Flow == nil {
					flowless++
					if kind != observation.MatchNone {
						t.Errorf("pivot from flowless record %d: kind = %q, want none", i, kind)
					}
					continue
				}

				if kind != observation.MatchExact {
					t.Errorf("pivot from record %d: kind = %q, want exact", i, kind)
				}
				if len(matches) != session.ExactMatches-1 {
					t.Errorf("pivot from record %d found %d matches, want %d",
						i, len(matches), session.ExactMatches-1)
				}
			}

			if flowless != session.FlowlessRecords {
				t.Errorf("session produced %d flowless records, want %d",
					flowless, session.FlowlessRecords)
			}
		})
	}
}

func TestFallbackPivotIsReportedAsApproximate(t *testing.T) {
	// When no Community ID exists, correlation must still work and must not
	// claim more confidence than it has (FR-015).
	session := fixtures.SessionWithoutCommunityID()
	records := normalizeSession(t, session)

	if len(records) < 2 {
		t.Fatalf("fixture produced %d records, want at least 2", len(records))
	}

	c := &observation.Correlator{Window: 5 * time.Second}
	kind, matches := c.Candidates(records[0], records)

	if kind != observation.MatchAttributeTime {
		t.Errorf("kind = %q, want %q", kind, observation.MatchAttributeTime)
	}
	if len(matches) == 0 {
		t.Error("the fallback pivot found nothing")
	}
}

func TestCrossAnalyzerRecordsShareTheirCommunityID(t *testing.T) {
	// The property the whole investigation workflow rests on: Suricata's alert
	// and Zeek's connection agree on the flow's identity.
	session := fixtures.TLSSessionWithAlert()
	records := normalizeSession(t, session)

	kinds := make([]observation.SourceKind, 0, len(records))
	for _, obs := range records {
		if obs.Flow == nil || obs.Flow.CommunityID != session.CommunityID {
			t.Errorf("%s record does not carry the session's Community ID", obs.Source.Kind)
		}
		kinds = append(kinds, obs.Source.Kind)
	}

	var hasSuricata, hasZeek bool
	for _, k := range kinds {
		switch k {
		case observation.SourceSuricata:
			hasSuricata = true
		case observation.SourceZeek:
			hasZeek = true
		case observation.SourceHubble:
			// Not part of this fixture.
		}
	}
	if !hasSuricata || !hasZeek {
		t.Error("the fixture does not exercise both analyzers")
	}
}

func TestStoredRecordsNeverCarryAQueryStringToken(t *testing.T) {
	// The property must hold through the whole path an operator queries, not
	// just at the function that strips it.
	session := fixtures.HTTPSessionWithCredentialInQuery()
	records := normalizeSession(t, session)

	var sawHTTP bool
	for _, obs := range records {
		if obs.Details.HTTP == nil {
			continue
		}
		sawHTTP = true
		if strings.Contains(obs.Details.HTTP.URIPath, "token") {
			t.Errorf("uri_path retained a query token: %q", obs.Details.HTTP.URIPath)
		}
		if strings.Contains(obs.Details.HTTP.URIPath, "s3cr3t-session-value") {
			t.Error("uri_path retained the session token verbatim")
		}
		if obs.Details.HTTP.URIPath != "/v1/session" {
			t.Errorf("uri_path = %q, want the path alone", obs.Details.HTTP.URIPath)
		}
	}
	if !sawHTTP {
		t.Fatal("the fixture produced no HTTP record")
	}
}

func TestEveryObservationSubtypeAppearsAcrossTheFixtures(t *testing.T) {
	// A subtype no fixture produces is one no investigation test exercises.
	seen := map[observation.ObservationType]bool{}
	for _, session := range fixtures.All() {
		for _, obs := range normalizeSession(t, session) {
			seen[obs.ObservationType] = true
		}
	}

	// Every subtype a Zeek or Suricata sensor can emit. cluster_flow is absent
	// by construction: it comes from Hubble, which these analyzer fixtures do
	// not model, and it is exercised against a real Hubble relay instead.
	for _, want := range []observation.ObservationType{
		observation.TypeSignature,
		observation.TypeConnection,
		observation.TypeDNS,
		observation.TypeHTTP,
		observation.TypeTLS,
		observation.TypeCertificate,
		observation.TypeFile,
		observation.TypeNotice,
		observation.TypeWeird,
	} {
		if !seen[want] {
			t.Errorf("no fixture produces a %q record", want)
		}
	}
}

func TestCertificateRecordsCarryTheirParsedFields(t *testing.T) {
	// The x509 parser previously decoded a nested "certificate" object, which
	// Zeek never writes: under the json-logs policy Trawl configures, a
	// record-valued field is flattened to dotted keys, exactly as conn.log's
	// "id.orig_h" is. The nested decode succeeded and produced a Certificate
	// with every field empty, so the record validated, stored, and answered
	// every query with blanks.
	records := normalizeSession(t, fixtures.TLSSessionWithCertificate())

	var cert *observation.Certificate
	for _, obs := range records {
		if obs.Details.Certificate != nil {
			cert = obs.Details.Certificate
		}
	}
	if cert == nil {
		t.Fatal("the fixture produced no certificate record")
	}

	if cert.Subject == "" || cert.Issuer == "" || cert.Serial == "" {
		t.Errorf("certificate fields were not parsed: %+v", cert)
	}
	if cert.NotValidBefore == nil || cert.NotValidAfter == nil {
		t.Errorf("certificate validity window was not parsed: %+v", cert)
	}
	if cert.FingerprintSHA256 == "" {
		t.Error("certificate has no fingerprint, so nothing can reach it from a flow")
	}
}

func TestATLSRecordReachesItsCertificateByFingerprint(t *testing.T) {
	// The only route from a flow to a certificate. x509.log has no uid, no
	// conn_id and no Community ID, so without the chain fingerprints on the TLS
	// record an observed certificate is unreachable from the handshake that
	// presented it.
	records := normalizeSession(t, fixtures.TLSSessionWithCertificate())

	var tlsFingerprints []string
	var certFingerprint string
	for _, obs := range records {
		if obs.Details.TLS != nil {
			tlsFingerprints = obs.Details.TLS.CertificateFingerprints
		}
		if obs.Details.Certificate != nil {
			certFingerprint = obs.Details.Certificate.FingerprintSHA256
		}
	}

	if certFingerprint == "" {
		t.Fatal("no certificate record")
	}
	if len(tlsFingerprints) == 0 {
		t.Fatal("the TLS record carries no certificate fingerprints")
	}

	var found bool
	for _, fp := range tlsFingerprints {
		if fp == certFingerprint {
			found = true
		}
	}
	if !found {
		t.Errorf("TLS chain %v does not include the observed certificate %q",
			tlsFingerprints, certFingerprint)
	}
}
