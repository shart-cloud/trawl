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
	"encoding/json"
	"strings"
	"testing"
	"time"

	"trawl.cloud/trawl/internal/observation"
)

// The envelope is what dashboards, LogQL templates, and the trigger worker all
// read. These tests hold it to the published schema for every subtype, and
// assert the fields that must never appear in it.

func envelope(obsType observation.ObservationType, details observation.Details) *observation.Observation {
	return &observation.Observation{
		SchemaVersion:   observation.SchemaVersion,
		ID:              strings.Repeat("a", 32),
		EventTime:       time.Date(2026, 8, 29, 11, 59, 0, 0, time.UTC),
		ObservedAt:      time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC),
		Source:          observation.Source{Kind: observation.SourceZeek, Version: "8.0.10"},
		Tap:             &observation.Tap{Namespace: "trawl-system", Name: "tap", UID: "tap-uid"},
		Target:          observation.Target{Node: "sensor-01", Interface: "enp5s0"},
		ObservationType: obsType,
		Flow: &observation.Flow{
			Protocol:    "tcp",
			Source:      observation.Endpoint{IP: "10.0.0.1"},
			Destination: observation.Endpoint{IP: "10.0.0.2"},
		},
		Details: details,
	}
}

func TestEverySubtypeSatisfiesTheSchema(t *testing.T) {
	// A subtype the sensor can emit but the schema rejects would be silently
	// dropped at the sensor and never appear in an investigation.
	notValidAfter := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	size := int64(4096)

	cases := map[observation.ObservationType]observation.Details{
		observation.TypeSignature: {Signature: &observation.Signature{
			RuleID: 2019401, Severity: 2, Category: "policy", Message: "test",
		}},
		observation.TypeConnection: {Connection: &observation.Connection{
			Service: "ssl", State: "SF",
		}},
		observation.TypeDNS: {DNS: &observation.DNS{Query: "example.com", QType: "A"}},
		observation.TypeHTTP: {HTTP: &observation.HTTP{
			Method: "GET", Host: "example.com", URIPath: "/index.html",
		}},
		observation.TypeTLS: {TLS: &observation.TLS{
			Version: "TLSv13", ServerName: "example.com",
		}},
		observation.TypeCertificate: {Certificate: &observation.Certificate{
			FingerprintSHA256: strings.Repeat("ab", 32),
			Subject:           "CN=example.com",
			NotValidAfter:     &notValidAfter,
		}},
		observation.TypeFile: {File: &observation.File{
			MIMEType: "application/zip", SHA256: strings.Repeat("cd", 32), SizeBytes: &size,
		}},
		observation.TypeNotice: {Notice: &observation.Notice{
			Type: "Scan::Port_Scan", Message: "scanned 20 ports",
		}},
		observation.TypeWeird: {Weird: &observation.Weird{Name: "bad_TCP_checksum"}},
		observation.TypeClusterFlow: {ClusterFlow: &observation.ClusterFlow{
			Verdict: "DROPPED", DropReason: "POLICY_DENIED",
		}},
	}

	for obsType, details := range cases {
		t.Run(string(obsType), func(t *testing.T) {
			obs := envelope(obsType, details)
			if obsType == observation.TypeClusterFlow {
				obs.Source = observation.Source{Kind: observation.SourceHubble, Version: "1.18.11"}
			}
			if err := observation.Validate(obs); err != nil {
				t.Errorf("%s violates the schema: %v", obsType, err)
			}
		})
	}

	// Every enum member must be covered, or a subtype could be added to the
	// code without ever being validated here.
	all := []observation.ObservationType{
		observation.TypeSignature, observation.TypeConnection, observation.TypeDNS,
		observation.TypeHTTP, observation.TypeTLS, observation.TypeCertificate,
		observation.TypeFile, observation.TypeNotice, observation.TypeWeird,
		observation.TypeClusterFlow,
	}
	for _, obsType := range all {
		if _, ok := cases[obsType]; !ok {
			t.Errorf("observation type %q has no schema case", obsType)
		}
	}
}

func TestSchemaRejectsAnEnvelopeWithTwoDetailBodies(t *testing.T) {
	// A record carrying two bodies is ambiguous about what it describes, and
	// downstream consumers would each pick a different one.
	obs := envelope(observation.TypeDNS, observation.Details{
		DNS:  &observation.DNS{Query: "example.com"},
		HTTP: &observation.HTTP{Method: "GET"},
	})
	if err := observation.Validate(obs); err == nil {
		t.Fatal("the schema accepted a record with two detail bodies")
	}
}

func TestSchemaRejectsAnEnvelopeWithNoDetailBody(t *testing.T) {
	obs := envelope(observation.TypeDNS, observation.Details{})
	if err := observation.Validate(obs); err == nil {
		t.Fatal("the schema accepted an envelope with no observation in it")
	}
}

func TestNormalizeRejectsMismatchedTypeAndBody(t *testing.T) {
	// A record labelled dns but carrying an http body would be filed under the
	// wrong subtype and be invisible to the query that should find it.
	obs := envelope(observation.TypeDNS, observation.Details{
		HTTP: &observation.HTTP{Method: "GET"},
	})
	if err := observation.Normalize(obs); err == nil {
		t.Fatal("a record whose type contradicts its body was accepted")
	}
}

func TestSchemaRequiresProvenanceFields(t *testing.T) {
	// Without these an observation cannot be attributed: which analyzer, which
	// version, which tap, which node.
	for name, mutate := range map[string]func(*observation.Observation){
		"no schema version": func(o *observation.Observation) { o.SchemaVersion = "" },
		"no id":             func(o *observation.Observation) { o.ID = "" },
		"no source kind":    func(o *observation.Observation) { o.Source.Kind = "" },
		"no source version": func(o *observation.Observation) { o.Source.Version = "" },
		"no target node":    func(o *observation.Observation) { o.Target.Node = "" },
	} {
		t.Run(name, func(t *testing.T) {
			obs := envelope(observation.TypeDNS, observation.Details{
				DNS: &observation.DNS{Query: "example.com"},
			})
			mutate(obs)
			if err := observation.Validate(obs); err == nil {
				t.Errorf("the schema accepted a record with %s", name)
			}
		})
	}
}

func TestZeroTimestampsAreRejectedByNormalizeNotTheSchema(t *testing.T) {
	// A zero time marshals to 0001-01-01T00:00:00Z, which is a syntactically
	// valid date-time, so the schema accepts it. Such a record would sit in
	// Loki dated year 1 - invisible to every dashboard range query and
	// impossible to place in a timeline.
	//
	// JSON Schema cannot express "a plausible timestamp", so Normalize enforces
	// it. This test documents that split so nobody assumes schema validation
	// alone is sufficient.
	for name, mutate := range map[string]func(*observation.Observation){
		"zero event time":       func(o *observation.Observation) { o.EventTime = time.Time{} },
		"zero observation time": func(o *observation.Observation) { o.ObservedAt = time.Time{} },
	} {
		t.Run(name, func(t *testing.T) {
			obs := envelope(observation.TypeDNS, observation.Details{
				DNS: &observation.DNS{Query: "example.com"},
			})
			mutate(obs)

			if err := observation.Validate(obs); err != nil {
				t.Logf("the schema also rejected %s, which is fine but not relied on", name)
			}
			if err := observation.Normalize(obs); err == nil {
				t.Errorf("Normalize accepted a record with %s", name)
			}
		})
	}
}

func TestSchemaForbidsUnknownTopLevelFields(t *testing.T) {
	// additionalProperties is false so a producer cannot smuggle an
	// unreviewed field - payload, headers, a raw record - into storage by
	// adding it to its own output.
	raw := map[string]any{
		"schema_version":   observation.SchemaVersion,
		"id":               strings.Repeat("a", 32),
		"event_time":       "2026-08-29T11:59:00Z",
		"observed_at":      "2026-08-29T12:00:00Z",
		"source":           map[string]any{"kind": "Zeek", "version": "8.0.10"},
		"target":           map[string]any{"node": "sensor-01"},
		"observation_type": "dns",
		"details":          map[string]any{"dns": map[string]any{"query": "example.com"}},
		"raw_packet":       "AAAA",
	}

	schema, err := observation.Schema()
	if err != nil {
		t.Fatalf("compiling schema: %v", err)
	}
	if err := schema.Validate(raw); err == nil {
		t.Fatal("the schema accepted an unknown top-level field")
	}
}

func TestSchemaForbidsPayloadFieldsInDetailBodies(t *testing.T) {
	// The subtype bodies are closed for the same reason: an analyzer that
	// starts emitting request bodies must not be able to get them stored.
	schema, err := observation.Schema()
	if err != nil {
		t.Fatalf("compiling schema: %v", err)
	}

	for _, field := range []string{"payload", "body", "headers", "packet", "request_body"} {
		t.Run(field, func(t *testing.T) {
			raw := map[string]any{
				"schema_version":   observation.SchemaVersion,
				"id":               strings.Repeat("a", 32),
				"event_time":       "2026-08-29T11:59:00Z",
				"observed_at":      "2026-08-29T12:00:00Z",
				"source":           map[string]any{"kind": "Zeek", "version": "8.0.10"},
				"target":           map[string]any{"node": "sensor-01"},
				"observation_type": "http",
				"details": map[string]any{"http": map[string]any{
					"method": "GET",
					field:    "secret content",
				}},
			}
			if err := schema.Validate(raw); err == nil {
				t.Errorf("the schema accepted %q inside an http detail body", field)
			}
		})
	}
}

func TestNormalizedRecordsCarryNoSensitiveFieldNames(t *testing.T) {
	// A belt-and-braces check on the Go types themselves: the envelope must not
	// gain a payload-shaped field through a future edit that the schema then
	// gets updated to permit.
	obs := envelope(observation.TypeHTTP, observation.Details{
		HTTP: &observation.HTTP{Method: "GET", Host: "h", URIPath: "/p"},
	})
	encoded, err := json.Marshal(obs)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}

	for _, forbidden := range []string{
		`"payload"`, `"body"`, `"headers"`, `"packet"`,
		`"cookie"`, `"authorization"`, `"password"`,
	} {
		if strings.Contains(string(encoded), forbidden) {
			t.Errorf("the observation envelope carries a %s field", forbidden)
		}
	}
}

func TestHTTPRecordsCarryNoQueryString(t *testing.T) {
	// The sensor strips it because a URI query routinely carries session tokens
	// and API keys. The schema names the field uri_path rather than uri so a
	// future producer cannot put a full URI there and call it correct.
	schema, err := observation.Schema()
	if err != nil {
		t.Fatalf("compiling schema: %v", err)
	}

	raw := map[string]any{
		"schema_version":   observation.SchemaVersion,
		"id":               strings.Repeat("a", 32),
		"event_time":       "2026-08-29T11:59:00Z",
		"observed_at":      "2026-08-29T12:00:00Z",
		"source":           map[string]any{"kind": "Zeek", "version": "8.0.10"},
		"target":           map[string]any{"node": "sensor-01"},
		"observation_type": "http",
		"details":          map[string]any{"http": map[string]any{"uri": "/p?token=secret"}},
	}
	if err := schema.Validate(raw); err == nil {
		t.Fatal("the schema accepted a full uri field rather than uri_path")
	}
}

func TestHubbleRecordsUseTheClusterFlowSubtype(t *testing.T) {
	// Hubble's records describe the cluster's verdict, not packets on a wire.
	// Filing them under connection would make an allowed/denied decision
	// indistinguishable from an observed connection.
	obs := envelope(observation.TypeClusterFlow, observation.Details{
		ClusterFlow: &observation.ClusterFlow{Verdict: "FORWARDED"},
	})
	obs.Source = observation.Source{Kind: observation.SourceHubble, Version: "1.18.11"}

	if err := observation.Validate(obs); err != nil {
		t.Fatalf("a Hubble cluster-flow record violates the schema: %v", err)
	}
}

func TestClusterFlowRequiresAVerdict(t *testing.T) {
	// A cluster-flow record without a verdict says nothing that a packet
	// analyzer has not already said better.
	obs := envelope(observation.TypeClusterFlow, observation.Details{
		ClusterFlow: &observation.ClusterFlow{},
	})
	obs.Source = observation.Source{Kind: observation.SourceHubble, Version: "1.18.11"}

	if err := observation.Validate(obs); err == nil {
		t.Fatal("a cluster-flow record with no verdict was accepted")
	}
}
