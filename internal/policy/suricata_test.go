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

package policy_test

import (
	"strings"
	"testing"
	"time"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/capture"
	"trawl.cloud/trawl/internal/observation"
	"trawl.cloud/trawl/internal/policy"
)

// alert builds a Suricata signature observation the way the sensor emits one.
// Tests override the fields they are about and leave the rest realistic, so a
// test that says "severity 2" is not also silently asserting an empty flow.
func alert(mutate ...func(*observation.Observation)) *observation.Observation {
	port := func(v int32) *int32 { return &v }
	obs := &observation.Observation{
		SchemaVersion:   observation.SchemaVersion,
		ID:              "4125e22fe6fad350aa771423a45c643e",
		EventTime:       time.Date(2026, 9, 9, 13, 46, 36, 0, time.UTC),
		ObservedAt:      time.Date(2026, 9, 9, 13, 46, 36, 0, time.UTC),
		Source:          observation.Source{Kind: observation.SourceSuricata, Version: "8.0.6"},
		Tap:             &observation.Tap{Namespace: "trawl-system", Name: "node-eno1", UID: "tap-uid"},
		Target:          observation.Target{Node: "talos-node", Interface: "eno1"},
		ObservationType: observation.TypeSignature,
		Flow: &observation.Flow{
			CommunityID: "1:jHqeeOu8/MiEmFspokLGdUQj4hE=",
			Protocol:    "tcp",
			Source:      observation.Endpoint{IP: "192.168.0.6", Port: port(51136)},
			Destination: observation.Endpoint{IP: "140.82.113.3", Port: port(22)},
		},
		Details: observation.Details{Signature: &observation.Signature{
			RuleID:   2038968,
			Severity: 2,
			Category: "Misc activity",
			Message:  "ET INFO SSH-2.0-Go version string Observed in Network Traffic",
			Action:   "allowed",
		}},
	}
	for _, m := range mutate {
		m(obs)
	}
	return obs
}

func TestAlertAtAListedSeverityMatches(t *testing.T) {
	trigger := trawlv1alpha1.SuricataAlertTrigger{Severities: []int32{1, 2}}

	got := policy.MatchSuricata(trigger, alert())

	if !got.Matched {
		t.Errorf("severity 2 alert did not match a trigger listing severities 1 and 2: %s", got.Reason)
	}
}

func TestObservationWithoutASignatureDoesNotMatch(t *testing.T) {
	// The worker reads one Loki stream carrying every observation type, so a
	// Zeek connection record reaches this function routinely. It must decline
	// it rather than panic on the absent signature body: a nil dereference here
	// would take down the event worker on ordinary traffic.
	trigger := trawlv1alpha1.SuricataAlertTrigger{Severities: []int32{1, 2}}
	conn := alert(func(o *observation.Observation) {
		o.Source = observation.Source{Kind: observation.SourceZeek, Version: "8.0.10"}
		o.ObservationType = observation.TypeConnection
		o.Details = observation.Details{Connection: &observation.Connection{Service: "ssh", State: "SF"}}
	})

	got := policy.MatchSuricata(trigger, conn)

	if got.Matched {
		t.Fatal("a Zeek connection record matched a Suricata alert trigger")
	}
	if got.Reason != policy.ReasonNotAnAlert {
		t.Errorf("reason = %q, want %q", got.Reason, policy.ReasonNotAnAlert)
	}
}

func TestRuleIDsNarrowWithinTheMatchedSeverities(t *testing.T) {
	// Optional fields narrow; they never widen. An alert at a listed severity
	// but an unlisted rule must not match, and the reason must say which of the
	// two filters rejected it - "SeverityNotListed" on a severity that is in
	// fact listed would send an operator to the wrong field.
	trigger := trawlv1alpha1.SuricataAlertTrigger{
		Severities: []int32{1, 2},
		RuleIDs:    []int64{2038968},
	}

	if got := policy.MatchSuricata(trigger, alert()); !got.Matched {
		t.Errorf("listed rule 2038968 did not match: %s", got.Reason)
	}

	other := alert(func(o *observation.Observation) { o.Details.Signature.RuleID = 2071407 })
	got := policy.MatchSuricata(trigger, other)
	if got.Matched {
		t.Fatal("unlisted rule 2071407 matched")
	}
	if got.Reason != policy.ReasonRuleNotListed {
		t.Errorf("reason = %q, want %q", got.Reason, policy.ReasonRuleNotListed)
	}
}

func TestAnOmittedNarrowingFieldMatchesEveryValue(t *testing.T) {
	// A trigger with no rule IDs matches every rule at the listed severities.
	// Read the other way - empty means match nothing - a policy an operator
	// believed was armed would silently never fire.
	trigger := trawlv1alpha1.SuricataAlertTrigger{Severities: []int32{2}}

	for _, rule := range []int64{2038968, 2071407, 1} {
		obs := alert(func(o *observation.Observation) { o.Details.Signature.RuleID = rule })
		if got := policy.MatchSuricata(trigger, obs); !got.Matched {
			t.Errorf("rule %d did not match a trigger that lists no rules: %s", rule, got.Reason)
		}
	}
}

func TestCategoriesNarrowExactlyAndNotBySubstring(t *testing.T) {
	// Categories are compared whole. A substring or prefix comparison would let
	// "Misc activity" be selected by a trigger listing "Misc", which reads as a
	// convenience until a category like "Attempted Administrator Privilege
	// Gain" is matched by a trigger meant for "Attempted".
	trigger := trawlv1alpha1.SuricataAlertTrigger{
		Severities: []int32{1, 2},
		Categories: []string{"Misc activity"},
	}

	if got := policy.MatchSuricata(trigger, alert()); !got.Matched {
		t.Errorf("exact category did not match: %s", got.Reason)
	}

	for _, category := range []string{"Misc", "misc activity", "Misc activity extended", ""} {
		obs := alert(func(o *observation.Observation) { o.Details.Signature.Category = category })
		got := policy.MatchSuricata(trigger, obs)
		if got.Matched {
			t.Errorf("category %q matched a trigger listing only %q", category, "Misc activity")
		}
		if got.Reason != policy.ReasonCategoryNotListed {
			t.Errorf("category %q: reason = %q, want %q", category, got.Reason, policy.ReasonCategoryNotListed)
		}
	}
}

func TestFilterTemplateRendersDocumentedPlaceholders(t *testing.T) {
	// The rendered filter is what the runner hands to dumpcap, so this is the
	// point where event data becomes part of a command's input.
	got, err := policy.RenderFilter(
		"host {{source.ip}} and host {{destination.ip}} and {{protocol}} port {{destination.port}}",
		alert())
	if err != nil {
		t.Fatalf("rendering a documented template: %v", err)
	}

	want := "host 192.168.0.6 and host 140.82.113.3 and tcp port 22"
	if got != want {
		t.Errorf("rendered %q, want %q", got, want)
	}
}

func TestPlaceholderValuesAreRejectedUnlessTheyAreTheTypeTheyClaim(t *testing.T) {
	// Placeholder values come from the observation, and the observation is
	// built from analyzer output describing traffic an attacker sends. If a
	// value carrying BPF syntax is interpolated verbatim, the attacker chooses
	// part of the expression the capture runner executes - selecting what gets
	// recorded, or widening a targeted capture to the whole interface.
	//
	// The defense is that every placeholder is typed: an ip placeholder yields
	// a value that parses as an IP address or the render fails. Escaping would
	// not do, because there is no quoting in BPF to escape into.
	for _, tc := range []struct {
		name string
		ip   string
	}{
		{"filter continuation", "1.2.3.4 or tcp"},
		{"expression close", "1.2.3.4) or ("},
		{"negation", "not 1.2.3.4"},
		{"trailing comment", "1.2.3.4 and port 22 -- "},
		{"empty", ""},
		{"not an address at all", "example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obs := alert(func(o *observation.Observation) { o.Flow.Source.IP = tc.ip })

			got, err := policy.RenderFilter("host {{source.ip}}", obs)

			if err == nil {
				t.Fatalf("rendered %q from source IP %q; want an error", got, tc.ip)
			}
			// Guarded: strings.Contains is vacuously true for an empty
			// needle, so the empty case would assert nothing.
			if tc.ip != "" && strings.Contains(got, tc.ip) {
				t.Errorf("the rejected value %q still reached the output %q", tc.ip, got)
			}
		})
	}
}

func TestUnknownPlaceholdersAreRejected(t *testing.T) {
	// Only the documented set renders. An undocumented name must fail loudly
	// rather than render as empty: "host " with nothing after it is either a
	// BPF syntax error or, worse, a filter that means something else.
	for _, template := range []string{
		"host {{source.mac}}",
		"host {{signature.message}}",
		"host {{}}",
		"host {{ source.ip ",
	} {
		if got, err := policy.RenderFilter(template, alert()); err == nil {
			t.Errorf("template %q rendered %q; want an error", template, got)
		}
	}
}

func TestRenderedFilterIsValidatedAsAWholeFilter(t *testing.T) {
	// Each placeholder is validated as it is substituted, but the result is
	// what reaches dumpcap. A template that is itself malformed - control
	// characters, or long enough that the rendered filter passes the bound the
	// rest of the system carries it under - has to fail here rather than at the
	// runner, where the failure surfaces as a capture that never starts.
	long := "host {{source.ip}} and (" + strings.Repeat("host 10.0.0.1 or ", 100) + "host 10.0.0.2)"
	if len(long) <= capture.MaxFilterBytes {
		t.Fatalf("test setup: template is %d bytes, not over the %d-byte bound",
			len(long), capture.MaxFilterBytes)
	}

	for name, template := range map[string]string{
		"over the byte bound": long,
		"control character":   "host {{source.ip}} and\x00 port 22",
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := policy.RenderFilter(template, alert()); err == nil {
				t.Errorf("rendered %q; want an error", got)
			}
		})
	}
}

func TestAValidRenderedFilterPassesTheSharedValidator(t *testing.T) {
	// The counterpart to the rejections above: the ordinary rendering path must
	// produce something the rest of the system accepts, so that this function
	// and internal/capture cannot drift into disagreeing about what a filter is.
	got, err := policy.RenderFilter("host {{source.ip}} and {{protocol}} port {{destination.port}}", alert())
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}
	if err := capture.ValidateFilterSyntax(got); err != nil {
		t.Errorf("rendered filter %q rejected by the shared validator: %v", got, err)
	}
}

func TestSuricataSnapshotRecordsTheAlertWithinTheAPIsBounds(t *testing.T) {
	// The snapshot is what explains a capture after the alert has aged out of
	// Loki, and it is written into a CaptureJob the API server validates. The
	// category and message come from the signature ruleset, which is not ours
	// and states no length limit, so a long rule description would otherwise
	// produce a CaptureJob the API server rejects - losing the capture over a
	// field that exists only to describe it.
	obs := alert(func(o *observation.Observation) {
		o.Details.Signature.Category = strings.Repeat("c", 200)
		o.Details.Signature.Message = strings.Repeat("m", 900)
	})

	got, err := policy.SuricataSnapshot(obs, "sha256:"+strings.Repeat("a", 64))
	if err != nil {
		t.Fatalf("building snapshot: %v", err)
	}

	if got.Source != trawlv1alpha1.TriggerSourceSuricataAlert {
		t.Errorf("source = %q, want %q", got.Source, trawlv1alpha1.TriggerSourceSuricataAlert)
	}
	if len(got.Suricata.Category) > 128 {
		t.Errorf("category is %d bytes, over the API's 128-byte bound", len(got.Suricata.Category))
	}
	if len(got.Suricata.Message) > 512 {
		t.Errorf("message is %d bytes, over the API's 512-byte bound", len(got.Suricata.Message))
	}
	if got.Suricata.RuleID != 2038968 || got.Suricata.Severity != 2 {
		t.Errorf("rule/severity = %d/%d, want 2038968/2", got.Suricata.RuleID, got.Suricata.Severity)
	}
	if !got.EventTime.Time.Equal(obs.EventTime) {
		t.Errorf("event time = %s, want %s", got.EventTime, obs.EventTime)
	}
	if got.Flow == nil || got.Flow.SourceIP != "192.168.0.6" {
		t.Errorf("flow snapshot did not record the matched source: %+v", got.Flow)
	}
}

func TestARevisionOutsideTheAPIsRangeIsOmittedNotWrapped(t *testing.T) {
	// Revision is int64 in the envelope and int32 in the API, with a Minimum of
	// 0. A plain conversion of a large value wraps to a negative number, which
	// the API server rejects - so an implausible revision on one signature
	// would cost the capture. Omitting the field loses a detail; wrapping it
	// loses the evidence.
	// 1<<31 is the smallest value that wraps to a negative int32; 1<<40
	// truncates to 0 and would let a broken conversion pass.
	revision := int64(1) << 31
	obs := alert(func(o *observation.Observation) { o.Details.Signature.Revision = &revision })

	got, err := policy.SuricataSnapshot(obs, "sha256:"+strings.Repeat("a", 64))
	if err != nil {
		t.Fatalf("building snapshot: %v", err)
	}

	if got.Suricata.Revision < 0 {
		t.Errorf("revision = %d, which the API's Minimum=0 rejects", got.Suricata.Revision)
	}
}

func TestFilterTemplateValidationRejectsUnknownPlaceholdersBeforeArming(t *testing.T) {
	// The webhook checks the template when the policy is written, with no event
	// in hand. Deferring it to render time would mean an operator arms a policy
	// that looks accepted and then fails silently at the only moment it
	// mattered - when an alert fired and the capture did not start.
	for name, template := range map[string]string{
		"unknown placeholder": "host {{source.mac}}",
		"payload field":       "host {{signature.message}}",
		"empty placeholder":   "host {{}}",
		"unterminated":        "host {{source.ip",
		"over the byte bound": "host {{source.ip}} " + strings.Repeat("x", 1100),
	} {
		t.Run(name, func(t *testing.T) {
			if err := policy.ValidateFilterTemplate(template); err == nil {
				t.Errorf("template %q was accepted", template)
			}
		})
	}
}

func TestAValidTemplateIsAcceptedWithoutAnEvent(t *testing.T) {
	// The control: every documented placeholder, and the empty template that
	// means "capture everything the bounds allow".
	for _, template := range []string{
		"",
		"host {{source.ip}} and host {{destination.ip}}",
		"{{protocol}} port {{source.port}} or {{protocol}} port {{destination.port}}",
		"tcp port 443",
	} {
		if err := policy.ValidateFilterTemplate(template); err != nil {
			t.Errorf("template %q was rejected: %v", template, err)
		}
	}
}

func TestTheValidatorAndTheRendererAgreeOnTheDocumentedPlaceholders(t *testing.T) {
	// Two lists describe the placeholder set: the switch RenderFilter
	// substitutes from, and the names ValidateFilterTemplate accepts. If they
	// drift, the failure is silent and one-directional - the webhook admits a
	// policy naming a placeholder the renderer cannot resolve, and the capture
	// fails only when an alert finally fires.
	//
	// Checked by round-tripping every name through both.
	obs := alert()
	for _, name := range []string{
		"source.ip", "destination.ip", "source.port", "destination.port", "protocol",
	} {
		template := "host {{" + name + "}}"

		if err := policy.ValidateFilterTemplate(template); err != nil {
			t.Errorf("the validator rejects documented placeholder %q: %v", name, err)
			continue
		}
		if _, err := policy.RenderFilter(template, obs); err != nil {
			t.Errorf("the renderer cannot resolve documented placeholder %q: %v", name, err)
		}
	}

	// And the other direction: a name the renderer does not know must not pass
	// the validator either.
	for _, name := range []string{"source.mac", "tap.name", "signature.category"} {
		template := "host {{" + name + "}}"
		if err := policy.ValidateFilterTemplate(template); err == nil {
			t.Errorf("the validator accepts %q, which the renderer cannot resolve", name)
		}
	}
}
