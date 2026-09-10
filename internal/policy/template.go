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

package policy

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"trawl.cloud/trawl/internal/capture"
	"trawl.cloud/trawl/internal/observation"
)

// placeholderRE matches one {{name}} occurrence and captures the name.
//
// Deliberately not text/template. A Go template brings functions, pipelines and
// field traversal, and the value being interpolated becomes part of a BPF
// expression the capture runner executes. The plan chose a closed set of typed
// placeholders over Go templates for exactly that reason
// (specs/001-cloud-native-nsm/plan.md).
var placeholderRE = regexp.MustCompile(`\{\{([^{}]*)\}\}`)

// RenderFilter substitutes the documented placeholders in a policy's filter
// template with values from the observation that triggered it.
func RenderFilter(template string, obs *observation.Observation) (string, error) {
	var err error
	rendered := placeholderRE.ReplaceAllStringFunc(template, func(match string) string {
		name := strings.TrimSpace(placeholderRE.FindStringSubmatch(match)[1])
		value, resolveErr := resolvePlaceholder(name, obs)
		if resolveErr != nil && err == nil {
			err = resolveErr
		}
		return value
	})
	if err != nil {
		return "", err
	}
	// An unterminated or malformed placeholder leaves braces behind. BPF has no
	// use for them, so rather than pass a filter the runner will reject with a
	// less obvious message, say so here.
	if strings.Contains(rendered, "{{") || strings.Contains(rendered, "}}") {
		return "", fmt.Errorf("filter template has an unterminated placeholder")
	}
	// Validated as a whole filter, with the same function the manual path uses.
	// Per-placeholder typing says each substituted value is what it claims to
	// be; it says nothing about the template around them, and the rendered
	// string is longer than the template it came from. Sharing the validator
	// rather than restating its rules is what stops the automatic and manual
	// paths drifting into disagreeing about what a filter is.
	if err := capture.ValidateFilterSyntax(rendered); err != nil {
		return "", fmt.Errorf("rendered filter: %w", err)
	}
	return rendered, nil
}

// bpfProtocols are the transport names a filter may name. Closed, because the
// protocol string is copied from analyzer output: anything outside this set is
// either a protocol dumpcap cannot filter on or an attempt to put something
// else in its place.
var bpfProtocols = []string{"tcp", "udp", "icmp", "icmp6", "sctp"}

// placeholder is one documented substitution: how to read it from a flow, and
// a representative value so a template can be checked before any event exists.
type placeholder struct {
	resolve  func(name string, flow *observation.Flow) (string, error)
	specimen string
}

// placeholders is the closed, documented set - the single source of truth for
// both RenderFilter and ValidateFilterTemplate.
//
// One map rather than a switch beside a list. The two used to be separate, and
// the drift between them would have been silent and one-directional: the
// webhook admits a policy naming a placeholder the renderer cannot resolve, and
// the capture fails only when an alert finally fires.
var placeholders = map[string]placeholder{
	"source.ip": {
		resolve:  func(n string, f *observation.Flow) (string, error) { return ipValue(n, f.Source.IP) },
		specimen: "192.0.2.1",
	},
	"destination.ip": {
		resolve:  func(n string, f *observation.Flow) (string, error) { return ipValue(n, f.Destination.IP) },
		specimen: "192.0.2.2",
	},
	"source.port": {
		resolve:  func(n string, f *observation.Flow) (string, error) { return portValue(n, f.Source.Port) },
		specimen: "65535",
	},
	"destination.port": {
		resolve:  func(n string, f *observation.Flow) (string, error) { return portValue(n, f.Destination.Port) },
		specimen: "65535",
	},
	"protocol": {
		resolve: func(n string, f *observation.Flow) (string, error) {
			if !slices.Contains(bpfProtocols, f.Protocol) {
				return "", fmt.Errorf("placeholder %q: %q is not a filterable protocol", n, f.Protocol)
			}
			return f.Protocol, nil
		},
		specimen: "tcp",
	},
}

// resolvePlaceholder returns the value for one documented placeholder name.
func resolvePlaceholder(name string, obs *observation.Observation) (string, error) {
	p, ok := placeholders[name]
	if !ok {
		return "", fmt.Errorf("unknown placeholder %q", name)
	}
	if obs.Flow == nil {
		return "", fmt.Errorf("placeholder %q: the observation carries no flow", name)
	}
	return p.resolve(name, obs.Flow)
}

// ipValue returns the address only if it parses as one.
//
// Parsing rather than escaping is the whole defense. BPF has no quoting to
// escape into, so a value carrying filter syntax cannot be neutralized - it can
// only be refused.
//
// netip.ParseAddr is not by itself that refusal. It accepts everything after a
// "%" in an IPv6 address as a zone, spaces and all, and String re-emits it
// verbatim: "fe80::1%or udp port 53" parses, round-trips unchanged, and lands
// in the expression the capture runner executes. The address in an observation
// describes traffic an attacker sends, and nothing validates it on the way in,
// so a crafted flow.source.ip would rewrite the filter of any policy using
// {{source.ip}} - widening a capture scoped to one conversation into whatever
// the injected clause names.
//
// A zone identifies a local interface. It is meaningless in a filter matching
// addresses seen on the wire, so there is no case to weigh against refusing it.
func ipValue(name, ip string) (string, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "", fmt.Errorf("placeholder %q: %q is not an IP address", name, ip)
	}
	if addr.Zone() != "" {
		return "", fmt.Errorf("placeholder %q: %q carries an IPv6 zone", name, ip)
	}
	// Re-rendered from the parsed value rather than passed through, so the
	// output is the canonical form of what was validated and not the original
	// bytes that happened to parse.
	return addr.String(), nil
}

func portValue(name string, port *int32) (string, error) {
	if port == nil {
		return "", fmt.Errorf("placeholder %q: the observation carries no port", name)
	}
	if *port < 0 || *port > 65535 {
		return "", fmt.Errorf("placeholder %q: %d is not a port number", name, *port)
	}
	return fmt.Sprint(*port), nil
}

// ValidateFilterTemplate checks a template without an event to render from.
//
// This is what the webhook calls when a policy is written. Deferring the check
// to render time would let an operator arm a policy that looks accepted and
// then fails at the only moment it mattered - when an alert fired and the
// capture did not start. The failure would be in the worker's logs, not on the
// object, so the policy would go on reporting itself armed.
//
// The placeholder names are checked against the same closed set RenderFilter
// substitutes from, so the two cannot drift into disagreeing about what is
// documented.
func ValidateFilterTemplate(template string) error {
	if len(template) > capture.MaxFilterBytes {
		return fmt.Errorf("filter template: longer than %d bytes", capture.MaxFilterBytes)
	}

	residual := placeholderRE.ReplaceAllStringFunc(template, func(match string) string {
		name := strings.TrimSpace(placeholderRE.FindStringSubmatch(match)[1])
		p, ok := placeholders[name]
		if !ok {
			// Left in place so the brace check below reports it.
			return match
		}
		// Substituted with a value of the right shape, so the remaining text is
		// checked as the filter it will become rather than as the template.
		return p.specimen
	})

	for _, match := range placeholderRE.FindAllStringSubmatch(residual, -1) {
		return fmt.Errorf("filter template: unknown placeholder %q", strings.TrimSpace(match[1]))
	}
	if strings.Contains(residual, "{{") || strings.Contains(residual, "}}") {
		return fmt.Errorf("filter template: unterminated placeholder")
	}
	if err := capture.ValidateFilterSyntax(residual); err != nil {
		return fmt.Errorf("filter template: %w", err)
	}
	return nil
}
