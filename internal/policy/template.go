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

// resolvePlaceholder returns the value for one documented placeholder name.
func resolvePlaceholder(name string, obs *observation.Observation) (string, error) {
	flow := obs.Flow
	if flow == nil {
		return "", fmt.Errorf("placeholder %q: the observation carries no flow", name)
	}

	switch name {
	case "source.ip":
		return ipValue(name, flow.Source.IP)
	case "destination.ip":
		return ipValue(name, flow.Destination.IP)
	case "source.port":
		return portValue(name, flow.Source.Port)
	case "destination.port":
		return portValue(name, flow.Destination.Port)
	case "protocol":
		if !slices.Contains(bpfProtocols, flow.Protocol) {
			return "", fmt.Errorf("placeholder %q: %q is not a filterable protocol", name, flow.Protocol)
		}
		return flow.Protocol, nil
	default:
		return "", fmt.Errorf("unknown placeholder %q", name)
	}
}

// ipValue returns the address only if it parses as one.
//
// Parsing rather than escaping is the whole defense. BPF has no quoting to
// escape into, so a value carrying filter syntax cannot be neutralized - it can
// only be refused. netip.ParseAddr accepts an address and nothing else: no
// spaces, no operators, no hostname.
func ipValue(name, ip string) (string, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "", fmt.Errorf("placeholder %q: %q is not an IP address", name, ip)
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
