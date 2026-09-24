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

// Package mikrotik drives port mirroring on RouterOS 7 switches through the
// REST API.
//
// Written against a real CRS328-24P-4S+ running RouterOS 7.24.2 (switch chip
// Marvell-98DX3236) rather than from the documentation, because the shape is
// not what a reading of the docs suggests and the difference matters:
//
//	GET /rest/interface/ethernet/switch        -> one object, carries mirror-target
//	GET /rest/interface/ethernet/switch/port   -> one object per port, each
//	                                              carrying mirror-ingress and
//	                                              mirror-egress booleans
//
// **There is no mirror-source field.** A mirror with four source ports is four
// separate writes to four port objects plus one write to the switch object, and
// three of them can succeed while the fourth fails. That single fact drives most
// of what follows: Configure is not atomic, so it cannot report success from its
// own writes, and Observe reading the device back is the only thing that knows
// what is really configured.
//
// Ports are addressed by RouterOS's own `.id` (`*2`, `*3`, …), never by name.
// Operators write names in a PortMirror and every call resolves name to id
// against the live device: ids are not guaranteed stable across reboots or
// configuration changes, and a cached one would eventually configure the wrong
// physical port while reporting success.
package mikrotik

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"trawl.cloud/trawl/internal/fabric"
	"trawl.cloud/trawl/internal/sanitize"
)

// ProviderName matches the CRD's MirrorProvider enum.
const ProviderName = "MikroTikRouterOS7"

// What RouterOS puts in these fields. Booleans come back as strings, and an
// unset mirror target is the literal word "none" rather than an absent field -
// a driver checking for emptiness would report a mirror targeting a port
// called "none".
const (
	noMirrorTarget = "none"
	routerOSTrue   = "true"
	routerOSFalse  = "false"
)

// requestTimeout bounds one REST call.
//
// Short on purpose. A switch that has stopped answering should surface as a
// Degraded mirror within a reconcile, not hold a controller worker while an
// operator wonders why nothing is reconciling.
const requestTimeout = 15 * time.Second

// Provider implements fabric.Provider for RouterOS 7.
type Provider struct {
	// NewClient overrides HTTP client construction in tests.
	NewClient func(d fabric.Device) (*http.Client, error)
}

// New returns a RouterOS 7 provider.
func New() *Provider { return &Provider{} }

// Name identifies this driver.
func (p *Provider) Name() string { return ProviderName }

// RouterOS field names. Decoding goes through map[string]any rather than
// structs: the identity field is literally ".id", and a Go struct tag with a
// leading dot is a trap for whoever edits it next.
const (
	idField      = ".id"
	nameField    = "name"
	targetField  = "mirror-target"
	ingressField = "mirror-ingress"
	egressField  = "mirror-egress"
)

// Observe reads back what the device actually has.
func (p *Provider) Observe(ctx context.Context, d fabric.Device) (fabric.State, error) {
	client, base, err := p.connect(d)
	if err != nil {
		return fabric.State{}, err
	}

	identity, err := p.identity(ctx, client, base, d)
	if err != nil {
		return fabric.State{}, err
	}

	switches, err := p.get(ctx, client, base, d, "/rest/interface/ethernet/switch")
	if err != nil {
		return fabric.State{}, fmt.Errorf("reading the switch: %w", err)
	}
	if len(switches) == 0 {
		return fabric.State{}, errors.New("the device reports no switch object, so it has no mirroring to configure")
	}
	target := stringField(switches[0], targetField)
	if target == noMirrorTarget {
		target = ""
	}

	ports, err := p.get(ctx, client, base, d, "/rest/interface/ethernet/switch/port")
	if err != nil {
		return fabric.State{}, fmt.Errorf("reading the switch ports: %w", err)
	}

	// Direction is derived from the ports rather than assumed. A device where
	// somebody set ingress on one port and egress on another is reported as
	// Both, which is honest: it is not the configuration any single request
	// would produce, and the mismatch is what tells a controller to reconcile.
	var sources []string
	var anyIngress, anyEgress bool
	sourceDirections := make(map[string]fabric.Direction)
	for _, port := range ports {
		in := stringField(port, ingressField) == routerOSTrue
		eg := stringField(port, egressField) == routerOSTrue
		if !in && !eg {
			continue
		}
		anyIngress = anyIngress || in
		anyEgress = anyEgress || eg
		name := stringField(port, nameField)
		sources = append(sources, name)
		switch {
		case in && eg:
			sourceDirections[name] = fabric.DirectionBoth
		case in:
			sourceDirections[name] = fabric.DirectionIngress
		case eg:
			sourceDirections[name] = fabric.DirectionEgress
		}
	}

	state := fabric.State{
		Sources:          sources,
		Target:           target,
		SourceDirections: sourceDirections,
		Identity:         identity,
	}
	switch {
	case anyIngress && anyEgress:
		state.Direction = fabric.DirectionBoth
	case anyIngress:
		state.Direction = fabric.DirectionIngress
	case anyEgress:
		state.Direction = fabric.DirectionEgress
	}
	return state, nil
}

// Configure makes the device mirror as requested.
//
// Idempotent by construction: every write is preceded by a read of the current
// value and skipped when it already matches. That is not an optimisation - a
// controller reconciles repeatedly, and a driver that wrote unconditionally
// would produce a device-configuration event on the switch every few seconds
// for as long as a PortMirror existed.
func (p *Provider) Configure(ctx context.Context, d fabric.Device, m fabric.Mirror) error {
	if err := fabric.Validate(m); err != nil {
		return err
	}
	client, base, err := p.connect(d)
	if err != nil {
		return err
	}

	switches, err := p.get(ctx, client, base, d, "/rest/interface/ethernet/switch")
	if err != nil {
		return fmt.Errorf("reading the switch: %w", err)
	}
	if len(switches) == 0 {
		return errors.New("the device reports no switch object")
	}

	ports, err := p.get(ctx, client, base, d, "/rest/interface/ethernet/switch/port")
	if err != nil {
		return fmt.Errorf("reading the switch ports: %w", err)
	}
	byName := make(map[string]map[string]any, len(ports))
	for _, port := range ports {
		byName[stringField(port, nameField)] = port
	}

	// Every named port must exist before anything is written. A request naming
	// one absent port would otherwise configure the others and fail half way,
	// leaving the device mirroring a subset nobody asked for.
	if _, ok := byName[m.Target]; !ok {
		return fmt.Errorf("target port %q is not a switch port on this device", sanitize.String(m.Target))
	}
	for _, source := range m.Sources {
		if _, ok := byName[source]; !ok {
			return fmt.Errorf("source port %q is not a switch port on this device", sanitize.String(source))
		}
	}

	wantIngress := m.Direction == fabric.DirectionIngress || m.Direction == fabric.DirectionBoth || m.Direction == ""
	wantEgress := m.Direction == fabric.DirectionEgress || m.Direction == fabric.DirectionBoth || m.Direction == ""

	// The target first. A device that accepts the sources and then refuses the
	// target would be copying traffic to whatever the previous target was,
	// which is a worse state than not mirroring at all.
	if stringField(switches[0], targetField) != m.Target {
		if err := p.patch(ctx, client, base, d,
			"/rest/interface/ethernet/switch/"+stringField(switches[0], idField),
			map[string]any{targetField: m.Target}); err != nil {
			return fmt.Errorf("setting the mirror target to %q: %w", sanitize.String(m.Target), err)
		}
	}

	wanted := make(map[string]bool, len(m.Sources))
	for _, source := range m.Sources {
		wanted[source] = true
	}

	for name, port := range byName {
		in, eg := wantIngress && wanted[name], wantEgress && wanted[name]
		hasIn := stringField(port, ingressField) == routerOSTrue
		hasEg := stringField(port, egressField) == routerOSTrue
		if in == hasIn && eg == hasEg {
			continue
		}
		// Ports not in the request are cleared as well as ports in it being
		// set. A PortMirror describes the device's whole mirror, not an
		// addition to whatever was there - otherwise removing a source from
		// the spec would leave it mirroring.
		if err := p.patch(ctx, client, base, d,
			"/rest/interface/ethernet/switch/port/"+stringField(port, idField),
			map[string]any{
				ingressField: fmt.Sprintf("%t", in),
				egressField:  fmt.Sprintf("%t", eg),
			}); err != nil {
			return fmt.Errorf("setting mirroring on port %q: %w", sanitize.String(name), err)
		}
	}
	return nil
}

// Revert removes Trawl's mirroring.
//
// Clears every mirrored port rather than only the ones a particular spec named,
// and tolerates a device somebody has already changed. The goal is "this device
// is not mirroring", not "this device matches a snapshot taken earlier".
func (p *Provider) Revert(ctx context.Context, d fabric.Device) error {
	client, base, err := p.connect(d)
	if err != nil {
		return err
	}

	ports, err := p.get(ctx, client, base, d, "/rest/interface/ethernet/switch/port")
	if err != nil {
		return fmt.Errorf("reading the switch ports: %w", err)
	}
	for _, port := range ports {
		if stringField(port, ingressField) != routerOSTrue && stringField(port, egressField) != routerOSTrue {
			continue
		}
		if err := p.patch(ctx, client, base, d,
			"/rest/interface/ethernet/switch/port/"+stringField(port, idField),
			map[string]any{ingressField: routerOSFalse, egressField: routerOSFalse}); err != nil {
			return fmt.Errorf("clearing mirroring on port %q: %w",
				sanitize.String(stringField(port, nameField)), err)
		}
	}

	switches, err := p.get(ctx, client, base, d, "/rest/interface/ethernet/switch")
	if err != nil {
		return fmt.Errorf("reading the switch: %w", err)
	}
	if len(switches) == 0 {
		return nil
	}
	if stringField(switches[0], targetField) == noMirrorTarget {
		return nil
	}
	if err := p.patch(ctx, client, base, d,
		"/rest/interface/ethernet/switch/"+stringField(switches[0], idField),
		map[string]any{targetField: noMirrorTarget}); err != nil {
		return fmt.Errorf("clearing the mirror target: %w", err)
	}
	return nil
}

// identity asks the device what it is.
func (p *Provider) identity(ctx context.Context, c *http.Client, base string, d fabric.Device) (string, error) {
	body, err := p.do(ctx, c, http.MethodGet, base+"/rest/system/resource", d, nil)
	if err != nil {
		return "", fmt.Errorf("reading the device identity: %w", err)
	}
	var res map[string]any
	if err := json.Unmarshal(body, &res); err != nil {
		return "", fmt.Errorf("decoding the device identity: %w", err)
	}
	return strings.TrimSpace(fmt.Sprintf("%s %s",
		stringField(res, "board-name"), stringField(res, "version"))), nil
}

func (p *Provider) get(ctx context.Context, c *http.Client, base string, d fabric.Device, path string) ([]map[string]any, error) {
	body, err := p.do(ctx, c, http.MethodGet, base+path, d, nil)
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", path, err)
	}
	return out, nil
}

func (p *Provider) patch(ctx context.Context, c *http.Client, base string, d fabric.Device, path string, payload map[string]any) error {
	// The id is sent raw. RouterOS ids look like "*0" and the device rejects a
	// percent-encoded one with "missing or invalid resource identifier" - it
	// does not decode the path segment. Escaping it was the obvious thing to
	// do and it is wrong; verified against the device both ways.
	//
	// That leaves the id unescaped in a URL, so it is checked instead: RouterOS
	// ids are '*' followed by hex, and anything else is refused here rather
	// than concatenated into a request path.
	cut := strings.LastIndex(path, "/")
	if id := path[cut+1:]; !validRouterOSID(id) {
		return fmt.Errorf("refusing to address %q: not a RouterOS id", sanitize.String(id))
	}
	_, err := p.do(ctx, c, http.MethodPatch, base+path, d, payload)
	return err
}

func (p *Provider) do(ctx context.Context, c *http.Client, method, endpoint string, d fabric.Device, payload map[string]any) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	var body *bytes.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("encoding the request: %w", err)
		}
		body = bytes.NewReader(encoded)
	} else {
		body = bytes.NewReader(nil)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("building the request: %w", err)
	}
	req.SetBasicAuth(d.Username, d.Password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Do(req)
	if err != nil {
		// Sanitized: a transport error can carry the URL, and the URL is the
		// device address an operator may not want in a status message.
		return nil, fmt.Errorf("calling the device: %w", sanitize.Error(err))
	}
	defer func() { _ = resp.Body.Close() }()

	out := make([]byte, 0, 8192)
	buf := make([]byte, 4096)
	for {
		n, readErr := resp.Body.Read(buf)
		out = append(out, buf[:n]...)
		if readErr != nil {
			break
		}
		// A device that answered with something enormous is a device doing
		// something unexpected; refusing is better than filling memory.
		if len(out) > 1<<20 {
			return nil, errors.New("the device returned more than 1MiB, which no mirror query should")
		}
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("the device refused the credential (%s); RouterOS needs a user whose "+
			"group carries the rest-api policy, and write for configuration", resp.Status)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("the device answered %s: %s", resp.Status, sanitize.String(string(out)))
	}
	return out, nil
}

// connect builds the HTTP client and base URL for a device.
func (p *Provider) connect(d fabric.Device) (*http.Client, string, error) {
	if d.Address == "" {
		return nil, "", errors.New("the device has no address")
	}
	if d.Username == "" || d.Password == "" {
		return nil, "", errors.New("the device credential is incomplete")
	}

	if p.NewClient != nil {
		c, err := p.NewClient(d)
		return c, baseURL(d.Address), err
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12} //nolint:gosec // InsecureSkipVerify is set below, deliberately and visibly.
	switch {
	case len(d.CACertPEM) > 0:
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(d.CACertPEM) {
			return nil, "", errors.New("the device CA certificate is not valid PEM")
		}
		tlsConfig.RootCAs = pool
	case d.InsecureSkipVerify:
		// A factory RouterOS device serves a self-signed certificate. This is
		// opt-in per device rather than a default, so that an installation
		// trusting whatever answers is visible in the object that chose it.
		tlsConfig.InsecureSkipVerify = true
	}

	return &http.Client{
		Timeout:   requestTimeout,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}, baseURL(d.Address), nil
}

func baseURL(address string) string {
	if strings.HasPrefix(address, "http://") || strings.HasPrefix(address, "https://") {
		return strings.TrimSuffix(address, "/")
	}
	return "https://" + strings.TrimSuffix(address, "/")
}

// validRouterOSID reports whether an id is the shape RouterOS issues: a '*'
// followed by lowercase hex. Anything else is not something this driver built,
// and is refused rather than interpolated into a request path.
func validRouterOSID(id string) bool {
	if len(id) < 2 || id[0] != '*' {
		return false
	}
	for _, r := range id[1:] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

// stringField reads a field that RouterOS may return as a string or a bool.
//
// RouterOS is inconsistent about this between releases and between endpoints,
// and a driver that assumed one would break on an upgrade in a way that looks
// like the mirror silently not being configured.
func stringField(m map[string]any, key string) string {
	switch v := m[key].(type) {
	case string:
		return v
	case bool:
		return fmt.Sprintf("%t", v)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", v)
	}
}

// Compile-time assertion that this satisfies the interface.
var _ fabric.Provider = (*Provider)(nil)
