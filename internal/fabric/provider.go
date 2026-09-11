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

// Package fabric drives traffic mirroring on network devices outside the
// cluster.
//
// This is the only part of Trawl that writes to hardware it does not own, and
// the interface below is shaped by that rather than by what any one vendor's
// API happens to look like.
//
// # Observe is not optional, and it is not a convenience
//
// A provider must be able to read back what the device actually has, because
// the constitution requires status to describe observed reality rather than
// echo desired configuration. A mirror is reported Active because the device
// was asked and said yes - never because a write returned 200. Devices are
// edited by other people, roll back on reboot, and silently drop configuration
// they dislike; a controller that trusted its own writes would report coverage
// that stopped existing weeks ago, and the captures taken under it would be
// empty for a reason nobody could see.
//
// # Revert is the blast-radius control
//
// Deleting a PortMirror must put the device back, and a provider that cannot
// undo what it did should not be able to do it. Revert is expected to be
// idempotent and to tolerate a device that has already been changed by hand:
// the goal is "Trawl's mirror is gone", not "the device matches a snapshot".
//
// # What a provider must never do
//
// Touch anything but mirroring. The credentials available on real hardware are
// coarser than this restraint - RouterOS has no "may only set a mirror" policy
// - so the narrowness lives here, in code that can be read, rather than in a
// permission that cannot be expressed. A provider that also changed a VLAN, a
// firewall rule or a port state would be reusing a monitoring credential for
// something that is not monitoring, which is the line the constitution draws.
package fabric

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Direction selects which of a source port's traffic is copied.
type Direction string

const (
	DirectionBoth    Direction = "Both"
	DirectionIngress Direction = "Ingress"
	DirectionEgress  Direction = "Egress"
)

// Device is how to reach one piece of hardware.
//
// Assembled from a Secret by the caller; a provider never reads Kubernetes.
// That keeps the drivers testable without a cluster and keeps credential
// handling in one place rather than in every vendor package.
type Device struct {
	// Address is host or host:port.
	Address string

	// Username and Password authenticate to the device.
	Username string
	Password string

	// CACertPEM optionally pins the device's TLS certificate. Empty means the
	// system roots, which on a homelab switch with a self-signed certificate
	// means the connection will fail - deliberately, rather than silently
	// trusting whatever answered.
	CACertPEM []byte

	// InsecureSkipVerify disables certificate verification.
	//
	// Present because a factory RouterOS device serves a self-signed
	// certificate and pinning it is a step an operator has to take
	// deliberately. It is a field rather than a default so that turning it on
	// is visible in the object that did it.
	InsecureSkipVerify bool
}

// Mirror is the configuration being asked for.
type Mirror struct {
	Sources   []string
	Target    string
	Direction Direction
}

// State is what a device reports about its mirroring.
type State struct {
	// Sources and Target are what the device says is configured. Empty means
	// the device reports no mirror at all.
	Sources []string
	Target  string

	// Direction is what the device reports, where it distinguishes them.
	Direction Direction

	// Identity is the device's own description of itself - model and firmware
	// - recorded so an incident months later can tell which it was.
	Identity string
}

// Matches reports whether an observed state satisfies a requested mirror.
//
// Source order is not significant: devices return their own ordering and a
// controller that compared slices directly would report drift every time a
// switch felt like listing ports differently.
func (s State) Matches(m Mirror) bool {
	if s.Target != m.Target {
		return false
	}
	if len(s.Sources) != len(m.Sources) {
		return false
	}
	got := slices.Clone(s.Sources)
	want := slices.Clone(m.Sources)
	slices.Sort(got)
	slices.Sort(want)
	return slices.Equal(got, want)
}

// Provider drives one vendor's devices.
type Provider interface {
	// Name is the provider's stable identifier, matching the CRD enum.
	Name() string

	// Configure makes the device mirror as requested. It must be idempotent:
	// a controller reconciles repeatedly and applying a mirror that is already
	// in place is the common case, not the exception.
	Configure(ctx context.Context, d Device, m Mirror) error

	// Observe reads back what the device actually has.
	Observe(ctx context.Context, d Device) (State, error)

	// Revert removes Trawl's mirroring. Idempotent, and tolerant of a device
	// somebody has already changed.
	Revert(ctx context.Context, d Device) error
}

// ErrUnsupportedProvider is returned when no driver is registered for a name.
var ErrUnsupportedProvider = errors.New("no provider registered for this name")

// Registry maps provider names to drivers.
//
// Explicit construction rather than a package-level map with init()
// registration: a driver that registers itself on import is a driver that
// cannot be left out of a binary, and the whole point of keeping this narrow is
// being able to say which binaries can talk to switches at all.
type Registry struct {
	providers map[string]Provider
}

// NewRegistry returns a registry holding the given providers.
func NewRegistry(providers ...Provider) (*Registry, error) {
	r := &Registry{providers: make(map[string]Provider, len(providers))}
	for _, p := range providers {
		name := p.Name()
		if name == "" {
			return nil, errors.New("a provider reported an empty name")
		}
		if _, dup := r.providers[name]; dup {
			return nil, fmt.Errorf("two providers both named %q", name)
		}
		r.providers[name] = p
	}
	return r, nil
}

// Get returns the driver for a provider name.
func (r *Registry) Get(name string) (Provider, error) {
	p, ok := r.providers[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q (registered: %s)",
			ErrUnsupportedProvider, name, strings.Join(r.Names(), ", "))
	}
	return p, nil
}

// Names lists the registered providers, sorted.
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// Validate checks a mirror request before any device is contacted.
//
// The API server enforces these too. They are repeated here because a provider
// is also reachable from a test and from any future caller, and a request that
// tells a switch to mirror a port into itself should be refused by the code
// that would otherwise send it rather than only by the admission layer that
// usually precedes it.
func Validate(m Mirror) error {
	if len(m.Sources) == 0 {
		return errors.New("a mirror needs at least one source port")
	}
	if m.Target == "" {
		return errors.New("a mirror needs a target port")
	}
	if slices.Contains(m.Sources, m.Target) {
		return fmt.Errorf("target %q is also a source; a port mirroring into itself is a loop", m.Target)
	}
	seen := map[string]bool{}
	for _, s := range m.Sources {
		if s == "" {
			return errors.New("a mirror source port name is empty")
		}
		if seen[s] {
			return fmt.Errorf("source %q is listed twice", s)
		}
		seen[s] = true
	}
	switch m.Direction {
	case "", DirectionBoth, DirectionIngress, DirectionEgress:
	default:
		return fmt.Errorf("unknown mirror direction %q", m.Direction)
	}
	return nil
}
