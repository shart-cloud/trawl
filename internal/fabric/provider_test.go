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

package fabric

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// stub is a provider that records what it was asked and answers as told.
type stub struct {
	name     string
	state    State
	observed int
}

func (s *stub) Name() string                                    { return s.name }
func (s *stub) Configure(context.Context, Device, Mirror) error { return nil }
func (s *stub) Revert(context.Context, Device) error            { return nil }
func (s *stub) Observe(context.Context, Device) (State, error) {
	s.observed++
	return s.state, nil
}

func TestValidateRefusesAPortMirroringIntoItself(t *testing.T) {
	// The loop a switch will happily configure. It is checked here as well as
	// by the CRD because a provider is reachable from a test and from any
	// later caller, and the code that would send the command is the last place
	// that can decline to.
	err := Validate(Mirror{Sources: []string{"ether1", "ether24"}, Target: "ether24"})
	if err == nil {
		t.Fatal("a mirror whose target is also a source was accepted")
	}
	if !strings.Contains(err.Error(), "loop") {
		t.Errorf("the refusal does not say why it matters: %v", err)
	}
}

func TestValidateRefusesAnEmptyOrDuplicatedSource(t *testing.T) {
	for name, m := range map[string]Mirror{
		"no sources":       {Target: "ether24"},
		"no target":        {Sources: []string{"ether1"}},
		"empty source":     {Sources: []string{"ether1", ""}, Target: "ether24"},
		"duplicate source": {Sources: []string{"ether1", "ether1"}, Target: "ether24"},
		"unknown direction": {
			Sources: []string{"ether1"}, Target: "ether24", Direction: Direction("Sideways"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := Validate(m); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestValidateAcceptsAWorkableMirror(t *testing.T) {
	// The control. Every rejection above only means something if the
	// otherwise-ordinary request is accepted in the same breath.
	if err := Validate(Mirror{
		Sources: []string{"ether1", "ether2"}, Target: "ether24", Direction: DirectionBoth,
	}); err != nil {
		t.Fatalf("an ordinary mirror was refused: %v", err)
	}
	// An absent direction is the defaulted case and must not be refused.
	if err := Validate(Mirror{Sources: []string{"ether1"}, Target: "ether24"}); err != nil {
		t.Fatalf("a mirror with no explicit direction was refused: %v", err)
	}
}

func TestObservedStateMatchesRegardlessOfSourceOrder(t *testing.T) {
	// Devices return their own ordering. A controller comparing slices
	// directly would report drift every time a switch listed its ports
	// differently, and an operator who saw Degraded for that reason twice
	// would stop reading the field.
	want := Mirror{Sources: []string{"ether1", "ether2"}, Target: "ether24"}
	got := State{Sources: []string{"ether2", "ether1"}, Target: "ether24"}
	if !got.Matches(want) {
		t.Error("the same mirror in a different order was reported as drift")
	}
}

func TestObservedStateDoesNotMatchADifferentMirror(t *testing.T) {
	want := Mirror{Sources: []string{"ether1", "ether2"}, Target: "ether24"}
	for name, got := range map[string]State{
		"different target": {Sources: []string{"ether1", "ether2"}, Target: "ether23"},
		"missing source":   {Sources: []string{"ether1"}, Target: "ether24"},
		"extra source":     {Sources: []string{"ether1", "ether2", "ether3"}, Target: "ether24"},
		"no mirror at all": {},
	} {
		t.Run(name, func(t *testing.T) {
			if got.Matches(want) {
				t.Error("reported as matching")
			}
		})
	}
}

func TestRegistryRefusesTwoProvidersWithOneName(t *testing.T) {
	// Two drivers under one name means the binary sends one vendor's
	// configuration to whichever registered last. Refused at construction
	// rather than discovered on a switch.
	if _, err := NewRegistry(&stub{name: "dup"}, &stub{name: "dup"}); err == nil {
		t.Fatal("a registry accepted two providers with the same name")
	}
	if _, err := NewRegistry(&stub{name: ""}); err == nil {
		t.Fatal("a registry accepted a provider with no name")
	}
}

func TestRegistryNamesWhatItHasWhenAskedForWhatItDoesNot(t *testing.T) {
	// The error an operator sees after a typo in spec.provider. Listing what
	// is available turns "unsupported" into a one-line fix.
	r, err := NewRegistry(&stub{name: "MikroTikRouterOS7"})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	_, err = r.Get("MikroTikRouterOs7")
	if !errors.Is(err, ErrUnsupportedProvider) {
		t.Fatalf("error = %v, want ErrUnsupportedProvider", err)
	}
	if !strings.Contains(err.Error(), "MikroTikRouterOS7") {
		t.Errorf("the error does not name the providers that do exist: %v", err)
	}
}
