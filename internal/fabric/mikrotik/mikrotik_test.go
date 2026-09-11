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

package mikrotik

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trawl.cloud/trawl/internal/fabric"
)

// fakeRouterOS serves the shapes a real CRS328-24P-4S+ running RouterOS 7.24.2
// returned, including its quirks: booleans come back as the strings "true" and
// "false", an unset mirror target is the string "none", and the identity field
// is ".id" holding values like "*2".
//
// Built from recorded responses rather than invented. A fake shaped the way the
// documentation suggests would have had a mirror-source field, and every test
// against it would have passed while the driver did nothing on real hardware.
type fakeRouterOS struct {
	target string
	ports  map[string]*fakePort // by name
	writes []string             // paths patched, in order
	fail   map[string]int       // path -> status to answer with
}

type fakePort struct {
	id      string
	ingress bool
	egress  bool
}

func newFake() *fakeRouterOS {
	return &fakeRouterOS{
		target: "none",
		ports: map[string]*fakePort{
			"ether1":  {id: "*2"},
			"ether2":  {id: "*3"},
			"ether3":  {id: "*4"},
			"ether24": {id: "*19"},
			"sfp1":    {id: "*1a"},
		},
		fail: map[string]int{},
	}
}

func (f *fakeRouterOS) portByID(id string) *fakePort {
	for _, p := range f.ports {
		if p.id == id {
			return p
		}
	}
	return nil
}

func (f *fakeRouterOS) start(t *testing.T) fabric.Device {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := r.BasicAuth(); !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if status, bad := f.fail[r.URL.Path]; bad {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":` + http.StatusText(status) + `}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.URL.Path == "/rest/system/resource":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"board-name": "CRS328-24P-4S+", "version": "7.24.2 (stable)",
			})

		case r.URL.Path == "/rest/interface/ethernet/switch" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				".id": "*0", "name": "switch1", "type": "Marvell-98DX3236",
				"mirror-target": f.target,
			}})

		case r.URL.Path == "/rest/interface/ethernet/switch/port" && r.Method == http.MethodGet:
			out := make([]map[string]any, 0, len(f.ports))
			for name, p := range f.ports {
				out = append(out, map[string]any{
					".id": p.id, "name": name,
					"mirror-ingress": boolString(p.ingress),
					"mirror-egress":  boolString(p.egress),
				})
			}
			_ = json.NewEncoder(w).Encode(out)

		case r.Method == http.MethodPatch:
			f.writes = append(f.writes, r.URL.Path)
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)

			id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			if strings.HasPrefix(r.URL.Path, "/rest/interface/ethernet/switch/port/") {
				if p := f.portByID(id); p != nil {
					if v, ok := body["mirror-ingress"]; ok {
						p.ingress = v == "true" || v == true
					}
					if v, ok := body["mirror-egress"]; ok {
						p.egress = v == "true" || v == true
					}
				}
			} else if v, ok := body["mirror-target"].(string); ok {
				f.target = v
			}
			_, _ = w.Write([]byte(`{}`))

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return fabric.Device{Address: srv.URL, Username: "trawl", Password: "secret"}
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func provider() *Provider {
	p := New()
	p.NewClient = func(fabric.Device) (*http.Client, error) { return http.DefaultClient, nil }
	return p
}

func TestObserveReportsNoMirrorWhenTheTargetIsNone(t *testing.T) {
	// The device's factory state, and the one this switch was actually in:
	// mirror-target "none" with every port false. "none" is a string, not an
	// absent field, so a driver checking for emptiness would report a mirror
	// targeting a port literally called "none".
	f := newFake()
	dev := f.start(t)

	state, err := provider().Observe(context.Background(), dev)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if state.Target != "" {
		t.Errorf("target = %q, want empty for an unconfigured device", state.Target)
	}
	if len(state.Sources) != 0 {
		t.Errorf("sources = %v, want none", state.Sources)
	}
	if !strings.Contains(state.Identity, "CRS328") {
		t.Errorf("identity = %q, does not name the device", state.Identity)
	}
}

func TestConfigureSetsTheTargetAndOnlyTheNamedSources(t *testing.T) {
	f := newFake()
	dev := f.start(t)

	err := provider().Configure(context.Background(), dev, fabric.Mirror{
		Sources: []string{"ether1", "ether2"}, Target: "ether24", Direction: fabric.DirectionBoth,
	})
	if err != nil {
		t.Fatalf("Configure: %v", err)
	}

	if f.target != "ether24" {
		t.Errorf("mirror-target = %q, want ether24", f.target)
	}
	for name, want := range map[string]bool{
		"ether1": true, "ether2": true, "ether3": false, "ether24": false, "sfp1": false,
	} {
		p := f.ports[name]
		if p.ingress != want || p.egress != want {
			t.Errorf("%s: ingress=%v egress=%v, want both %v", name, p.ingress, p.egress, want)
		}
	}
}

func TestConfigureIsIdempotent(t *testing.T) {
	// A controller reconciles repeatedly. A driver that wrote unconditionally
	// would produce a configuration-change event on the switch every few
	// seconds for as long as a PortMirror existed, which is noise in somebody
	// else's audit log.
	f := newFake()
	dev := f.start(t)
	m := fabric.Mirror{Sources: []string{"ether1"}, Target: "ether24", Direction: fabric.DirectionIngress}

	if err := provider().Configure(context.Background(), dev, m); err != nil {
		t.Fatalf("first Configure: %v", err)
	}
	first := len(f.writes)
	if first == 0 {
		t.Fatal("the first Configure wrote nothing")
	}

	if err := provider().Configure(context.Background(), dev, m); err != nil {
		t.Fatalf("second Configure: %v", err)
	}
	if len(f.writes) != first {
		t.Errorf("the second Configure wrote %d more times; it is not idempotent",
			len(f.writes)-first)
	}
}

func TestConfigureClearsAPortDroppedFromTheSpec(t *testing.T) {
	// A PortMirror describes the whole mirror, not an addition to it. Removing
	// a source from the spec has to stop that port mirroring, or the device
	// keeps copying traffic nobody asked for any more.
	f := newFake()
	dev := f.start(t)
	p := provider()

	if err := p.Configure(context.Background(), dev, fabric.Mirror{
		Sources: []string{"ether1", "ether2"}, Target: "ether24",
	}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if err := p.Configure(context.Background(), dev, fabric.Mirror{
		Sources: []string{"ether1"}, Target: "ether24",
	}); err != nil {
		t.Fatalf("narrowing Configure: %v", err)
	}
	if f.ports["ether2"].ingress || f.ports["ether2"].egress {
		t.Error("ether2 is still mirroring after being dropped from the spec")
	}
	if !f.ports["ether1"].ingress {
		t.Error("ether1 stopped mirroring when ether2 was dropped")
	}
}

func TestConfigureRefusesAPortTheDeviceDoesNotHave(t *testing.T) {
	// Checked before anything is written. A request naming one absent port
	// would otherwise configure the others and fail half way, leaving the
	// device mirroring a subset nobody asked for.
	f := newFake()
	dev := f.start(t)

	err := provider().Configure(context.Background(), dev, fabric.Mirror{
		Sources: []string{"ether1", "ether99"}, Target: "ether24",
	})
	if err == nil {
		t.Fatal("a mirror naming a port the device does not have was accepted")
	}
	if len(f.writes) != 0 {
		t.Errorf("it wrote %d times before refusing: %v", len(f.writes), f.writes)
	}
}

func TestObserveReportsWhatTheDeviceHasNotWhatWasAsked(t *testing.T) {
	// Somebody changed the switch by hand. Observe must report their change,
	// because that difference is the only thing that tells a controller the
	// device drifted - and status claiming the spec would hide it forever.
	f := newFake()
	dev := f.start(t)
	f.target = "sfp1"
	f.ports["ether3"].ingress = true

	state, err := provider().Observe(context.Background(), dev)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if state.Target != "sfp1" {
		t.Errorf("target = %q, want the sfp1 somebody set by hand", state.Target)
	}
	if state.Matches(fabric.Mirror{Sources: []string{"ether1"}, Target: "ether24"}) {
		t.Error("a hand-edited device was reported as matching the spec")
	}
}

func TestRevertClearsEveryMirroredPortAndTheTarget(t *testing.T) {
	f := newFake()
	dev := f.start(t)
	p := provider()

	if err := p.Configure(context.Background(), dev, fabric.Mirror{
		Sources: []string{"ether1", "ether2"}, Target: "ether24",
	}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	// Somebody else's mirroring, which Revert must also clear: the goal is
	// "this device is not mirroring", not "undo exactly my writes".
	f.ports["ether3"].egress = true

	if err := p.Revert(context.Background(), dev); err != nil {
		t.Fatalf("Revert: %v", err)
	}
	if f.target != "none" {
		t.Errorf("mirror-target = %q after Revert, want none", f.target)
	}
	for name, port := range f.ports {
		if port.ingress || port.egress {
			t.Errorf("%s is still mirroring after Revert", name)
		}
	}
}

func TestRevertOnAnAlreadyCleanDeviceWritesNothing(t *testing.T) {
	// Idempotent, and quiet about it. Deleting a PortMirror on a device
	// somebody already reset should not generate configuration churn.
	f := newFake()
	dev := f.start(t)

	if err := provider().Revert(context.Background(), dev); err != nil {
		t.Fatalf("Revert: %v", err)
	}
	if len(f.writes) != 0 {
		t.Errorf("Revert wrote %d times to an already-clean device: %v", len(f.writes), f.writes)
	}
}

func TestARefusedCredentialSaysWhatRouterOSNeeds(t *testing.T) {
	// The error an operator sees when the RouterOS group lacks rest-api. It
	// names the policy because "403" alone sends people to the firewall.
	f := newFake()
	f.fail["/rest/system/resource"] = http.StatusForbidden
	dev := f.start(t)

	_, err := provider().Observe(context.Background(), dev)
	if err == nil {
		t.Fatal("a forbidden device was reported as observable")
	}
	if !strings.Contains(err.Error(), "rest-api") {
		t.Errorf("the error does not say which RouterOS policy is missing: %v", err)
	}
}
