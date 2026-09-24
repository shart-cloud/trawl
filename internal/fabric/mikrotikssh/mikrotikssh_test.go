package mikrotikssh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"trawl.cloud/trawl/internal/fabric"
	"trawl.cloud/trawl/internal/fabric/sshtransport"
)

type fakeRunner struct {
	board       string
	version     string
	switches    int
	target      string
	ports       map[string]port
	writes      []string
	failPortOne string
}

func newFake() *fakeRunner {
	return &fakeRunner{
		board: supportedBoard, version: "7.24.2 (stable)", switches: 1, target: "none",
		ports: map[string]port{
			"ether1": {name: "ether1"}, "ether2": {name: "ether2"},
			"ether24": {name: "ether24"},
		},
	}
}

func (f *fakeRunner) Close() error { return nil }

func (f *fakeRunner) Run(_ context.Context, command string) ([]byte, error) {
	switch {
	case strings.Contains(command, "/system resource print as-value"):
		return json.Marshal([]map[string]any{{"board-name": f.board, "version": f.version}})
	case strings.Contains(command, "/interface ethernet switch port print as-value"):
		rows := make([]map[string]any, 0, len(f.ports))
		for name, p := range f.ports {
			rows = append(rows, map[string]any{
				"name": name, "mirror-ingress": fmt.Sprint(p.ingress),
				"mirror-egress": fmt.Sprint(p.egress),
			})
		}
		return json.Marshal(rows)
	case strings.Contains(command, "/interface ethernet switch print as-value"):
		rows := make([]map[string]any, f.switches)
		for i := range rows {
			rows[i] = map[string]any{"name": fmt.Sprintf("switch%d", i+1), "mirror-target": f.target}
		}
		return json.Marshal(rows)
	case strings.Contains(command, "/interface ethernet switch port set"):
		name := named(command)
		if f.failPortOne == name {
			f.failPortOne = ""
			return nil, errors.New("temporary device failure")
		}
		p, ok := f.ports[name]
		if !ok {
			return nil, errors.New("unknown port")
		}
		p.ingress = strings.Contains(command, "mirror-ingress=yes")
		p.egress = strings.Contains(command, "mirror-egress=yes")
		f.ports[name] = p
		f.writes = append(f.writes, command)
		return nil, nil
	case strings.Contains(command, "/interface ethernet switch set"):
		if named(command) != "switch1" {
			return nil, errors.New("unknown switch")
		}
		marker := "mirror-target=\""
		start := strings.Index(command, marker)
		if start < 0 {
			return nil, errors.New("missing target")
		}
		rest := command[start+len(marker):]
		f.target = rest[:strings.Index(rest, "\"")]
		f.writes = append(f.writes, command)
		return nil, nil
	default:
		return nil, fmt.Errorf("unexpected command: %s", command)
	}
}

func named(command string) string {
	marker := "name=\""
	_, rest, ok := strings.Cut(command, marker)
	if !ok {
		return ""
	}
	name, _, _ := strings.Cut(rest, "\"")
	return name
}

func providerFor(f *fakeRunner) *Provider {
	return &Provider{Dial: func(context.Context, fabric.Device) (sshtransport.Runner, error) {
		return f, nil
	}}
}

func TestSSHProfileConfiguresReadsAndReverts(t *testing.T) {
	f := newFake()
	p := providerFor(f)
	want := fabric.Mirror{Sources: []string{"ether1", "ether2"}, Target: "ether24", Direction: fabric.DirectionBoth}
	if err := p.Configure(context.Background(), fabric.Device{}, want); err != nil {
		t.Fatalf("configure: %v", err)
	}
	got, err := p.Observe(context.Background(), fabric.Device{})
	if err != nil || !got.Matches(want) {
		t.Fatalf("readback: state=%+v error=%v", got, err)
	}
	if len(f.writes) != 3 {
		t.Fatalf("writes = %d, want target plus two ports", len(f.writes))
	}
	if err := p.Configure(context.Background(), fabric.Device{}, want); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(f.writes) != 3 {
		t.Fatal("reconcile rewrote an already matching device")
	}
	if err := p.Revert(context.Background(), fabric.Device{}); err != nil {
		t.Fatalf("revert: %v", err)
	}
	got, err = p.Observe(context.Background(), fabric.Device{})
	if err != nil || len(got.Sources) != 0 || got.Target != "" {
		t.Fatalf("revert readback: state=%+v error=%v", got, err)
	}
	afterRevert := len(f.writes)
	if err := p.Revert(context.Background(), fabric.Device{}); err != nil {
		t.Fatalf("second revert: %v", err)
	}
	if len(f.writes) != afterRevert {
		t.Fatal("idempotent revert rewrote the device")
	}
}

func TestSSHProfileClearsOldSourcesBeforeChangingTarget(t *testing.T) {
	f := newFake()
	f.target = "ether2"
	f.ports["ether1"] = port{name: "ether1", ingress: true, egress: true}
	want := fabric.Mirror{
		Sources: []string{"ether1"}, Target: "ether24", Direction: fabric.DirectionBoth,
	}
	if err := providerFor(f).Configure(context.Background(), fabric.Device{}, want); err != nil {
		t.Fatalf("change target: %v", err)
	}
	if len(f.writes) != 3 {
		t.Fatalf("writes = %d, want clear, retarget, then enable", len(f.writes))
	}
	if !strings.Contains(f.writes[0], "mirror-ingress=no mirror-egress=no") ||
		!strings.Contains(f.writes[1], "mirror-target=") ||
		!strings.Contains(f.writes[2], "mirror-ingress=yes mirror-egress=yes") {
		t.Errorf("unsafe target-change order: %v", f.writes)
	}
}
func TestSSHProfileRefusesUnsupportedDevicesBeforeWriting(t *testing.T) {
	for name, mutate := range map[string]func(*fakeRunner){
		"model":        func(f *fakeRunner) { f.board = "unknown" },
		"firmware":     func(f *fakeRunner) { f.version = "6.49" },
		"two chips":    func(f *fakeRunner) { f.switches = 2 },
		"missing port": func(f *fakeRunner) { delete(f.ports, "ether24") },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake()
			mutate(f)
			err := providerFor(f).Configure(context.Background(), fabric.Device{},
				fabric.Mirror{Sources: []string{"ether1"}, Target: "ether24", Direction: fabric.DirectionBoth})
			if err == nil {
				t.Fatal("unsupported device was accepted")
			}
			if len(f.writes) != 0 {
				t.Fatal("unsupported device was changed")
			}
		})
	}
}

func TestSSHProfileConvergesAfterAPartialWrite(t *testing.T) {
	f := newFake()
	f.failPortOne = "ether2"
	p := providerFor(f)
	want := fabric.Mirror{Sources: []string{"ether1", "ether2"}, Target: "ether24", Direction: fabric.DirectionBoth}
	if err := p.Configure(context.Background(), fabric.Device{}, want); err == nil {
		t.Fatal("partial write reported success")
	}
	got, err := p.Observe(context.Background(), fabric.Device{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Matches(want) {
		t.Fatal("partial mirror reported complete")
	}
	if err := p.Configure(context.Background(), fabric.Device{}, want); err != nil {
		t.Fatalf("retry did not converge: %v", err)
	}
	got, err = p.Observe(context.Background(), fabric.Device{})
	if err != nil || !got.Matches(want) {
		t.Fatalf("retry readback: state=%+v error=%v", got, err)
	}
}
