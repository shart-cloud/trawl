package mikrotikssh

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"trawl.cloud/trawl/internal/fabric"
	"trawl.cloud/trawl/internal/fabric/sshtransport"
	"trawl.cloud/trawl/internal/sanitize"
)

const ProviderName = "MikroTikRouterOS7SSH"
const supportedBoard = "CRS328-24P-4S+"
const noMirrorTarget = "none"

// Dialer permits a fake command runner in tests while production uses the
// shared, host-key-verified SSH transport.
type Dialer func(context.Context, fabric.Device) (sshtransport.Runner, error)

type Provider struct {
	Dial Dialer
}

func New() *Provider             { return &Provider{} }
func (p *Provider) Name() string { return ProviderName }

func (p *Provider) connect(ctx context.Context, d fabric.Device) (sshtransport.Runner, error) {
	if p.Dial != nil {
		return p.Dial(ctx, d)
	}
	return sshtransport.Dial(ctx, d)
}

type port struct {
	name    string
	ingress bool
	egress  bool
}

type snapshot struct {
	state      fabric.State
	switchName string
	ports      map[string]port
}

func (p *Provider) Observe(ctx context.Context, d fabric.Device) (fabric.State, error) {
	runner, err := p.connect(ctx, d)
	if err != nil {
		return fabric.State{}, err
	}
	defer func() { _ = runner.Close() }()
	got, err := readSnapshot(ctx, runner)
	if err != nil {
		return fabric.State{}, err
	}
	return got.state, nil
}

func (p *Provider) Configure(ctx context.Context, d fabric.Device, want fabric.Mirror) error {
	if err := fabric.Validate(want); err != nil {
		return err
	}
	runner, err := p.connect(ctx, d)
	if err != nil {
		return err
	}
	defer func() { _ = runner.Close() }()
	got, err := readSnapshot(ctx, runner)
	if err != nil {
		return err
	}
	if _, ok := got.ports[want.Target]; !ok {
		return fmt.Errorf("%w: target port %q is not on the switch", fabric.ErrUnsupportedDevice, sanitize.String(want.Target))
	}
	for _, name := range want.Sources {
		if _, ok := got.ports[name]; !ok {
			return fmt.Errorf("%w: source port %q is not on the switch", fabric.ErrUnsupportedDevice, sanitize.String(name))
		}
	}
	if got.state.Matches(want) {
		return nil
	}
	names := make([]string, 0, len(got.ports))
	for name := range got.ports {
		names = append(names, name)
	}
	slices.Sort(names)
	if got.state.Target != want.Target {
		// Remove old sources before changing the destination so a partial
		// update cannot copy them to the newly selected target.
		for _, name := range names {
			current := got.ports[name]
			if !current.ingress && !current.egress {
				continue
			}
			if err := setPort(ctx, runner, name, false, false); err != nil {
				return err
			}
			current.ingress, current.egress = false, false
			got.ports[name] = current
		}
		if err := setSwitchTarget(ctx, runner, got.switchName, want.Target); err != nil {
			return err
		}
	}
	wanted := make(map[string]bool, len(want.Sources))
	for _, name := range want.Sources {
		wanted[name] = true
	}
	direction := want.Direction
	if direction == "" {
		direction = fabric.DirectionBoth
	}
	for _, name := range names {
		current := got.ports[name]
		in := wanted[name] && (direction == fabric.DirectionBoth || direction == fabric.DirectionIngress)
		eg := wanted[name] && (direction == fabric.DirectionBoth || direction == fabric.DirectionEgress)
		if current.ingress == in && current.egress == eg {
			continue
		}
		if err := setPort(ctx, runner, name, in, eg); err != nil {
			return err
		}
	}
	after, err := readSnapshot(ctx, runner)
	if err != nil {
		return fmt.Errorf("reading back the configured mirror: %w", err)
	}
	if !after.state.Matches(want) {
		return errors.New("device readback does not match the requested mirror")
	}
	return nil
}

func (p *Provider) Revert(ctx context.Context, d fabric.Device) error {
	runner, err := p.connect(ctx, d)
	if err != nil {
		return err
	}
	defer func() { _ = runner.Close() }()
	got, err := readSnapshot(ctx, runner)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(got.ports))
	for name := range got.ports {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		port := got.ports[name]
		if !port.ingress && !port.egress {
			continue
		}
		if err := setPort(ctx, runner, name, false, false); err != nil {
			return err
		}
	}
	if got.state.Target != "" {
		if err := setSwitchTarget(ctx, runner, got.switchName, noMirrorTarget); err != nil {
			return err
		}
	}
	after, err := readSnapshot(ctx, runner)
	if err != nil {
		return fmt.Errorf("reading back the reverted mirror: %w", err)
	}
	if len(after.state.Sources) != 0 || after.state.Target != "" {
		return errors.New("device readback still reports a mirror after revert")
	}
	return nil
}

func readSnapshot(ctx context.Context, runner sshtransport.Runner) (snapshot, error) {
	resource, err := queryRows(ctx, runner, "/system resource print as-value")
	if err != nil {
		return snapshot{}, fmt.Errorf("reading device identity: %w", err)
	}
	if len(resource) != 1 {
		return snapshot{}, errors.New("device did not report one resource identity")
	}
	board := value(resource[0], "board-name")
	version := value(resource[0], "version")
	if board != supportedBoard || !strings.HasPrefix(version, "7.") {
		return snapshot{}, fmt.Errorf("%w: RouterOS model or firmware", fabric.ErrUnsupportedDevice)
	}
	switchName, targetName, err := readSwitch(ctx, runner)
	if err != nil {
		return snapshot{}, err
	}
	rows, err := queryRows(ctx, runner, "/interface ethernet switch port print as-value")
	if err != nil {
		return snapshot{}, fmt.Errorf("reading switch ports: %w", err)
	}
	if len(rows) == 0 {
		return snapshot{}, fmt.Errorf("%w: no switch ports", fabric.ErrUnsupportedDevice)
	}
	got := snapshot{
		switchName: switchName,
		ports:      make(map[string]port, len(rows)),
		state: fabric.State{
			Target:           targetName,
			Identity:         board + " " + version,
			SourceDirections: make(map[string]fabric.Direction),
		},
	}
	var anyIn, anyEg bool
	for _, row := range rows {
		name := value(row, "name")
		if !validName(name) {
			return snapshot{}, fmt.Errorf("%w: unsafe port name", fabric.ErrUnsupportedDevice)
		}
		if _, dup := got.ports[name]; dup {
			return snapshot{}, fmt.Errorf("%w: duplicate port names", fabric.ErrUnsupportedDevice)
		}
		inRaw, inOK := row["mirror-ingress"]
		egRaw, egOK := row["mirror-egress"]
		if !inOK || !egOK || inRaw == nil || egRaw == nil {
			return snapshot{}, fmt.Errorf("%w: no per-port ingress and egress fields", fabric.ErrUnsupportedDevice)
		}
		in, err := boolean(value(row, "mirror-ingress"))
		if err != nil {
			return snapshot{}, err
		}
		eg, err := boolean(value(row, "mirror-egress"))
		if err != nil {
			return snapshot{}, err
		}
		got.ports[name] = port{name: name, ingress: in, egress: eg}
		if !in && !eg {
			continue
		}
		got.state.Sources = append(got.state.Sources, name)
		anyIn, anyEg = anyIn || in, anyEg || eg
		switch {
		case in && eg:
			got.state.SourceDirections[name] = fabric.DirectionBoth
		case in:
			got.state.SourceDirections[name] = fabric.DirectionIngress
		case eg:
			got.state.SourceDirections[name] = fabric.DirectionEgress
		}
	}
	switch {
	case anyIn && anyEg:
		got.state.Direction = fabric.DirectionBoth
	case anyIn:
		got.state.Direction = fabric.DirectionIngress
	case anyEg:
		got.state.Direction = fabric.DirectionEgress
	}
	return got, nil
}

func readSwitch(ctx context.Context, runner sshtransport.Runner) (string, string, error) {
	switches, err := queryRows(ctx, runner, "/interface ethernet switch print as-value")
	if err != nil {
		return "", "", fmt.Errorf("reading switch layout: %w", err)
	}
	if len(switches) != 1 {
		return "", "", fmt.Errorf("%w: SSH profile requires exactly one switch chip", fabric.ErrUnsupportedDevice)
	}
	switchName := value(switches[0], "name")
	if !validName(switchName) {
		return "", "", fmt.Errorf("%w: unsafe switch name", fabric.ErrUnsupportedDevice)
	}
	target, ok := switches[0]["mirror-target"]
	if !ok || target == nil {
		return "", "", fmt.Errorf("%w: no mirror target field", fabric.ErrUnsupportedDevice)
	}
	targetName := value(switches[0], "mirror-target")
	if targetName == noMirrorTarget {
		targetName = ""
	}
	return switchName, targetName, nil
}
func queryRows(ctx context.Context, runner sshtransport.Runner, path string) ([]map[string]any, error) {
	command := ":put [:serialize to=json options=json.no-string-conversion value=[" + path + "]]"
	body, err := runner.Run(ctx, command)
	if err != nil {
		return nil, err
	}
	body = bytes.TrimSpace(body)
	var rows []map[string]any
	if err := json.Unmarshal(body, &rows); err == nil {
		return rows, nil
	}
	var one map[string]any
	if err := json.Unmarshal(body, &one); err != nil {
		return nil, errors.New("device returned invalid JSON for a mirror query")
	}
	return []map[string]any{one}, nil
}

func setSwitchTarget(ctx context.Context, runner sshtransport.Runner, switchName, target string) error {
	if !validName(switchName) || !validName(target) && target != noMirrorTarget {
		return errors.New("refusing an unsafe switch or target name")
	}
	command := fmt.Sprintf("/interface ethernet switch set [find where name=\"%s\"] mirror-target=\"%s\"", switchName, target)
	if _, err := runner.Run(ctx, command); err != nil {
		return fmt.Errorf("setting the switch mirror target: %w", err)
	}
	return nil
}

func setPort(ctx context.Context, runner sshtransport.Runner, name string, ingress, egress bool) error {
	if !validName(name) {
		return errors.New("refusing an unsafe port name")
	}
	command := fmt.Sprintf("/interface ethernet switch port set [find where name=\"%s\"] mirror-ingress=%s mirror-egress=%s", name, yesNo(ingress), yesNo(egress))
	if _, err := runner.Run(ctx, command); err != nil {
		return fmt.Errorf("setting port mirroring: %w", err)
	}
	return nil
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func validName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, c := range name {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		if c != '.' && c != '_' && c != '-' && c != '/' {
			return false
		}
	}
	return true
}

func boolean(v string) (bool, error) {
	switch v {
	case "true", "yes":
		return true, nil
	case "false", "no":
		return false, nil
	default:
		return false, fmt.Errorf("%w: invalid mirror boolean", fabric.ErrUnsupportedDevice)
	}
}

func value(row map[string]any, key string) string {
	v := row[key]
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}
