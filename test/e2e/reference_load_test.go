//go:build acceptance

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

// T126: the reference-load acceptance, and an honest account of the half of it
// this installation cannot perform.
//
// # SC-002 is measured here in full
//
// "At least 95% of valid traffic-source creations and updates reach Active or an
// actionable non-active state within 2 minutes." Twenty trials, timed from the
// write to the terminal-or-actionable status. That is a real measurement and it
// runs.
//
// # SC-003's loss clause is measured; its rate clause cannot be
//
// "During a 60-minute test at 100 Mb/s sustained observed traffic, active
// sources remain available and report less than 1% packet loss at the capture
// boundary."
//
// The loss ratio is measurable and is measured: the sensor exports
// `trawl_sensor_packets_total` and `trawl_sensor_kernel_drops_total`, and drops
// over drops-plus-packets is exactly the capture-boundary loss the criterion
// names. The availability clause is measurable and is measured.
//
// The *rate* clause is not, for two independent reasons, and neither is
// something a test can paper over:
//
//  1. **Trawl exports no observed-byte counter.** The telemetry contract has
//     `trawl_sensor_packets_total` and no bytes equivalent; the only byte metric
//     in the contract is `trawl_capture_size_bytes`, which is artifact size. So
//     "100 Mb/s observed" cannot be computed from Trawl's own signals at all. It
//     would have to come from the node's NIC counters, which are outside what
//     this suite may read.
//
//  2. **The tap observes a physical node interface.** Generating 100 Mb/s across
//     `eno1` needs traffic that actually leaves the node. An in-cluster load
//     generator's packets traverse Cilium's veth path and never appear on it, so
//     the obvious approach measures nothing. A genuine run needs the external,
//     isolated traffic source the quickstart calls for.
//
// So this file measures loss and availability over a sustained window at
// whatever rate the interface really carries, and records that rate as
// *unmeasured* rather than asserting a figure it cannot obtain. A test that
// claimed SC-003 by running for an hour at four megabits would be worse than no
// test: it would retire the criterion without having exercised it.
package e2e

import (
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
)

const (
	// sc002Trials is the sample SC-002 is stated over.
	sc002Trials = 20

	// sc002Budget is the bound each trial must come in under.
	sc002Budget = 2 * time.Minute

	// sc002PassRate is SC-002's threshold.
	sc002PassRate = 0.95

	// sc003LossBudget is SC-003's capture-boundary loss ceiling.
	sc003LossBudget = 0.01
)

// trial is one timed tap create or update.
type trial struct {
	N        int
	Action   string
	Duration time.Duration
	Phase    string
	Passed   bool
}

func TestReferenceLoadSC002TapTrialsReachActiveWithinTwoMinutes(t *testing.T) {
	a := requireAcceptanceCluster(t)
	if os.Getenv("TRAWL_E2E_REFERENCE_LOAD") != "1" {
		t.Skip("set TRAWL_E2E_REFERENCE_LOAD=1 to run this; it creates and updates twenty taps " +
			"and schedules a sensor for each")
	}

	// One tap, created and then updated repeatedly. SC-002 counts creations
	// *and* updates, and a fresh tap per trial would schedule twenty sensor
	// DaemonSets on one node - which measures the node's pod capacity rather
	// than Trawl's reconciliation.
	name := a.tapName(t)
	trials := make([]trial, 0, sc002Trials)

	for i := 1; i <= sc002Trials; i++ {
		action := "update"
		opts := defaultTapOptions()
		// Alternate a real, observable difference so each update is a genuine
		// generation bump rather than a no-op write the controller can skip.
		if i%2 == 0 {
			opts.suricataEnabled = false
		}

		start := time.Now()
		if i == 1 {
			action = "create"
			a.applyTap(t, name, opts)
		} else {
			a.updateTap(t, name, opts)
		}

		// "Active or an actionable non-active state": the criterion is about
		// the operator learning where they stand, not about the tap always
		// succeeding. A Degraded tap whose conditions say why is a pass; a tap
		// sitting in Pending with nothing to act on is not.
		status := a.waitForTap(t, name, sc002Budget+30*time.Second,
			"reach Active or an actionable non-active state", isActionable)
		elapsed := time.Since(start)

		passed := elapsed < sc002Budget && isActionable(status)
		trials = append(trials, trial{
			N: i, Action: action, Duration: elapsed,
			Phase: string(status.Phase), Passed: passed,
		})
	}

	var passes int
	durations := make([]time.Duration, 0, len(trials))
	t.Log("trial | action | duration | phase    | result")
	for _, tr := range trials {
		if tr.Passed {
			passes++
		}
		durations = append(durations, tr.Duration)
		result := "FAIL"
		if tr.Passed {
			result = "pass"
		}
		t.Logf("%5d | %-6s | %8s | %-8s | %s",
			tr.N, tr.Action, tr.Duration.Round(time.Millisecond), tr.Phase, result)
	}

	slices.Sort(durations)
	t.Logf("SC-002: trials=%d passed=%d (%.1f%%) budget=%s p50=%s p95=%s max=%s",
		len(trials), passes, 100*float64(passes)/float64(len(trials)), sc002Budget,
		durations[len(durations)/2].Round(time.Millisecond),
		durations[(len(durations)*95)/100].Round(time.Millisecond),
		durations[len(durations)-1].Round(time.Millisecond))

	want := int(float64(len(trials)) * sc002PassRate)
	if passes < want {
		t.Errorf("%d of %d trials reached an actionable state within %s, want at least %d (SC-002's 95%%)",
			passes, len(trials), sc002Budget, want)
	}
}

func TestReferenceLoadSC003LossStaysUnderOnePercent(t *testing.T) {
	a := requireAcceptanceCluster(t)
	if os.Getenv("TRAWL_E2E_REFERENCE_LOAD") != "1" {
		t.Skip("set TRAWL_E2E_REFERENCE_LOAD=1 to run this; it observes the production tap for " +
			"the configured window")
	}

	// Default one hour, overridable so the spec can be exercised quickly
	// without pretending a short run satisfies SC-003.
	window := time.Hour
	if raw := os.Getenv("TRAWL_E2E_LOAD_WINDOW"); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			t.Fatalf("TRAWL_E2E_LOAD_WINDOW=%q is not a duration: %v", raw, err)
		}
		window = parsed
	}

	tap := a.productionTap(t)
	before, ok := a.tapStatus(t, tap)
	if !ok || !isActive(before) {
		t.Skipf("the production tap is not Active, so there is no sustained observation to measure")
	}

	startPackets, startDrops := a.sensorCounters(t)
	t.Logf("SC-003 window opening: packets=%d drops=%d", startPackets, startDrops)

	deadline := time.Now().Add(window)
	var lostActive int
	for time.Now().Before(deadline) {
		time.Sleep(30 * time.Second)
		status, exists := a.tapStatus(t, tap)
		if !exists || !isActive(status) {
			lostActive++
			t.Errorf("the tap left Active during the window: exists=%v phase=%q", exists, status.Phase)
		}
	}

	endPackets, endDrops := a.sensorCounters(t)
	packets := endPackets - startPackets
	drops := endDrops - startDrops
	t.Logf("SC-003 window closed: packets=%d drops=%d over %s", packets, drops, window)

	if packets == 0 {
		t.Fatalf("no packets were observed over %s, so a zero loss ratio would mean nothing", window)
	}

	// Loss at the capture boundary: what the kernel dropped before userspace
	// drained the ring, over everything that reached the boundary.
	loss := float64(drops) / float64(drops+packets)
	t.Logf("SC-003: observed=%d dropped=%d loss=%.4f%% budget=%.2f%% availability=%s",
		packets, drops, 100*loss, 100*sc003LossBudget,
		map[bool]string{true: "held", false: "LOST"}[lostActive == 0])

	if loss >= sc003LossBudget {
		t.Errorf("capture-boundary loss was %.4f%%, over SC-003's %.2f%%", 100*loss, 100*sc003LossBudget)
	}

	// Said in the run's own output so evidence transcribed from it cannot
	// silently become a claim that SC-003 was met.
	t.Logf("NOTE: the rate clause of SC-003 is NOT verified by this run. Trawl exports no " +
		"observed-byte counter, so throughput cannot be computed from its telemetry, and the tap " +
		"observes a physical node interface that in-cluster load never traverses. This measures " +
		"loss and availability at whatever rate the interface actually carried.")
}

// sensorCounters reads the sensor's packet and drop totals from the metrics the
// telemetry contract exports.
//
// Read from the sensor pods rather than from the manager: nothing aggregates
// them, and a per-node figure is what "the capture boundary" means.
//
// The probe port is derived per tap, not fixed - the sensor runs on the host
// network and :9100 is node_exporter's, so a fixed port loses that race on any
// cluster scraping node metrics. It is read off the pod's own arguments rather
// than recomputed here, because a spec that recomputed it would keep passing
// against a sensor listening somewhere else.
func (a *acceptance) sensorCounters(t *testing.T) (packets, drops int64) {
	t.Helper()

	pods, err := kubectlOut("get", "pods", "-n", a.namespace,
		"-l", "app.kubernetes.io/component=sensor",
		"-o", "jsonpath={range .items[*]}{.metadata.name}{\" \"}{end}")
	if err != nil {
		t.Fatalf("listing sensor pods: %v: %s", err, pods)
	}
	names := strings.Fields(pods)
	if len(names) == 0 {
		t.Fatal("no sensor pods, so there are no capture-boundary counters to read")
	}

	for _, pod := range names {
		args, err := kubectlOut("get", "pod", pod, "-n", a.namespace,
			"-o", "jsonpath={.spec.containers[?(@.name=='sensor-agent')].args}")
		if err != nil {
			t.Fatalf("reading %s's arguments: %v: %s", pod, err, args)
		}
		port := probeAddrPort(args)
		if port == "" {
			t.Fatalf("%s declares no --probe-addr, so this spec cannot find its metrics: %s", pod, args)
		}

		body, err := kubectlOut("exec", "-n", a.namespace, pod, "-c", "sensor-agent", "--",
			"wget", "-qO-", "http://127.0.0.1:"+port+"/metrics")
		if err != nil {
			t.Skipf("the sensor's metrics endpoint is not reachable from inside its pod: %v: %s", err, body)
		}
		packets += metricValue(t, body, "trawl_sensor_packets_total")
		drops += metricValue(t, body, "trawl_sensor_kernel_drops_total")
	}
	return packets, drops
}

// probeAddrPort pulls the port out of the sensor's --probe-addr argument.
func probeAddrPort(args string) string {
	for field := range strings.SplitSeq(args, "\"") {
		if after, ok := strings.CutPrefix(field, "--probe-addr=:"); ok {
			return after
		}
	}
	return ""
}

// metricValue sums every series of one counter in a Prometheus exposition body.
func metricValue(t *testing.T, body, name string) int64 {
	t.Helper()
	var total int64
	for line := range strings.SplitSeq(body, "\n") {
		if !strings.HasPrefix(line, name) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, err := strconv.ParseFloat(fields[len(fields)-1], 64)
		if err != nil {
			continue
		}
		total += int64(v)
	}
	return total
}

// isActionable reports whether a tap has reached a state an operator can act on:
// Active, or a non-active phase whose conditions say what is wrong.
//
// SC-002 is about the operator learning where they stand within two minutes,
// not about the tap always succeeding. Pending with nothing said is the failure
// the criterion is written against.
func isActionable(status trawlv1alpha1.NetworkTapStatus) bool {
	if isActive(status) {
		return true
	}
	switch status.Phase {
	case trawlv1alpha1.TapPhaseDegraded, trawlv1alpha1.TapPhaseError:
		for _, c := range status.Conditions {
			if c.Status == "False" && c.Message != "" {
				return true
			}
		}
	}
	return false
}
