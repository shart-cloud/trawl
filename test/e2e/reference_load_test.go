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

// T126: the reference-load acceptance at the traffic rate the installation
// actually produces.
//
// # SC-002 is measured here in full
//
// "At least 95% of valid traffic-source creations and updates reach Active or an
// actionable non-active state within 2 minutes." Twenty trials, timed from the
// write to the terminal-or-actionable status. That is a real measurement and it
// runs.
//
// # SC-003 is measured at the produced rate
//
// "During a 60-minute test at whatever sustained traffic rate the installation
// produces, active sources remain available and report less than 1% packet loss
// at the capture boundary." The evidence must report that measured rate rather
// than infer a reference load.
//
// The loss ratio is measurable and is measured: the sensor exports
// `trawl_sensor_packets_total` and `trawl_sensor_kernel_drops_total`, and drops
// over drops-plus-packets is exactly the capture-boundary loss the criterion
// names. The availability clause is measurable and is measured.
//
// Packet rate is always computable from the same capture-boundary counter used
// for loss. The sensor also exports decoder bytes; that is an analyzer-accepted
// byte rate rather than a wire byte rate, so the output names it as such and it
// must be read beside kernel drops rather than alone.
package e2e

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
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

	// This is the criterion, not a smoke test. A shorter configurable window
	// once let the opted-in release gate pass without measuring the required
	// hour, even though its log cautioned against interpreting that as SC-003.
	const window = time.Hour

	tap := a.requiredProductionTap(t)
	before, ok := a.tapStatus(t, tap)
	if !ok || !isActive(before) {
		t.Fatalf("the production tap is not Active, so SC-003 availability cannot be verified")
	}

	startPackets, startDrops, startBytes := a.sensorCounters(t, tap)
	t.Logf("SC-003 window opening: packets=%d drops=%d decoder_bytes=%d",
		startPackets, startDrops, startBytes)

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

	endPackets, endDrops, endBytes := a.sensorCounters(t, tap)
	packets := endPackets - startPackets
	drops := endDrops - startDrops
	bytes := endBytes - startBytes
	t.Logf("SC-003 window closed: packets=%d drops=%d decoder_bytes=%d over %s",
		packets, drops, bytes, window)

	if packets == 0 {
		t.Fatalf("no packets were observed over %s, so a zero loss ratio would mean nothing", window)
	}

	// Loss at the capture boundary: what the kernel dropped before userspace
	// drained the ring, over everything that reached the boundary.
	loss := float64(drops) / float64(drops+packets)
	packetRate := float64(packets) / window.Seconds()
	decoderBitRate := float64(bytes) * 8 / window.Seconds()
	t.Logf("SC-003: observed=%d dropped=%d loss=%.4f%% budget=%.2f%% "+
		"measured_packet_rate=%.2f packets/s measured_decoder_rate=%.2f bit/s availability=%s",
		packets, drops, 100*loss, 100*sc003LossBudget, packetRate, decoderBitRate,
		map[bool]string{true: "held", false: "LOST"}[lostActive == 0])

	if loss >= sc003LossBudget {
		t.Errorf("capture-boundary loss was %.4f%%, over SC-003's %.2f%%", 100*loss, 100*sc003LossBudget)
	}

	// Said in the run's own output so an ambient run cannot silently become a
	// claim that a reference load was generated.
	t.Logf("SC-003 is evaluated at the measured produced rate above; this run makes no claim " +
		"that the installation generated 100 Mb/s or any other unmeasured wire rate.")
}

// sensorCounters reads the sensor's packet and drop totals from the metrics the
// telemetry contract exports.
//
// Read from the sensor pods rather than from the manager: nothing aggregates
// them, and a per-node figure is what "the capture boundary" means.
//
// Fetched over a port-forward rather than by exec'ing a client inside the pod.
// The sensor-agent image is distroless and has no shell and no wget, so the
// obvious `kubectl exec ... wget` fails with "executable file not found" - which
// is the image doing exactly what a minimal runtime image should.
//
// The probe port is derived per tap rather than fixed, because the sensor runs
// on the host network and :9100 is node_exporter's. It is read off the pod's own
// arguments rather than recomputed, because a spec that recomputed it would keep
// passing against a sensor listening somewhere else.
func (a *acceptance) sensorCounters(t *testing.T, tap string) (packets, drops, bytes int64) {
	t.Helper()

	pods, err := kubectlOut("get", "pods", "-n", a.namespace,
		"-l", "app.kubernetes.io/component=sensor,trawl.cloud/tap="+tap,
		"-o", "jsonpath={range .items[*]}{.metadata.name}{\" \"}{end}")
	if err != nil {
		t.Fatalf("listing sensor pods: %v: %s", err, pods)
	}
	names := strings.Fields(pods)
	if len(names) == 0 {
		t.Fatal("no sensor pods, so there are no capture-boundary counters to read")
	}

	for i, pod := range names {
		args, err := kubectlOut("get", "pod", pod, "-n", a.namespace,
			"-o", "jsonpath={.spec.containers[?(@.name=='sensor-agent')].args}")
		if err != nil {
			t.Fatalf("reading %s's arguments: %v: %s", pod, err, args)
		}
		port := probeAddrPort(args)
		if port == "" {
			t.Fatalf("%s declares no --probe-addr, so this spec cannot find its metrics: %s", pod, args)
		}

		body := a.scrapeSensor(t, pod, port, 32000+i)
		packets += metricValue(t, body, "trawl_sensor_packets_total")
		drops += metricValue(t, body, "trawl_sensor_kernel_drops_total")
		bytes += metricValue(t, body, "trawl_sensor_bytes_total")
	}
	return packets, drops, bytes
}

// scrapeSensor port-forwards one sensor's probe port and returns its metrics.
func (a *acceptance) scrapeSensor(t *testing.T, pod, port string, localPort int) string {
	t.Helper()

	//nolint:gosec // G204: the pod name and port come from the cluster this
	// spec is already talking to, not from evidence or the environment.
	cmd := exec.Command("kubectl", "port-forward", "-n", a.namespace,
		"pod/"+pod, fmt.Sprintf("%d:%s", localPort, port))
	if err := cmd.Start(); err != nil {
		t.Fatalf("forwarding %s's probe port: %v", pod, err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	url := fmt.Sprintf("http://127.0.0.1:%d/metrics", localPort)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		//nolint:gosec,noctx // G107: a loopback URL this function just built.
		resp, err := http.Get(url)
		if err == nil {
			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if readErr == nil && resp.StatusCode == http.StatusOK {
				return string(body)
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("%s did not serve metrics on %s within 30s", pod, url)
	return ""
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
	var found bool
	for line := range strings.SplitSeq(body, "\n") {
		if !strings.HasPrefix(line, name+"{") && !strings.HasPrefix(line, name+" ") {
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
		found = true
		total += int64(v)
	}
	if !found {
		t.Fatalf("required metric %s is absent from the sensor exposition", name)
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
