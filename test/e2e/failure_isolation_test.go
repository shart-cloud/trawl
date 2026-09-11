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

// T125: what survives when a component fails, and what must refuse to.
//
// Trawl's failure design has two halves, and every spec in this file asserts
// both of them about one injected fault.
//
//   - The passive path keeps observing. The sensor reads an interface and
//     writes to stdout; it touches no storage, no API server and no ledger. A
//     control-plane failure that stopped it would mean an operator loses
//     visibility at exactly the moment something is wrong with their cluster.
//
//   - Everything that records or authorizes fails closed. An action that cannot
//     be written to the ledger must not happen (FR-036), and a capture nobody
//     can be shown to have authorized is worse than a capture that was refused.
//
// Between those two, the distinction that matters is *evidence versus
// availability*. Losing the ability to start a new capture during an outage is
// an availability problem and is acceptable. Producing a capture with no audit
// record, or silently ceasing to observe while still reporting Active, is an
// evidence problem and is not.
//
// Two of T125's injections already have specs and are not repeated here:
// storage (TestALedgerOutageRefusesMutationsAndLeavesMonitoringRunning) and the
// audit path (TestAnAuditOutageRefusesCapturesAndServesNothingUnrecorded).
//
// Every spec here is opt-in. Each one disrupts the installation for as long as
// it runs, which is not something a routine acceptance run should do to a
// shared cluster, and each restores what it broke even when it fails.
package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
)

// requireFailureInjection gates a spec that breaks the installation.
//
// A separate gate from TRAWL_E2E_LEDGER_OUTAGE rather than the same one: these
// injections disrupt different things for different lengths of time, and an
// operator deciding to accept one is not thereby deciding to accept all of
// them.
func requireFailureInjection(t *testing.T, what string) {
	t.Helper()
	if os.Getenv("TRAWL_E2E_FAILURE_INJECTION") != "1" {
		t.Skipf("set TRAWL_E2E_FAILURE_INJECTION=1 to run this; it %s while it runs", what)
	}
}

// scaleDeployment scales a Deployment to zero and returns a restore function
// that is safe to call more than once.
//
// Modelled on stopLedger, including the part that matters most: a failure to
// restore is fatal rather than logged. A run that ends quietly having left the
// installation with a component scaled to zero is worse than a run that fails.
func (a *acceptance) scaleDeployment(t *testing.T, name string) func() {
	t.Helper()

	// Note what this cannot protect against: SIGKILL runs no deferred code, so
	// a run killed outright leaves the Deployment at zero. For the controller
	// manager that means the installation refuses every mutation until somebody
	// notices, and it looks exactly like a component that crashed on its own.
	// hack/e2e-cleanup.sh reports it; there is no way to make the test itself
	// survive being killed.

	replicas, err := kubectlOut("get", "deployment", name, "-n", a.namespace,
		"-o", "jsonpath={.spec.replicas}")
	if err != nil {
		t.Fatalf("reading deployment %s: %v: %s", name, err, replicas)
	}
	want := strings.TrimSpace(replicas)
	if want == "" || want == "0" {
		t.Skipf("deployment %s is already scaled to %q, so there is no outage to inject", name, want)
	}

	if out, err := kubectlOut("scale", "deployment", name, "-n", a.namespace, "--replicas=0"); err != nil {
		t.Fatalf("scaling %s down: %v: %s", name, err, out)
	}

	var once sync.Once
	restore := func() {
		once.Do(func() {
			if out, err := kubectlOut("scale", "deployment", name, "-n", a.namespace,
				"--replicas="+want); err != nil {
				t.Fatalf("restoring %s to %s replicas: %v: %s", name, want, err, out)
			}
			if out, err := kubectlOut("rollout", "status", "deployment/"+name,
				"-n", a.namespace, "--timeout=3m"); err != nil {
				t.Fatalf("waiting for %s to return: %v: %s", name, err, out)
			}
		})
	}
	// Registered as cleanup as well as returned, so an assertion that fails
	// mid-spec still restores the installation.
	t.Cleanup(restore)
	return restore
}

// isolateWorkerEgress applies a NetworkPolicy that denies the event worker all
// egress, and returns a restore function.
//
// Chosen over stopping Loki or Hubble Relay because both live outside the
// installation namespace and are shared with everything else on the cluster.
// Severing the worker's own egress produces the same observable condition - the
// worker cannot reach its event source - without taking a dependency away from
// unrelated workloads.
func (a *acceptance) isolateWorkerEgress(t *testing.T) func() {
	t.Helper()

	const name = "trawl-e2e-deny-worker-egress"
	manifest := fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: %s
  namespace: %s
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/component: event-worker
  policyTypes: [Egress]
  egress: []
`, name, a.namespace)

	// Remove any leftover of the same name before applying. A killed run -
	// SIGKILL runs no deferred code, so t.Cleanup does not save this - leaves
	// the worker isolated indefinitely, and the next run would otherwise start
	// against an installation that was already broken and report the outage it
	// found as the outage it caused. hack/e2e-cleanup.sh is the same job for a
	// human.
	if out, err := kubectlOut("delete", "networkpolicy", name, "-n", a.namespace,
		"--ignore-not-found"); err != nil {
		t.Fatalf("clearing a leftover isolation policy: %v: %s", err, out)
	}

	path := filepath.Join(t.TempDir(), "deny-worker-egress.yaml")
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatalf("writing the isolation policy: %v", err)
	}
	if err := kubectl("apply", "-f", path); err != nil {
		t.Fatalf("isolating the event worker: %v", err)
	}

	var once sync.Once
	restore := func() {
		once.Do(func() {
			if out, err := kubectlOut("delete", "networkpolicy", name, "-n", a.namespace,
				"--ignore-not-found"); err != nil {
				t.Fatalf("restoring the event worker's egress: %v: %s", err, out)
			}
		})
	}
	t.Cleanup(restore)
	return restore
}

// --- Specs ------------------------------------------------------------------

func TestAControllerOutageRefusesMutationsAndLeavesMonitoringRunning(t *testing.T) {
	// The controller manager serves the admission webhooks, and their
	// failurePolicy is Fail. Taking it away must therefore refuse every
	// mutation - that is the fail-closed half working, not a bug - while the
	// sensors that are already running keep observing.
	//
	// This is the sharpest statement of the evidence/availability distinction.
	// Nobody can request a capture during the outage, which is inconvenient.
	// What would be unacceptable is the tap going quiet, because an operator
	// would then have lost visibility precisely while their control plane was
	// broken.
	a := requireAcceptanceCluster(t)
	requireFailureInjection(t, "refuses every Trawl mutation installation-wide")

	tap := a.productionTap(t)
	before, ok := a.tapStatus(t, tap)
	if !ok {
		t.Fatalf("the production tap %s is not present, so there is nothing to protect", tap)
	}
	if !isActive(before) {
		t.Skipf("the production tap is not Active before the outage (phase=%q), so this spec "+
			"cannot tell an outage from a pre-existing fault", before.Phase)
	}

	restore := a.scaleDeployment(t, "trawl-controller-manager")

	// Retried rather than asserted once: the API server keeps the webhook's
	// endpoints for a moment after the pod goes, so the first attempt can still
	// succeed without the outage being absent.
	refused := a.waitForRefusal(t, a.tapName(t)+"-during-controller-outage")
	t.Logf("controller outage: creating a tap was refused with %q", firstLine(refused))

	during, exists := a.tapStatus(t, tap)
	if !exists {
		t.Fatal("the production tap disappeared while the controller was down")
	}
	if !isActive(during) {
		t.Errorf("the tap left Active during a controller outage: phase=%q conditions=%s",
			during.Phase, formatConditions(during.Conditions))
	}
	if len(a.sensorDaemonSets(t, tap)) == 0 {
		t.Error("the sensor DaemonSet was removed while the controller was down")
	}
	// The strongest form: packets are still arriving, not merely that a status
	// field has not been updated by the controller that is currently absent.
	a.requireSensorsStillRunning(t)

	restore()
	a.waitForTap(t, tap, settleTimeout, "Active after the controller returned", isActive)
}

func TestATriggerSourceOutageDegradesPoliciesAndLeavesMonitoringRunning(t *testing.T) {
	// The event worker reads Suricata alerts from Loki and Hubble drops from a
	// live gRPC stream. Severing its egress takes both away at once.
	//
	// What must happen: armed policies stop being able to see events and say
	// so. What must not happen: a policy that silently reports itself Armed
	// while evaluating nothing, because that is indistinguishable from a quiet
	// network and would let an operator believe they had detection coverage
	// they did not have.
	a := requireAcceptanceCluster(t)
	a.requirePolicySupport(t)
	requireFailureInjection(t, "severs the event worker's egress, so no policy evaluates events")

	tap := a.productionTap(t)
	before, ok := a.tapStatus(t, tap)
	if !ok || !isActive(before) {
		t.Skip("the production tap is not Active, so this spec cannot tell an outage from a prior fault")
	}

	name := a.policyName(t)
	a.applyPolicy(t, name, defaultPolicyOptions())
	a.waitForPolicy(t, name, policyStatusTimeout, "report itself armed",
		func(s trawlv1alpha1.CapturePolicyStatus) bool {
			return s.Phase == trawlv1alpha1.CapturePolicyArmed
		})

	restore := a.isolateWorkerEgress(t)

	// The worker reports the loss through the policy it is holding. Degraded is
	// the phase that says "armed, and not seeing events" - the distinction this
	// whole spec exists to protect.
	degraded := a.waitForPolicy(t, name, 4*time.Minute,
		"report that it lost its event source",
		func(s trawlv1alpha1.CapturePolicyStatus) bool {
			if s.Phase == trawlv1alpha1.CapturePolicyDegraded {
				return true
			}
			for _, c := range s.Conditions {
				if c.Type == "SourceConnected" && c.Status == "False" {
					return true
				}
			}
			return false
		})
	t.Logf("trigger source outage: policy phase=%q conditions=%s",
		degraded.Phase, formatConditions(degraded.Conditions))

	// Monitoring is a wholly separate path and must be untouched.
	during, exists := a.tapStatus(t, tap)
	if !exists || !isActive(during) {
		t.Errorf("the tap stopped being Active when the event worker lost its egress: exists=%v phase=%q",
			exists, during.Phase)
	}
	a.requireLastPacketAdvanced(t, tap, before.LastPacketTime)

	restore()
	a.waitForPolicy(t, name, 4*time.Minute, "recover once its egress returns",
		func(s trawlv1alpha1.CapturePolicyStatus) bool {
			return s.Phase == trawlv1alpha1.CapturePolicyArmed
		})
}

func TestAGatewayOutageRefusesDownloadsAndStillCollectsEvidence(t *testing.T) {
	// The artifact gateway is the only authorized read path for a capture. If
	// it is down, nobody can download - and that is the correct behaviour,
	// because the alternative is a read path that is not authorized or audited.
	//
	// Collection is deliberately independent of it. A capture requested during
	// a gateway outage still runs and still stores its artifact, so the
	// evidence exists to be read once the gateway returns. Losing the ability
	// to *read* evidence during an outage is availability; failing to *collect*
	// it would be evidence lost for good, because the traffic is gone.
	a := requireAcceptanceCluster(t)
	requireFailureInjection(t, "takes the artifact gateway down, so no capture can be downloaded")

	tap := a.productionTap(t)
	before, ok := a.tapStatus(t, tap)
	if !ok || !isActive(before) {
		t.Skip("the production tap is not Active, so a capture requested here would not run")
	}

	restore := a.scaleDeployment(t, "trawl-artifact-gateway")

	// A capture requested while the gateway is down still completes and still
	// verifies its artifact.
	name := fmt.Sprintf("gateway-outage-%s", a.runID)
	opts := a.defaultCaptureOptions()
	opts.duration = "10s"
	a.applyCapture(t, name, opts)

	status := a.waitForCapture(t, name, captureCompleteTimeout,
		"complete while the gateway is down",
		func(s trawlv1alpha1.CaptureJobStatus) bool {
			return s.Phase == trawlv1alpha1.CapturePhaseCompleted || s.Phase == trawlv1alpha1.CapturePhaseFailed
		})
	if status.Phase != trawlv1alpha1.CapturePhaseCompleted {
		t.Errorf("a capture requested during a gateway outage ended %q, not Completed: %s",
			status.Phase, formatConditions(status.Conditions))
	}

	// The tap is untouched throughout: the gateway is not on the capture path.
	during, exists := a.tapStatus(t, tap)
	if !exists || !isActive(during) {
		t.Errorf("the tap stopped being Active during a gateway outage: exists=%v phase=%q",
			exists, during.Phase)
	}

	restore()
	t.Logf("gateway restored; the capture collected during the outage is %q", status.Phase)
}

// requireSensorsStillRunning asserts the passive path survived, by the only
// evidence available while the controller is down.
//
// Named for what it actually checks. During a controller outage nothing is
// writing status at all, so "the phase is still Active" is equally consistent
// with a healthy sensor and with one that died the moment the controller did -
// the field is simply stale. The sensor pods' own state does not go through the
// controller, so it is the honest signal here.
//
// Where the controller *is* alive, requireLastPacketAdvanced is the stronger
// check and is used instead.
func (a *acceptance) requireSensorsStillRunning(t *testing.T) {
	t.Helper()

	pods, err := kubectlOut("get", "pods", "-n", a.namespace,
		"-l", "app.kubernetes.io/component=sensor",
		"-o", "jsonpath={range .items[*]}{.status.phase}{\" \"}{end}")
	if err != nil {
		t.Fatalf("reading sensor pods: %v: %s", err, pods)
	}
	states := strings.Fields(pods)
	if len(states) == 0 {
		t.Fatal("no sensor pods are running, so the passive path did not survive the outage")
	}
	for _, state := range states {
		if state != "Running" {
			t.Errorf("a sensor pod is %q during the outage; the passive path must be unaffected", state)
		}
	}
}

// requireLastPacketAdvanced asserts the tap observed a packet after the moment
// the fault was injected.
//
// This is the assertion that distinguishes "still observing" from "status has
// not been updated since it stopped". Only usable when the controller is alive
// to write status.
func (a *acceptance) requireLastPacketAdvanced(t *testing.T, tap string, since *metav1.Time) {
	t.Helper()
	if since == nil {
		t.Skip("the tap reported no packet before the fault, so there is no baseline to advance from")
	}

	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		status, ok := a.tapStatus(t, tap)
		if ok && status.LastPacketTime != nil && status.LastPacketTime.After(since.Time) {
			return
		}
		time.Sleep(pollInterval)
	}
	status, _ := a.tapStatus(t, tap)
	t.Errorf("the tap observed no packet after the fault was injected (last packet %v, baseline %v); "+
		"it is reporting Active while seeing nothing", status.LastPacketTime, since)
}
