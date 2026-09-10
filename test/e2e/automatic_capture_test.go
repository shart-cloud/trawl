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

// US4's cluster acceptance: an armed policy turning an event into evidence
// against a deployed Trawl.
//
// The integration suite already drives the engine against envtest, faster and
// in more shapes. What only a cluster can answer is whether the pieces are
// wired to each other: whether the worker's RBAC lets it create the CaptureJob
// it built, whether its NetworkPolicy lets it reach Loki and the audit sink,
// whether the CaptureJob the engine assembles is admitted by the webhook that
// is really installed, and whether the capture controller then runs it. Every
// one of those has been the defect in this project at least once.
//
// How the alerts get here is worth being plain about. Suricata alerts reach the
// worker through the observation pipeline - the sensor writes them, Alloy ships
// them, Loki holds them - so these specs push a synthetic alert observation
// into Loki rather than trying to trip a specific ET rule with generated
// traffic. That makes the alert content synthetic and everything downstream of
// it real: a real worker polls it, real policies evaluate it, a real CaptureJob
// is admitted, and a real runner collects real packets. The sensor-to-Loki half
// is not skipped, it is covered where it belongs - the investigation suite and
// the NetworkTap acceptance suite both assert it against live traffic.
//
// Denied-flow policies cannot be driven that way, because the worker reads
// those from Hubble's live gRPC stream rather than from Loki. Those specs cause
// real denials with a NetworkPolicy in a scratch namespace.
package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/observation"
	"trawl.cloud/trawl/internal/policy"
	"trawl.cloud/trawl/internal/status"
	"trawl.cloud/trawl/test/integration/harness"
)

const (
	// policyTriggerTimeout bounds a pushed alert becoming a CaptureJob. It has
	// to clear one alert poll interval plus the evaluation and the create, and
	// the poll interval is configuration - so this is generous rather than
	// tight, because a tight bound here would fail on a slow cluster while
	// saying nothing about correctness.
	policyTriggerTimeout = 3 * time.Minute

	// policyStatusTimeout bounds the policy's own counters catching up. Status
	// is batched and flushed on an interval, so it is always behind the
	// CaptureJob it describes.
	policyStatusTimeout = 2 * time.Minute

	// quietWindow is how long a spec waits before concluding that nothing
	// happened. Long enough for two poll intervals: concluding "no capture"
	// after less than one would be reading the interval rather than the policy.
	quietWindow = 45 * time.Second

	// policyCaptureDuration is how long an automatic capture collects for.
	// Short, because no spec here is testing the bound.
	policyCaptureDuration = "10s"

	// alertRuleID and alertCategory identify the synthetic alerts. A rule ID
	// well outside the ET range cannot collide with a real detection, so a
	// spec counting its own captures is never counting somebody else's.
	alertRuleID   = 9900001
	alertCategory = "Trawl Acceptance"
)

// requirePolicySupport skips when the deployed Trawl predates US4.
//
// A skip rather than a failure: it describes the installation this is running
// against, not the software under test, and a red build on a cluster running
// last month's image teaches people to ignore the colour.
func (a *acceptance) requirePolicySupport(t *testing.T) {
	t.Helper()
	if out, err := kubectlOut("get", "crd", "capturepolicies.trawl.cloud"); err != nil {
		t.Skipf("the deployed Trawl has no CapturePolicy CRD: %v: %s", err, out)
	}
}

// policyName is unique per spec and per run, so a leaked policy from an
// interrupted run is visibly not this one's.
func (a *acceptance) policyName(t *testing.T) string {
	t.Helper()
	name := strings.ToLower(t.Name())
	name = strings.NewReplacer("test", "", "_", "-", "/", "-").Replace(name)
	if len(name) > 26 {
		name = name[:26]
	}
	return fmt.Sprintf("acc-%s-%s", strings.Trim(name, "-"), a.runID)
}

// policyOptions are the knobs the specs vary. Everything else is held constant
// so a failure points at the thing under test.
type policyOptions struct {
	armed      bool
	severities []int32
	ruleIDs    []int64
	perHour    int32
	cooldown   time.Duration
	filter     string

	// dropReasons and threshold make it a denied-flow policy instead.
	dropReasons  []string
	dropNamespac []string
	thresholdN   int32
	thresholdWin time.Duration
}

func defaultPolicyOptions() policyOptions {
	return policyOptions{
		armed:      true,
		severities: []int32{1, 2},
		ruleIDs:    []int64{alertRuleID},
		perHour:    5,
		cooldown:   5 * time.Minute,
	}
}

// buildPolicy renders the object rather than a YAML template, so a field this
// test sets that the API later renames fails to compile instead of silently
// testing a default.
func (a *acceptance) buildPolicy(t *testing.T, name string, opts policyOptions) *trawlv1alpha1.CapturePolicy {
	t.Helper()

	trigger := trawlv1alpha1.CapturePolicyTrigger{
		Type: trawlv1alpha1.CaptureTriggerSuricataAlert,
		SuricataAlert: &trawlv1alpha1.SuricataAlertTrigger{
			Severities: opts.severities,
			RuleIDs:    opts.ruleIDs,
		},
	}
	if len(opts.dropReasons) > 0 {
		drop := &trawlv1alpha1.HubbleDropTrigger{
			Reasons:          opts.dropReasons,
			SourceNamespaces: opts.dropNamespac,
		}
		if opts.thresholdN > 0 {
			drop.Threshold = &trawlv1alpha1.DropThreshold{
				Count:  opts.thresholdN,
				Window: metav1.Duration{Duration: opts.thresholdWin},
			}
		}
		trigger = trawlv1alpha1.CapturePolicyTrigger{
			Type: trawlv1alpha1.CaptureTriggerHubbleDrop, HubbleDrop: drop,
		}
	}

	return &trawlv1alpha1.CapturePolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: trawlv1alpha1.GroupVersion.String(),
			Kind:       "CapturePolicy",
		},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: a.namespace},
		Spec: trawlv1alpha1.CapturePolicySpec{
			TapRef:  corev1.LocalObjectReference{Name: a.productionTap(t)},
			Armed:   opts.armed,
			Trigger: trigger,
			Capture: trawlv1alpha1.PolicyCaptureBounds{
				Duration:       policyCaptureDuration,
				MaxSize:        resource.MustParse("16Mi"),
				FilterTemplate: opts.filter,
			},
			Retention: "1h",
			RateLimit: trawlv1alpha1.CaptureRateLimit{
				MaxCapturesPerHour: opts.perHour,
				Cooldown:           metav1.Duration{Duration: opts.cooldown},
			},
		},
	}
}

// applyPolicy creates the policy and removes it when the spec ends.
//
// Deleting it is what stops one spec's policy evaluating the next spec's
// alerts. The captures it created are deliberately left: they carry no owner
// reference, and asserting that they survive their policy is one of the specs
// below.
func (a *acceptance) applyPolicy(t *testing.T, name string, opts policyOptions) {
	t.Helper()
	p := a.buildPolicy(t, name, opts)
	if err := applyObject(p); err != nil {
		t.Fatalf("applying policy %s: %v", name, err)
	}
	t.Cleanup(func() {
		if err := kubectl("delete", "capturepolicy", name, "-n", a.namespace, "--ignore-not-found"); err != nil {
			t.Logf("deleting policy %s: %v", name, err)
		}
	})
}

func (a *acceptance) policyStatus(t *testing.T, name string) (trawlv1alpha1.CapturePolicyStatus, bool) {
	t.Helper()
	out, err := kubectlOut("get", "capturepolicy", name, "-n", a.namespace, "-o", "json")
	if err != nil {
		return trawlv1alpha1.CapturePolicyStatus{}, false
	}
	var p trawlv1alpha1.CapturePolicy
	if err := json.Unmarshal([]byte(out), &p); err != nil {
		t.Fatalf("decoding policy %s: %v", name, err)
	}
	return p.Status, true
}

// waitForPolicy polls until want is satisfied, failing with the phase, the
// counters and the conditions rather than a bare timeout.
func (a *acceptance) waitForPolicy(t *testing.T, name string, timeout time.Duration,
	describe string, want func(trawlv1alpha1.CapturePolicyStatus) bool,
) trawlv1alpha1.CapturePolicyStatus {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last trawlv1alpha1.CapturePolicyStatus
	for time.Now().Before(deadline) {
		st, ok := a.policyStatus(t, name)
		if ok {
			last = st
			if want(st) {
				return st
			}
		}
		time.Sleep(pollInterval)
	}
	t.Fatalf("policy %s did not %s within %s: phase=%q decisions=%+v captures=%d active=%d\n%s",
		name, describe, timeout, last.Phase, last.Decisions,
		last.TotalCaptures, last.ActiveCaptures, formatConditions(last.Conditions))
	return last
}

// policyCaptures lists the CaptureJobs this policy created.
func (a *acceptance) policyCaptures(t *testing.T, policyName string) []trawlv1alpha1.CaptureJob {
	t.Helper()
	out, err := kubectlOut("get", "capturejobs", "-n", a.namespace, "-o", "json")
	if err != nil {
		t.Fatalf("listing captures: %v: %s", err, out)
	}
	var list trawlv1alpha1.CaptureJobList
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		t.Fatalf("decoding captures: %v", err)
	}
	var mine []trawlv1alpha1.CaptureJob
	for _, job := range list.Items {
		if ref := job.Spec.PolicyRef; ref != nil && ref.Name == policyName {
			mine = append(mine, job)
		}
	}
	return mine
}

// waitForFirstCapture polls until the policy has created a capture.
//
// Deliberately "at least one" rather than "exactly n". A spec asserting an
// exact count has to wait out the quiet window anyway, and polling for a count
// would return the moment it was reached and miss a second capture arriving a
// second later - passing on timing rather than on behaviour.
func (a *acceptance) waitForFirstCapture(t *testing.T, policyName string) []trawlv1alpha1.CaptureJob {
	t.Helper()
	deadline := time.Now().Add(policyTriggerTimeout)
	var last []trawlv1alpha1.CaptureJob
	for time.Now().Before(deadline) {
		last = a.policyCaptures(t, policyName)
		if len(last) >= 1 {
			return last
		}
		time.Sleep(pollInterval)
	}
	st, _ := a.policyStatus(t, policyName)
	t.Fatalf("policy %s created no capture within %s: phase=%q decisions=%+v\n%s",
		policyName, policyTriggerTimeout, st.Phase, st.Decisions, formatConditions(st.Conditions))
	return last
}

// --- Synthetic alerts -------------------------------------------------------

// alertFixture is one synthetic Suricata alert attributed to the deployed tap.
//
// Attribution is the part that has to be right. The engine matches a signature
// observation to a policy by the tap UID the record carries, so a fixture that
// invented one would be declined as another tap's traffic and the spec would
// fail for a reason that has nothing to do with what it is testing.
func (a *acceptance) alertFixture(t *testing.T, severity int32, srcIP string, srcPort int32, at time.Time,
) *observation.Observation {
	t.Helper()

	tapName := a.productionTap(t)
	uid, err := kubectlOut("get", "networktap", tapName, "-n", a.namespace, "-o", "jsonpath={.metadata.uid}")
	if err != nil {
		t.Fatalf("reading the tap UID: %v: %s", err, uid)
	}
	iface, err := kubectlOut("get", "networktap", tapName, "-n", a.namespace,
		"-o", "jsonpath={.status.targets[0].interface}")
	if err != nil {
		t.Fatalf("reading the tap interface: %v: %s", err, iface)
	}
	node, err := kubectlOut("get", "networktap", tapName, "-n", a.namespace,
		"-o", "jsonpath={.status.targets[0].nodeName}")
	if err != nil {
		t.Fatalf("reading the tap's observing node: %v: %s", err, node)
	}

	port := func(v int32) *int32 { return &v }
	obs := &observation.Observation{
		SchemaVersion:   observation.SchemaVersion,
		EventTime:       at,
		ObservedAt:      at,
		Source:          observation.Source{Kind: observation.SourceSuricata, Version: "8.0.6"},
		Tap:             &observation.Tap{Namespace: a.namespace, Name: tapName, UID: strings.TrimSpace(uid)},
		Target:          observation.Target{Node: strings.TrimSpace(node), Interface: strings.TrimSpace(iface)},
		ObservationType: observation.TypeSignature,
		Flow: &observation.Flow{
			Protocol: "tcp",
			// RFC 5737 documentation addresses. Never routed, so a capture
			// filtered to them collects nothing and cannot pick up somebody
			// else's traffic - these specs are testing that a capture starts,
			// not what lands in it.
			Source:      observation.Endpoint{IP: srcIP, Port: port(srcPort)},
			Destination: observation.Endpoint{IP: "198.51.100.20", Port: port(22)},
		},
		Details: observation.Details{Signature: &observation.Signature{
			RuleID:   alertRuleID,
			Severity: severity,
			Category: alertCategory,
			Message:  "Trawl acceptance synthetic alert",
			Action:   "allowed",
		}},
	}
	// The record ID is what the cursor suppresses replays by. The pipeline
	// derives it from the record's own content and its deriver is unexported,
	// so this derives one the same way - from the fields that make this alert
	// this alert. Two pushes of the same fixture therefore carry one ID and are
	// suppressed as the replay they are, and two distinct conversations carry
	// two and are not.
	sum := sha256.Sum256(fmt.Appendf(nil, "%s|%d|%d|%d", srcIP, srcPort, severity, at.UnixNano()))
	obs.ID = hex.EncodeToString(sum[:16])
	return obs
}

// pushAlerts writes synthetic alerts into the stream the worker polls.
func (a *acceptance) pushAlerts(t *testing.T, records ...*observation.Observation) {
	t.Helper()
	loki := a.openLoki(t)
	streams := harness.ObservationStreams(records, a.clusterID(t), 0)
	if err := loki.Push(context.Background(), streams); err != nil {
		t.Fatalf("pushing synthetic alerts: %v", err)
	}
}

// --- Specs ------------------------------------------------------------------

func TestAnArmedSignaturePolicyTurnsAnAlertIntoACapture(t *testing.T) {
	// The whole of US4 in one spec. Everything between the alert and the packets
	// is wiring, and wiring is where this project's defects live: the worker's
	// RBAC, its egress to Loki and to the audit sink, the CaptureJob the engine
	// assembles being admitted by the installed webhook, and the capture
	// controller picking it up.
	a := requireAcceptanceCluster(t)
	a.requirePolicySupport(t)

	name := a.policyName(t)
	a.applyPolicy(t, name, defaultPolicyOptions())
	a.waitForPolicy(t, name, policyStatusTimeout, "report itself armed",
		func(s trawlv1alpha1.CapturePolicyStatus) bool {
			return s.Phase == trawlv1alpha1.CapturePolicyArmed
		})

	a.pushAlerts(t, a.alertFixture(t, 2, "192.0.2.10", 39510, time.Now()))

	jobs := a.waitForFirstCapture(t, name)
	job := jobs[0]

	if job.Spec.RequestType != trawlv1alpha1.CaptureRequestPolicy {
		t.Errorf("requestType = %q, want Policy", job.Spec.RequestType)
	}
	if job.Spec.PolicyRef.Generation < 1 {
		t.Error("the capture does not pin the policy generation that was armed")
	}
	// The immutable snapshot is what lets the capture explain itself after the
	// alert has aged out of Loki (FR-032).
	if job.Spec.Trigger == nil || job.Spec.Trigger.Suricata == nil {
		t.Fatal("the capture carries no trigger snapshot")
	}
	if job.Spec.Trigger.Suricata.RuleID != alertRuleID {
		t.Errorf("snapshot rule ID = %d, want %d", job.Spec.Trigger.Suricata.RuleID, alertRuleID)
	}
	if job.Spec.TargetNode == "" {
		t.Error("the capture resolved no target node, so no eligible sensor was found for the alert")
	}
	// And it actually runs. A CaptureJob that is admitted and never scheduled
	// would satisfy everything above.
	a.waitForCapture(t, job.Name, captureCompleteTimeout, "reach a terminal phase",
		func(s trawlv1alpha1.CaptureJobStatus) bool {
			return s.Phase == trawlv1alpha1.CapturePhaseCompleted || s.Phase == trawlv1alpha1.CapturePhaseFailed
		})

	a.waitForPolicy(t, name, policyStatusTimeout, "count the capture it made",
		func(s trawlv1alpha1.CapturePolicyStatus) bool {
			return s.TotalCaptures >= 1 && s.LastCaptureRef != nil && s.LastTriggerTime != nil
		})
}

func TestAnAlertOutsideThePolicysFiltersCapturesNothing(t *testing.T) {
	// The counterpart, and the more important half. A policy that captures on
	// everything is a policy nobody can leave armed, so "did not match" has to
	// be as reliable as "matched" - and it has to be visible, or a policy that
	// is silently matching nothing looks exactly like a quiet network.
	a := requireAcceptanceCluster(t)
	a.requirePolicySupport(t)

	name := a.policyName(t)
	opts := defaultPolicyOptions()
	opts.severities = []int32{1}
	a.applyPolicy(t, name, opts)
	a.waitForPolicy(t, name, policyStatusTimeout, "report itself armed",
		func(s trawlv1alpha1.CapturePolicyStatus) bool {
			return s.Phase == trawlv1alpha1.CapturePolicyArmed
		})

	// Severity 3 against a trigger listing severity 1 only.
	a.pushAlerts(t, a.alertFixture(t, 3, "192.0.2.11", 39511, time.Now()))
	time.Sleep(quietWindow)

	if jobs := a.policyCaptures(t, name); len(jobs) != 0 {
		t.Errorf("a policy listing severity 1 captured %d times on a severity 3 alert", len(jobs))
	}
	st := a.waitForPolicy(t, name, policyStatusTimeout, "count the event it declined",
		func(s trawlv1alpha1.CapturePolicyStatus) bool { return s.Decisions.NotMatched > 0 })
	if st.LastTriggerTime != nil {
		t.Error("an event that did not match moved lastTriggerTime, which is meant to answer " +
			"'when did this policy last see its traffic'")
	}
}

func TestEquivalentAlertsInsideTheCooldownCollapseToOneCapture(t *testing.T) {
	// FR-031. The second alert is a different record describing the same
	// conversation, which is the ordinary case for a signature that fires
	// repeatedly - and capturing it twice would collect the same packets twice
	// while spending the policy's hourly budget on the duplicate.
	a := requireAcceptanceCluster(t)
	a.requirePolicySupport(t)

	name := a.policyName(t)
	a.applyPolicy(t, name, defaultPolicyOptions())
	a.waitForPolicy(t, name, policyStatusTimeout, "report itself armed",
		func(s trawlv1alpha1.CapturePolicyStatus) bool {
			return s.Phase == trawlv1alpha1.CapturePolicyArmed
		})

	now := time.Now()
	a.pushAlerts(t, a.alertFixture(t, 2, "192.0.2.12", 39512, now))
	a.waitForFirstCapture(t, name)

	// Same five-tuple, seconds later, well inside the five-minute cooldown.
	a.pushAlerts(t, a.alertFixture(t, 2, "192.0.2.12", 39512, now.Add(5*time.Second)))
	a.waitForPolicy(t, name, policyStatusTimeout, "record the duplicate",
		func(s trawlv1alpha1.CapturePolicyStatus) bool { return s.Decisions.Duplicate > 0 })

	if jobs := a.policyCaptures(t, name); len(jobs) != 1 {
		t.Errorf("got %d captures for equivalent traffic in one cooldown window, want 1", len(jobs))
	}
}

func TestTwoPoliciesMatchingOneAlertShareOneCapture(t *testing.T) {
	// Settled deliberately: the deduplication key covers the tap, the flow and
	// the cooldown bucket and not the policy, so two policies wanting the same
	// packets get one capture rather than two of the same conversation. Both
	// still record a decision, because each evaluation is its own.
	a := requireAcceptanceCluster(t)
	a.requirePolicySupport(t)

	first := a.policyName(t) + "-a"
	second := a.policyName(t) + "-b"
	a.applyPolicy(t, first, defaultPolicyOptions())
	a.applyPolicy(t, second, defaultPolicyOptions())
	for _, name := range []string{first, second} {
		a.waitForPolicy(t, name, policyStatusTimeout, "report itself armed",
			func(s trawlv1alpha1.CapturePolicyStatus) bool {
				return s.Phase == trawlv1alpha1.CapturePolicyArmed
			})
	}

	a.pushAlerts(t, a.alertFixture(t, 2, "192.0.2.13", 39513, time.Now()))

	names := make([]string, 0, 2)
	for _, name := range []string{first, second} {
		st := a.waitForPolicy(t, name, policyTriggerTimeout, "record a decision about the alert",
			func(s trawlv1alpha1.CapturePolicyStatus) bool {
				return s.Decisions.Matched > 0 || s.Decisions.Duplicate > 0
			})
		if st.LastCaptureRef == nil {
			t.Fatalf("policy %s decided without naming a capture", name)
		}
		names = append(names, st.LastCaptureRef.Name)
	}
	if names[0] != names[1] {
		t.Errorf("the two policies name captures %q and %q; equivalent requests must collapse",
			names[0], names[1])
	}
}

func TestAPolicyStopsCapturingAtItsHourlyLimit(t *testing.T) {
	// The only thing standing between a noisy signature and a capture storm
	// that fills the artifact bucket. Each alert is a distinct conversation, so
	// deduplication does not collapse them and the limit is the only thing that
	// can refuse the last one.
	a := requireAcceptanceCluster(t)
	a.requirePolicySupport(t)

	name := a.policyName(t)
	opts := defaultPolicyOptions()
	opts.perHour = 2
	// A short cooldown so successive alerts fall in different buckets and each
	// one asks for its own capture.
	opts.cooldown = time.Second
	a.applyPolicy(t, name, opts)
	a.waitForPolicy(t, name, policyStatusTimeout, "report itself armed",
		func(s trawlv1alpha1.CapturePolicyStatus) bool {
			return s.Phase == trawlv1alpha1.CapturePolicyArmed
		})

	now := time.Now()
	for i := range 3 {
		a.pushAlerts(t, a.alertFixture(t, 2,
			fmt.Sprintf("192.0.2.%d", 20+i), int32(39520+i), now.Add(time.Duration(i)*10*time.Second)))
	}

	a.waitForPolicy(t, name, policyTriggerTimeout, "refuse the capture over its limit",
		func(s trawlv1alpha1.CapturePolicyStatus) bool { return s.Decisions.RateLimited > 0 })

	if jobs := a.policyCaptures(t, name); len(jobs) > 2 {
		t.Errorf("got %d captures with a limit of 2 per hour", len(jobs))
	}
	st, _ := a.policyStatus(t, name)
	limit := status.Get(st.Conditions, status.TypeWithinRateLimit)
	if limit == nil || limit.Status != metav1.ConditionFalse {
		t.Errorf("WithinRateLimit = %+v, want False while the policy is at its ceiling", limit)
	}
	if st.Phase != trawlv1alpha1.CapturePolicyRateLimited {
		t.Errorf("phase = %q, want RateLimited", st.Phase)
	}
}

func TestADisarmedPolicyReportsWhatItWouldHaveCapturedAndCapturesNothing(t *testing.T) {
	// Arming is the act that starts collecting packets, so a disarmed policy
	// must create nothing. It is still evaluated, because "this rule would have
	// fired N times today" is what an operator needs in order to decide whether
	// to arm it - and a rule they cannot preview is one they arm blind.
	a := requireAcceptanceCluster(t)
	a.requirePolicySupport(t)

	name := a.policyName(t)
	opts := defaultPolicyOptions()
	opts.armed = false
	a.applyPolicy(t, name, opts)
	a.waitForPolicy(t, name, policyStatusTimeout, "report itself disarmed",
		func(s trawlv1alpha1.CapturePolicyStatus) bool {
			return s.Phase == trawlv1alpha1.CapturePolicyDisarmed
		})

	a.pushAlerts(t, a.alertFixture(t, 2, "192.0.2.14", 39514, time.Now()))
	time.Sleep(quietWindow)

	if jobs := a.policyCaptures(t, name); len(jobs) != 0 {
		t.Errorf("a disarmed policy created %d captures", len(jobs))
	}
	st, _ := a.policyStatus(t, name)
	ready := status.Get(st.Conditions, status.TypeReady)
	if ready == nil || ready.Reason != status.ReasonDisarmed {
		t.Errorf("Ready = %+v, want False/Disarmed", ready)
	}
}

func TestRestartingTheWorkerDoesNotRecaptureWhatItAlreadyHandled(t *testing.T) {
	// The alert cursor's whole purpose. The query deliberately overlaps, so a
	// worker that came back without its cursor would re-read every alert in the
	// overlap and re-trigger each one - restarting the worker would manufacture
	// duplicate captures, and it is most likely to be restarted exactly when a
	// policy is firing hard.
	//
	// It is also the reconnect path: the new pod resumes the Hubble stream from
	// its watermark and reports any coverage it could not re-read.
	a := requireAcceptanceCluster(t)
	a.requirePolicySupport(t)

	name := a.policyName(t)
	opts := defaultPolicyOptions()
	// Short, so a re-triggered alert would land in a different bucket and
	// produce a visibly second capture rather than being collapsed by the
	// deduplication key. Without this the spec would pass on the wrong
	// mechanism.
	opts.cooldown = time.Second
	a.applyPolicy(t, name, opts)
	a.waitForPolicy(t, name, policyStatusTimeout, "report itself armed",
		func(s trawlv1alpha1.CapturePolicyStatus) bool {
			return s.Phase == trawlv1alpha1.CapturePolicyArmed
		})

	a.pushAlerts(t, a.alertFixture(t, 2, "192.0.2.15", 39515, time.Now()))
	before := a.waitForFirstCapture(t, name)

	if out, err := kubectlOut("delete", "pod", "-n", a.namespace,
		"-l", "app.kubernetes.io/component=event-worker", "--wait=true"); err != nil {
		t.Fatalf("restarting the event worker: %v: %s", err, out)
	}
	// Back and evaluating again, which is also what proves the restart did not
	// simply stop the worker.
	a.waitForPolicy(t, name, policyTriggerTimeout, "recover after the restart",
		func(s trawlv1alpha1.CapturePolicyStatus) bool {
			return s.Phase == trawlv1alpha1.CapturePolicyArmed
		})
	time.Sleep(quietWindow)

	if after := a.policyCaptures(t, name); len(after) != len(before) {
		t.Errorf("captures went from %d to %d across a restart; the cursor did not survive",
			len(before), len(after))
	}
}

func TestDeletingAPolicyLeavesTheEvidenceItCollected(t *testing.T) {
	// A capture is evidence. The policy-created job carries no owner reference
	// precisely so that deleting the rule does not collect back what it
	// collected - and an owner reference is the kind of thing added in good
	// faith during a tidy-up, which is why this is asserted against a real API
	// server's garbage collector rather than in a unit test.
	a := requireAcceptanceCluster(t)
	a.requirePolicySupport(t)

	name := a.policyName(t)
	a.applyPolicy(t, name, defaultPolicyOptions())
	a.waitForPolicy(t, name, policyStatusTimeout, "report itself armed",
		func(s trawlv1alpha1.CapturePolicyStatus) bool {
			return s.Phase == trawlv1alpha1.CapturePolicyArmed
		})

	a.pushAlerts(t, a.alertFixture(t, 2, "192.0.2.16", 39516, time.Now()))
	jobs := a.waitForFirstCapture(t, name)
	captured := jobs[0].Name

	if out, err := kubectlOut("delete", "capturepolicy", name, "-n", a.namespace); err != nil {
		t.Fatalf("deleting the policy: %v: %s", err, out)
	}
	// The garbage collector is asynchronous, so a capture that was owned would
	// not vanish instantly. Waiting is what makes the assertion mean something.
	time.Sleep(quietWindow)

	if out, err := kubectlOut("get", "capturejob", captured, "-n", a.namespace); err != nil {
		t.Errorf("the capture %s did not survive its policy: %v: %s", captured, err, out)
	}
}

func TestAPolicyWhoseTapIsGoneReportsDegradedRatherThanQuiet(t *testing.T) {
	// Absence of captures has two explanations and they lead to opposite
	// actions. A policy pointed at a tap that does not exist must say so rather
	// than sit at Armed reporting nothing, because "armed and quiet" is what an
	// operator reads as "the network is fine".
	a := requireAcceptanceCluster(t)
	a.requirePolicySupport(t)

	name := a.policyName(t)
	p := a.buildPolicy(t, name, defaultPolicyOptions())
	p.Spec.TapRef.Name = "no-such-tap-" + a.runID
	if err := applyObject(p); err != nil {
		t.Fatalf("applying policy %s: %v", name, err)
	}
	t.Cleanup(func() {
		if err := kubectl("delete", "capturepolicy", name, "-n", a.namespace, "--ignore-not-found"); err != nil {
			t.Logf("deleting policy %s: %v", name, err)
		}
	})

	st := a.waitForPolicy(t, name, policyStatusTimeout, "report itself degraded",
		func(s trawlv1alpha1.CapturePolicyStatus) bool {
			return s.Phase == trawlv1alpha1.CapturePolicyDegraded
		})

	tap := status.Get(st.Conditions, status.TypeTapResolved)
	if tap == nil || tap.Status != metav1.ConditionFalse || tap.Reason != status.ReasonTapNotFound {
		t.Errorf("TapResolved = %+v, want False/TapNotFound", tap)
	}
}

func TestThePolicyCapturesCarryADeduplicationKeyTheClusterAccepts(t *testing.T) {
	// The schema pattern-validates the deduplication key and the trigger
	// fingerprint as sha256 digests, and the engine derives both. A malformed
	// one is not a wrong string but a rejected CaptureJob - the capture is lost
	// over a field that exists only to describe it.
	a := requireAcceptanceCluster(t)
	a.requirePolicySupport(t)

	name := a.policyName(t)
	a.applyPolicy(t, name, defaultPolicyOptions())
	a.waitForPolicy(t, name, policyStatusTimeout, "report itself armed",
		func(s trawlv1alpha1.CapturePolicyStatus) bool {
			return s.Phase == trawlv1alpha1.CapturePolicyArmed
		})

	a.pushAlerts(t, a.alertFixture(t, 2, "192.0.2.17", 39517, time.Now()))
	jobs := a.waitForFirstCapture(t, name)
	job := jobs[0]

	if want := policy.CaptureJobName(job.Spec.DeduplicationKey); job.Name != want {
		t.Errorf("capture is named %q, want %q derived from its own deduplication key", job.Name, want)
	}
	if !strings.HasPrefix(job.Spec.Trigger.Fingerprint, "sha256:") {
		t.Errorf("trigger fingerprint = %q, want a sha256 digest", job.Spec.Trigger.Fingerprint)
	}
}
