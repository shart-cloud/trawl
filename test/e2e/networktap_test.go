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

// Cluster acceptance for NetworkTap (T034).
//
// Everything here is asserted against a deployed Trawl: a real admission
// webhook, a real reconciler, a real DaemonSet scheduled onto a real node, and
// the real audit ledger. The unit and envtest suites already cover the same
// rules against fakes; what they cannot show is that the rules survive being
// wired together and installed, which is the seam every defect in this
// codebase's history has lived in.
//
// It runs against the single live install rather than a per-run namespace. The
// CRD and both webhook configurations are cluster-scoped singletons and
// config.Validate pins the system namespace, so an isolated copy would be a
// second installation path maintained only for tests - and a test that proves
// a second installation path works proves nothing about the one in use.
//
// Living in the real namespace sets the rules these specs follow:
//
//   - Every tap is created by the test, named for the run, and deleted in
//     cleanup. No spec touches a tap it did not create.
//
//   - Taps bind the loopback interface. It exists on every node and carries no
//     traffic anyone depends on, so a failing spec cannot disturb what the
//     production tap observes.
//
//   - The one spec that must break a shared dependency - the audit ledger - is
//     opt-in, because it briefly refuses mutations for the whole installation.
//
//     go test -tags=acceptance ./test/e2e/ -v
package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/audit"
	"trawl.cloud/trawl/internal/config"
	"trawl.cloud/trawl/internal/observation"
	"trawl.cloud/trawl/internal/storage"
	"trawl.cloud/trawl/test/e2e/traffic"
)

const (
	// acceptanceInterface is the interface every tap here binds.
	//
	// Loopback is chosen for what it is not: it is not the interface the
	// production tap watches, so a spec that leaves an analyzer crash-looping
	// cannot cost anyone visibility of real traffic. Analyzer health is
	// observed liveness rather than record volume, so a quiet interface still
	// reports healthy and the happy-path specs remain meaningful.
	acceptanceInterface = "lo"

	// activeTimeout bounds how long a valid tap may take to reach Active. It
	// covers scheduling, the content init containers' upstream fetch, and the
	// first status heartbeat. SC-002 allows fifteen minutes for a first
	// observation; this is the tighter budget for the tap merely being ready.
	activeTimeout = 6 * time.Minute

	// settleTimeout bounds a status change on an already-running tap, where
	// nothing has to be pulled or fetched.
	settleTimeout = 3 * time.Minute

	// pollInterval is how often status is re-read while waiting.
	pollInterval = 2 * time.Second

	// starvedMemory is a memory ceiling no Suricata can start under. It is the
	// lever for the analyzer-failure scenario: requests and limits are equal so
	// the webhook's requests-exceed-limits rule is satisfied and the failure
	// happens where the test means it to, in the analyzer rather than in
	// admission.
	starvedMemory = "24Mi"

	// healthyMemory is what an analyzer is asked for when it is meant to run,
	// and healthyMemoryLimit is the ceiling it is given.
	//
	// The two differ, and copy the deployed tap's numbers. Setting the ceiling
	// equal to the request looked tidier and was wrong: Suricata grows past a
	// gigabyte after a minute or so, so the short specs finished before it
	// mattered and the one long spec had its sensor OOMKilled underneath it.
	// The tap then left Active for a reason that had nothing to do with what
	// that spec was testing.
	healthyMemory      = "1Gi"
	healthyMemoryLimit = "3Gi"
)

// acceptance holds the deployed environment the specs share.
type acceptance struct {
	namespace string
	node      string
	runID     string
	skip      string

	ledgerOnce sync.Once
	ledger     storage.Store
	ledgerErr  error
}

var (
	acceptOnce sync.Once
	accept     acceptance
)

// requireAcceptanceCluster attaches to the deployed Trawl, skipping when there
// is none.
//
// A missing cluster is a skip for the same reason the investigation suite skips
// one: this test is meaningful only against a running installation, and a red
// build on a laptop without a kubeconfig teaches people to ignore the colour.
func requireAcceptanceCluster(t *testing.T) *acceptance {
	t.Helper()
	acceptOnce.Do(setupAcceptance)
	if accept.skip != "" {
		t.Skip(accept.skip)
	}
	return &accept
}

func setupAcceptance() {
	accept.namespace = envOr("TRAWL_E2E_NAMESPACE", "trawl-system")
	accept.runID = fmt.Sprintf("%d", time.Now().UnixNano()%1e9)

	// The CRD is the cheapest proof that this is a Trawl cluster rather than
	// merely a reachable one.
	if out, err := kubectlOut("get", "crd", "networktaps.trawl.cloud"); err != nil {
		accept.skip = fmt.Sprintf("no deployed Trawl to accept against: %v: %s", err, out)
		return
	}

	node, err := kubectlOut("get", "nodes",
		"-o", "jsonpath={.items[0].metadata.name}")
	if err != nil || strings.TrimSpace(node) == "" {
		accept.skip = fmt.Sprintf("no schedulable node to place a sensor on: %v", err)
		return
	}
	accept.node = strings.TrimSpace(node)
}

// --- Taps -------------------------------------------------------------------

// tapOptions are the knobs the specs vary. Everything else about a tap is held
// constant so a failure points at the thing under test.
type tapOptions struct {
	iface           string
	suricataMemory  string
	suricataEnabled bool
	// nodeLabel selects the target. Empty means this run's node by hostname.
	nodeLabel map[string]string
}

func defaultTapOptions() tapOptions {
	return tapOptions{
		iface:           acceptanceInterface,
		suricataMemory:  healthyMemory,
		suricataEnabled: true,
	}
}

// tapName is unique per spec and per run, so a leaked tap from an interrupted
// run is visibly not this one's and a concurrent run cannot be mistaken for it.
func (a *acceptance) tapName(t *testing.T) string {
	t.Helper()
	name := strings.ToLower(t.Name())
	name = strings.NewReplacer("test", "", "_", "-", "/", "-").Replace(name)
	if len(name) > 30 {
		name = name[:30]
	}
	return fmt.Sprintf("acc-%s-%s", strings.Trim(name, "-"), a.runID)
}

// buildTap renders the object rather than a YAML template.
//
// Built from the API types, a field this test sets that the API later renames
// fails to compile. Rendered from a string, it would keep applying and start
// silently testing a default.
func (a *acceptance) buildTap(name string, opts tapOptions) *trawlv1alpha1.NetworkTap {
	selector := opts.nodeLabel
	if selector == nil {
		selector = map[string]string{"kubernetes.io/hostname": a.node}
	}
	analyzer := func(memory string, enabled bool) trawlv1alpha1.AnalyzerConfig {
		// The starved fixture pins the ceiling to the request so the analyzer
		// cannot start; anything meant to run gets the deployed tap's headroom.
		limit := healthyMemoryLimit
		if memory != healthyMemory {
			limit = memory
		}
		return trawlv1alpha1.AnalyzerConfig{
			Enabled: enabled,
			Resources: &corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("100m"),
					corev1.ResourceMemory: resource.MustParse(memory),
				},
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("1"),
					corev1.ResourceMemory: resource.MustParse(limit),
				},
			},
		}
	}
	return &trawlv1alpha1.NetworkTap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: trawlv1alpha1.GroupVersion.String(),
			Kind:       "NetworkTap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: a.namespace,
			Labels:    map[string]string{"trawl.cloud/acceptance-run": a.runID},
		},
		Spec: trawlv1alpha1.NetworkTapSpec{
			Type: trawlv1alpha1.TapSourceNodeInterface,
			Mode: trawlv1alpha1.TapModePassive,
			NodeInterface: &trawlv1alpha1.InterfaceSource{
				Interface:    opts.iface,
				NodeSelector: metav1.LabelSelector{MatchLabels: selector},
			},
			Analyzers: trawlv1alpha1.AnalyzerSelection{
				Suricata: analyzer(opts.suricataMemory, opts.suricataEnabled),
				Zeek:     analyzer(healthyMemory, true),
			},
		},
	}
}

// applyTap applies a tap and registers its deletion.
func (a *acceptance) applyTap(t *testing.T, name string, opts tapOptions) {
	t.Helper()
	if err := a.apply(a.buildTap(name, opts)); err != nil {
		t.Fatalf("applying tap %s: %v", name, err)
	}
	t.Cleanup(func() { a.deleteTap(t, name) })
}

// updateTap re-applies a tap with changed options, without registering another
// cleanup.
func (a *acceptance) updateTap(t *testing.T, name string, opts tapOptions) {
	t.Helper()
	if err := a.apply(a.buildTap(name, opts)); err != nil {
		t.Fatalf("updating tap %s: %v", name, err)
	}
}

func (a *acceptance) apply(tap *trawlv1alpha1.NetworkTap) error {
	return applyObject(tap)
}

// applyObject applies any object built from the API types.
//
// The object travels on stdin rather than through a rendered file so nothing
// this test builds can be left behind on disk for a later run to apply by
// accident.
func applyObject(obj any) error {
	doc, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("encoding object: %w", err)
	}
	// #nosec G204 -- the arguments are constants; the object travels on stdin.
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(string(doc))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("kubectl apply: %w: %s", err, out)
	}
	return nil
}

// deleteTap removes a tap and waits for it to be gone.
//
// Waiting matters: the finalizer is what removes the sensor DaemonSet, and a
// spec that returned while its pods were still terminating would leave the next
// one competing for the node's remaining pod slots.
func (a *acceptance) deleteTap(t *testing.T, name string) {
	t.Helper()
	if out, err := kubectlOut("delete", "networktap", name,
		"-n", a.namespace, "--ignore-not-found", "--wait=true",
		"--timeout=2m"); err != nil {
		t.Errorf("deleting tap %s: %v: %s", name, err, out)
	}
}

// tapStatus reads one tap's status, or reports that it is gone.
func (a *acceptance) tapStatus(t *testing.T, name string) (trawlv1alpha1.NetworkTapStatus, bool) {
	t.Helper()
	out, err := kubectlOut("get", "networktap", name, "-n", a.namespace,
		"-o", "jsonpath={.status}")
	if err != nil {
		return trawlv1alpha1.NetworkTapStatus{}, false
	}
	if strings.TrimSpace(out) == "" {
		return trawlv1alpha1.NetworkTapStatus{}, true
	}
	var status trawlv1alpha1.NetworkTapStatus
	if err := json.Unmarshal([]byte(out), &status); err != nil {
		t.Fatalf("decoding status of %s: %v: %s", name, err, out)
	}
	return status, true
}

// waitForTap polls until want is satisfied, and fails with the last status it
// saw rather than a bare timeout.
func (a *acceptance) waitForTap(t *testing.T, name string, timeout time.Duration,
	describe string, want func(trawlv1alpha1.NetworkTapStatus) bool) trawlv1alpha1.NetworkTapStatus {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last trawlv1alpha1.NetworkTapStatus
	for time.Now().Before(deadline) {
		status, exists := a.tapStatus(t, name)
		if !exists {
			t.Fatalf("tap %s disappeared while waiting for %s", name, describe)
		}
		last = status
		if want(status) {
			return status
		}
		time.Sleep(pollInterval)
	}
	t.Fatalf("tap %s did not reach %s within %s; last status was phase=%q "+
		"matched=%d ready=%d conditions=%s",
		name, describe, timeout, last.Phase, last.MatchedTargets,
		last.ReadyTargets, formatConditions(last.Conditions))
	return last
}

func formatConditions(conds []metav1.Condition) string {
	parts := make([]string, 0, len(conds))
	for _, c := range conds {
		parts = append(parts, fmt.Sprintf("%s=%s(%s: %s)",
			c.Type, c.Status, c.Reason, c.Message))
	}
	return strings.Join(parts, " ")
}

func conditionIs(status trawlv1alpha1.NetworkTapStatus, name string, want metav1.ConditionStatus) bool {
	for _, c := range status.Conditions {
		if c.Type == name {
			return c.Status == want
		}
	}
	return false
}

func condition(t *testing.T, status trawlv1alpha1.NetworkTapStatus, name string) metav1.Condition {
	t.Helper()
	for _, c := range status.Conditions {
		if c.Type == name {
			return c
		}
	}
	t.Fatalf("no %s condition; conditions were %s", name, formatConditions(status.Conditions))
	return metav1.Condition{}
}

// isActive is the whole-tap readiness the specs mean by "working".
func isActive(status trawlv1alpha1.NetworkTapStatus) bool {
	return status.Phase == trawlv1alpha1.TapPhaseActive &&
		status.ReadyTargets > 0 &&
		conditionIs(status, "WorkloadReady", metav1.ConditionTrue) &&
		conditionIs(status, "AnalyzersHealthy", metav1.ConditionTrue)
}

// --- The audit ledger -------------------------------------------------------

// recordsInfix mirrors the ledger layout in internal/audit/sink.go. It is
// spelled out rather than imported because it is unexported there, and reading
// the ledger the way an auditor would - by key - is the point of this check. A
// change to the layout should fail here loudly.
const recordsInfix = "records/"

// openLedger builds a client for the deployed audit bucket.
//
// It reads the endpoint and bucket from the installation ConfigMap and the
// credentials from the audit Secret, so the test addresses the ledger the
// manager was configured to write to rather than one the test decided on. The
// audit credential is used, not the artifact one: if the two were interchanged,
// ADR-0003's separation would be broken and this would still pass, so using the
// wrong one would hide exactly the defect the separation exists to prevent.
func (a *acceptance) openLedger(t *testing.T) storage.Store {
	t.Helper()
	a.ledgerOnce.Do(func() { a.ledger, a.ledgerErr = a.connectLedger() })
	if a.ledgerErr != nil {
		t.Fatalf("reaching the audit ledger: %v", a.ledgerErr)
	}
	return a.ledger
}

func (a *acceptance) connectLedger() (storage.Store, error) {
	raw, err := kubectlOut("get", "configmap", "trawl-config", "-n", a.namespace,
		"-o", "jsonpath={.data.config\\.yaml}")
	if err != nil {
		return nil, fmt.Errorf("reading the installation config: %w: %s", err, raw)
	}
	installCfg, err := config.Load([]byte(raw))
	if err != nil {
		return nil, fmt.Errorf("parsing the installation config: %w", err)
	}

	credsDir, err := a.writeLedgerCredentials()
	if err != nil {
		return nil, err
	}

	endpoint, err := a.forwardMinIO(installCfg.AuditLedger.Endpoint)
	if err != nil {
		return nil, err
	}

	return storage.NewS3Store(config.BucketConfig{
		Endpoint:        endpoint,
		Bucket:          installCfg.AuditLedger.Bucket,
		Region:          installCfg.AuditLedger.Region,
		CredentialsPath: credsDir,
		UseTLS:          false,
	})
}

// writeLedgerCredentials materialises the audit Secret in the layout
// storage.NewS3Store reads, which is the same layout the manager mounts.
func (a *acceptance) writeLedgerCredentials() (string, error) {
	dir, err := os.MkdirTemp("", "trawl-acceptance-audit-")
	if err != nil {
		return "", fmt.Errorf("creating a credentials directory: %w", err)
	}
	for _, key := range []string{"accessKeyID", "secretAccessKey"} {
		value, err := kubectlOut("get", "secret", "trawl-audit-ledger",
			"-n", a.namespace, "-o", "jsonpath={.data."+key+"}")
		if err != nil {
			return "", fmt.Errorf("reading %s from the audit secret: %w: %s", key, err, value)
		}
		decoded, err := decodeBase64(value)
		if err != nil {
			return "", fmt.Errorf("decoding %s: %w", key, err)
		}
		// 0600: the credential is written to a developer's machine for the
		// life of the run, so it gets the narrowest mode that still works.
		if err := os.WriteFile(filepath.Join(dir, key), decoded, 0o600); err != nil {
			return "", fmt.Errorf("writing %s: %w", key, err)
		}
	}
	return dir, nil
}

// forwardMinIO opens a tunnel to the storage service for the whole run.
//
// The in-cluster endpoint is a Service DNS name the test process cannot
// resolve, so the host and port are taken from it and the forward is made to
// the same Service. Like the investigation suite's Loki forward, this is not
// torn down per test; the process owns it for its lifetime.
func (a *acceptance) forwardMinIO(clusterEndpoint string) (string, error) {
	service, port, ok := strings.Cut(clusterEndpoint, ":")
	if !ok {
		return "", fmt.Errorf("audit endpoint %q has no port", clusterEndpoint)
	}
	service, _, _ = strings.Cut(service, ".")

	// The local port is claimed by the kernel rather than fixed in this file.
	//
	// A constant looked simpler and hid a failure that is hard to read. A
	// forward left behind by an earlier run still holds the port and still
	// accepts connections, while the pod behind it is gone - so a fresh run
	// binds nothing, dials the stale forward, and fails on the first ledger
	// read with a closed connection rather than anything naming the cause.
	// This suite makes that likely rather than rare: the ledger-outage spec
	// deletes the very pod a forward points at.
	local, err := reserveLocalPort()
	if err != nil {
		return "", err
	}

	// #nosec G204 -- the service name and port come from the installation
	// ConfigMap, which is cluster configuration rather than user input.
	cmd := exec.Command("kubectl", "port-forward", "-n", a.namespace,
		"svc/"+service, fmt.Sprintf("%s:%s", localPort(local), port))
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("starting kubectl port-forward to %s: %w", service, err)
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := net.DialTimeout("tcp", local, 2*time.Second); err == nil {
			_ = conn.Close()
			return local, nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	return "", fmt.Errorf("the audit ledger did not answer on %s within 30s", local)
}

// reserveLocalPort returns a loopback address nothing else is listening on.
func reserveLocalPort() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("claiming a local port: %w", err)
	}
	address := listener.Addr().String()
	// Closed immediately so kubectl can take it. The window between here and
	// the forward binding is the price of asking the kernel for a free port;
	// nothing else on a test machine is racing for ephemeral ports.
	if err := listener.Close(); err != nil {
		return "", fmt.Errorf("releasing the local port: %w", err)
	}
	return address, nil
}

func localPort(address string) string {
	_, port, _ := strings.Cut(address, ":")
	return port
}

// ledgerCursor is the newest record key in the ledger, or "" when it is empty.
//
// The specs mark their window with this rather than with a wall-clock instant.
// The ledger's keys are chronological by construction - that ordering is what
// makes replay resumable - so a key taken before an action is an exact
// "everything after this" marker in the ledger's own terms.
//
// A timestamp is not, and the difference is not hypothetical. The runner's
// clock and the cluster's differ by a fraction of a second, so a window opened
// with time.Now() immediately before a fast mutation excludes the record that
// mutation writes. The first draft of these specs did exactly that, and read as
// a missing delete audit record - a serious-looking security finding that was
// entirely an artefact of comparing two clocks.
func (a *acceptance) ledgerCursor(t *testing.T) string {
	t.Helper()
	objects := a.ledgerObjects(t)
	if len(objects) == 0 {
		return ""
	}
	return objects[len(objects)-1].Key
}

func (a *acceptance) ledgerObjects(t *testing.T) []storage.ObjectInfo {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	objects, err := a.openLedger(t).List(ctx, audit.DefaultPrefix+recordsInfix, "")
	if err != nil {
		t.Fatalf("listing the audit ledger: %v", err)
	}
	return objects
}

// ledgerRecordsAfter returns the records committed after a cursor, oldest first.
func (a *acceptance) ledgerRecordsAfter(t *testing.T, cursor string) []audit.Record {
	t.Helper()
	store := a.openLedger(t)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	var records []audit.Record
	for _, obj := range a.ledgerObjects(t) {
		// List includes the cursor object: replay re-delivers its cursor record
		// rather than risk skipping one. A window that wants what came after
		// has to drop it here.
		if obj.Key <= cursor {
			continue
		}
		body, err := store.Get(ctx, obj.Key)
		if err != nil {
			t.Fatalf("reading ledger object %s: %v", obj.Key, err)
		}
		rec, err := audit.Decode(body)
		if err != nil {
			t.Fatalf("decoding ledger object %s: %v", obj.Key, err)
		}
		// The ledger key the record claims must be the key it was found at. A
		// record that names a different object is one whose durability was
		// acknowledged against something other than what was stored.
		if rec.LedgerKey != obj.Key {
			t.Errorf("ledger object %s carries ledgerKey %q; a record must name the object it is stored as",
				obj.Key, rec.LedgerKey)
		}
		records = append(records, rec)
	}
	return records
}

// controllerActor is the identity the manager mutates taps under.
//
// The manager's own writes - adding the finalizer, updating status - go through
// the same webhook and are audited like anyone else's, and every create is
// followed by one within milliseconds. A spec asserting on what a user did has
// to say which records are the user's, or it is asserting on a race with the
// reconciler.
func (a *acceptance) controllerActor() string {
	return "system:serviceaccount:" + a.namespace + ":trawl-controller-manager"
}

// requireAuditRecord asserts that exactly one durable record describes a user's
// action on a tap, and returns it.
func (a *acceptance) requireAuditRecord(t *testing.T, cursor, action, tapName string) audit.Record {
	t.Helper()

	// The commit happens inside admission, so the record is durable before the
	// API call returns. Polling here would hide a sink that acknowledged early.
	var byUser, byController []audit.Record
	for _, rec := range a.ledgerRecordsAfter(t, cursor) {
		if rec.Action != action || rec.Resource.Name != tapName {
			continue
		}
		if rec.Actor.Username == a.controllerActor() {
			byController = append(byController, rec)
			continue
		}
		byUser = append(byUser, rec)
	}
	if len(byUser) != 1 {
		t.Fatalf("want exactly one %s record for %s written by a user, found %d "+
			"(the reconciler wrote %d more)",
			action, tapName, len(byUser), len(byController))
	}

	rec := byUser[0]
	if rec.Decision != audit.DecisionAllowed {
		t.Errorf("%s on %s recorded decision %q, want %q",
			action, tapName, rec.Decision, audit.DecisionAllowed)
	}
	if rec.CommittedAt.IsZero() {
		t.Errorf("%s on %s has no committedAt; the sink acknowledged without verifying", action, tapName)
	}
	if rec.Resource.Namespace != a.namespace || rec.Resource.Kind != "NetworkTap" {
		t.Errorf("%s recorded resource %s/%s %s, want a NetworkTap in %s",
			action, rec.Resource.Namespace, rec.Resource.Kind,
			rec.Resource.Name, a.namespace)
	}
	if rec.Actor.Username == "" {
		t.Errorf("%s on %s recorded no actor; an audit record that cannot answer \"who\" is not an audit record",
			action, tapName)
	}
	return rec
}

// --- Specs ------------------------------------------------------------------

// A valid tap becomes Active, and admitting it is durably recorded.
func TestAValidTapBecomesActiveAndIsRecorded(t *testing.T) {
	a := requireAcceptanceCluster(t)
	name := a.tapName(t)
	cursor := a.ledgerCursor(t)

	a.applyTap(t, name, defaultTapOptions())
	status := a.waitForTap(t, name, activeTimeout, "Active", isActive)

	if status.MatchedTargets != 1 {
		t.Errorf("matched %d targets, want the one node the selector names", status.MatchedTargets)
	}
	if len(status.Targets) != 1 {
		t.Fatalf("status carries %d targets, want 1", len(status.Targets))
	}
	target := status.Targets[0]
	if target.NodeName != a.node {
		t.Errorf("target reports node %q, want %q", target.NodeName, a.node)
	}
	if target.Interface != acceptanceInterface {
		t.Errorf("target reports interface %q, want %q", target.Interface, acceptanceInterface)
	}
	if len(target.Analyzers) != 2 {
		t.Errorf("target reports %d analyzers, want Suricata and Zeek", len(target.Analyzers))
	}
	for _, an := range target.Analyzers {
		if !an.Healthy {
			t.Errorf("analyzer %s is unhealthy on an Active tap: %s", an.Name, an.Reason)
		}
		if an.Version == "" {
			t.Errorf("analyzer %s reports no version; the status is describing a process it has not identified", an.Name)
		}
	}

	rec := a.requireAuditRecord(t, cursor, audit.ActionNetworkTapCreate, name)
	t.Logf("active: %d target(s), audited as %s by %s", status.ReadyTargets, rec.Action, rec.Actor.Username)
}

// Changing a tap rolls the change out, and the change is durably recorded.
func TestUpdatingATapRollsOutAndIsRecorded(t *testing.T) {
	a := requireAcceptanceCluster(t)
	name := a.tapName(t)

	a.applyTap(t, name, defaultTapOptions())
	before := a.waitForTap(t, name, activeTimeout, "Active", isActive)

	cursor := a.ledgerCursor(t)
	opts := defaultTapOptions()
	opts.suricataEnabled = false
	a.updateTap(t, name, opts)

	// The observed generation is what proves the reconciler acted on this
	// change rather than the test reading the previous rollout's status back.
	after := a.waitForTap(t, name, settleTimeout, "the Zeek-only spec", func(s trawlv1alpha1.NetworkTapStatus) bool {
		if s.ObservedGeneration <= before.ObservedGeneration || !isActive(s) {
			return false
		}
		return len(s.Targets) == 1 && len(s.Targets[0].Analyzers) == 1
	})

	if got := after.Targets[0].Analyzers[0].Name; got != trawlv1alpha1.AnalyzerZeek {
		t.Errorf("the surviving analyzer is %q, want Zeek; disabling Suricata removed the wrong one", got)
	}

	a.requireAuditRecord(t, cursor, audit.ActionNetworkTapUpdate, name)
	t.Logf("updated: generation %d -> %d, analyzers %d -> %d",
		before.ObservedGeneration, after.ObservedGeneration,
		len(before.Targets[0].Analyzers), len(after.Targets[0].Analyzers))
}

// Deleting a tap removes its workload, and the deletion is durably recorded.
//
// Deletion is the action an attacker would use to blind the sensor, so it is
// the one whose record matters most.
func TestDeletingATapRemovesItsWorkloadAndIsRecorded(t *testing.T) {
	a := requireAcceptanceCluster(t)
	name := a.tapName(t)

	a.applyTap(t, name, defaultTapOptions())
	a.waitForTap(t, name, activeTimeout, "Active", isActive)

	daemonSets := a.sensorDaemonSets(t, name)
	if len(daemonSets) == 0 {
		t.Fatalf("an Active tap owns no sensor DaemonSet; nothing is capturing")
	}

	cursor := a.ledgerCursor(t)
	a.deleteTap(t, name)

	if _, exists := a.tapStatus(t, name); exists {
		t.Errorf("tap %s still exists after a completed delete", name)
	}
	// The finalizer owns this. If the DaemonSet outlived the tap, a deleted tap
	// would keep capturing with nothing left to describe why.
	if remaining := a.sensorDaemonSets(t, name); len(remaining) != 0 {
		t.Errorf("deleting %s left %d sensor DaemonSet(s) behind: %v", name, len(remaining), remaining)
	}

	a.requireAuditRecord(t, cursor, audit.ActionNetworkTapDelete, name)
	t.Logf("deleted: %d DaemonSet(s) removed with the tap", len(daemonSets))
}

// sensorDaemonSets lists the DaemonSets a tap owns.
func (a *acceptance) sensorDaemonSets(t *testing.T, tapName string) []string {
	t.Helper()
	out, err := kubectlOut("get", "daemonset", "-n", a.namespace,
		"-o", "jsonpath={range .items[?(@.metadata.ownerReferences[0].name==\""+tapName+"\")]}{.metadata.name}{\"\\n\"}{end}")
	if err != nil {
		t.Fatalf("listing sensor DaemonSets: %v: %s", err, out)
	}
	var names []string
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		if line != "" {
			names = append(names, line)
		}
	}
	return names
}

// sensorPods counts the pods a tap's DaemonSets are currently running.
//
// This is the question "is anything capturing", which the DaemonSet's desired
// count answers and the existence of the object does not.
func (a *acceptance) sensorPods(t *testing.T, tapName string) int {
	t.Helper()
	total := 0
	for _, ds := range a.sensorDaemonSets(t, tapName) {
		out, err := kubectlOut("get", "daemonset", ds, "-n", a.namespace,
			"-o", "jsonpath={.status.desiredNumberScheduled}")
		if err != nil {
			t.Fatalf("reading DaemonSet %s: %v: %s", ds, err, out)
		}
		desired, err := strconv.Atoi(strings.TrimSpace(out))
		if err != nil {
			t.Fatalf("DaemonSet %s reported desiredNumberScheduled %q: %v", ds, out, err)
		}
		total += desired
	}
	return total
}

// A tap naming an interface no node has never claims to be working.
//
// The failure that matters is not the error; it is a tap that reports Active
// while capturing nothing, which is indistinguishable from a quiet network.
func TestATapOnAMissingInterfaceNeverReportsActive(t *testing.T) {
	a := requireAcceptanceCluster(t)
	name := a.tapName(t)

	opts := defaultTapOptions()
	opts.iface = "trawlnope0"
	a.applyTap(t, name, opts)

	status := a.waitForTap(t, name, settleTimeout, "a workload that is not ready",
		func(s trawlv1alpha1.NetworkTapStatus) bool {
			return conditionIs(s, "WorkloadReady", metav1.ConditionFalse)
		})

	if status.Phase == trawlv1alpha1.TapPhaseActive {
		t.Errorf("a tap on a missing interface reports phase %q", status.Phase)
	}
	if status.ReadyTargets != 0 {
		t.Errorf("a tap on a missing interface reports %d ready target(s)", status.ReadyTargets)
	}

	// The target still resolves: the node exists, only the interface does not.
	// Reporting no targets here would misdescribe the fault as a selector
	// problem and send an operator to the wrong field.
	if status.MatchedTargets != 1 {
		t.Errorf("matched %d targets, want the node the selector names; the fault is the interface, not the selector",
			status.MatchedTargets)
	}
	t.Logf("missing interface: phase=%q ready=%d, %s",
		status.Phase, status.ReadyTargets,
		condition(t, status, "WorkloadReady").Message)
}

// A target that stops matching is reported as gone, and returns when it does.
//
// This is the disappearing-target and recovery pair. It moves a label rather
// than a node: a single-node cluster has no spare node to drain, and draining
// the only one would take the installation down to prove a status field.
func TestADisappearingTargetIsReportedAndRecovers(t *testing.T) {
	a := requireAcceptanceCluster(t)
	name := a.tapName(t)
	label := "trawl.cloud/acceptance-" + a.runID

	opts := defaultTapOptions()
	opts.nodeLabel = map[string]string{label: "yes"}
	a.applyTap(t, name, opts)

	// No node carries the label yet, so the tap starts with nothing to place.
	empty := a.waitForTap(t, name, settleTimeout, "zero matched targets",
		func(s trawlv1alpha1.NetworkTapStatus) bool { return s.MatchedTargets == 0 })
	if empty.Phase == trawlv1alpha1.TapPhaseActive {
		t.Errorf("a tap matching no node reports phase %q", empty.Phase)
	}

	a.labelNode(t, label, "yes")
	appeared := a.waitForTap(t, name, activeTimeout, "Active after the target appeared", isActive)
	if appeared.MatchedTargets != 1 {
		t.Fatalf("labelling the node matched %d targets, want 1", appeared.MatchedTargets)
	}

	a.unlabelNode(t, label)
	gone := a.waitForTap(t, name, settleTimeout, "zero matched targets after the label was removed",
		func(s trawlv1alpha1.NetworkTapStatus) bool { return s.MatchedTargets == 0 })
	if gone.ReadyTargets != 0 {
		t.Errorf("a tap whose target disappeared reports %d ready target(s)", gone.ReadyTargets)
	}
	// The DaemonSet object stays - the tap still owns it, and it is what the
	// sensor comes back on. What must go is the capture: its node selector no
	// longer matches, so it scales itself to zero pods. Asserting the object
	// were deleted would be asserting the wrong thing and would fail against a
	// correctly behaving cluster.
	if scheduled := a.sensorPods(t, name); scheduled != 0 {
		t.Errorf("%d sensor pod(s) are still scheduled for a tap with no targets", scheduled)
	}

	// Recovery: the same tap, unchanged, comes back when the target does.
	a.labelNode(t, label, "yes")
	recovered := a.waitForTap(t, name, activeTimeout, "Active again", isActive)
	t.Logf("disappearing target: matched 0 -> 1 -> 0 -> %d without touching the spec",
		recovered.MatchedTargets)
}

func (a *acceptance) labelNode(t *testing.T, key, value string) {
	t.Helper()
	if out, err := kubectlOut("label", "node", a.node, key+"="+value, "--overwrite"); err != nil {
		t.Fatalf("labelling node %s: %v: %s", a.node, err, out)
	}
	t.Cleanup(func() { _ = kubectl("label", "node", a.node, key+"-") })
}

func (a *acceptance) unlabelNode(t *testing.T, key string) {
	t.Helper()
	if out, err := kubectlOut("label", "node", a.node, key+"-"); err != nil {
		t.Fatalf("removing label %s from node %s: %v: %s", key, a.node, err, out)
	}
}

// An analyzer that cannot run is reported, and the tap recovers when it can.
//
// The lever is a memory ceiling Suricata cannot start under. Corrupt custom
// content would not do: T047a makes the content path fall back to upstream on
// purpose, so a bad reference leaves a healthy analyzer and would have this
// test asserting the opposite of the designed behaviour.
func TestAFailedAnalyzerIsReportedAndRecovers(t *testing.T) {
	a := requireAcceptanceCluster(t)
	name := a.tapName(t)

	opts := defaultTapOptions()
	opts.suricataMemory = starvedMemory
	a.applyTap(t, name, opts)

	failed := a.waitForTap(t, name, settleTimeout, "a workload that is not ready",
		func(s trawlv1alpha1.NetworkTapStatus) bool {
			return conditionIs(s, "WorkloadReady", metav1.ConditionFalse)
		})
	if failed.Phase == trawlv1alpha1.TapPhaseActive {
		t.Errorf("a tap whose analyzer cannot start reports phase %q", failed.Phase)
	}
	if failed.ReadyTargets != 0 {
		t.Errorf("a tap whose analyzer cannot start reports %d ready target(s)", failed.ReadyTargets)
	}

	opts.suricataMemory = healthyMemory
	a.updateTap(t, name, opts)
	recovered := a.waitForTap(t, name, activeTimeout, "Active after the ceiling was raised", isActive)

	for _, an := range recovered.Targets[0].Analyzers {
		if !an.Healthy {
			t.Errorf("analyzer %s is still unhealthy after recovery: %s", an.Name, an.Reason)
		}
	}
	t.Logf("analyzer failure: %s -> %s recovered to phase %q with %d analyzer(s) healthy",
		starvedMemory, healthyMemory, recovered.Phase, len(recovered.Targets[0].Analyzers))
}

// With the ledger unreachable, mutations are refused and monitoring continues.
//
// This is FR-036's trade stated as an outcome: an unaudited change to what the
// sensor watches is worse than a failed kubectl apply, and refusing one does
// not touch traffic already being observed.
//
// It asserts the outcome and not the mechanism on purpose. readyz consults the
// ledger, so an outage both fails the gate and drops the webhook's endpoints,
// and which of the two refuses a given request is a race. Pinning the error
// text would make this test fail on a timing difference that changes nothing
// about the property being protected.
//
// It is opt-in. Scaling the storage down refuses mutations for the whole
// installation for as long as it takes to run, which is not something a routine
// acceptance run should do to a shared cluster.
func TestALedgerOutageRefusesMutationsAndLeavesMonitoringRunning(t *testing.T) {
	a := requireAcceptanceCluster(t)
	if os.Getenv("TRAWL_E2E_LEDGER_OUTAGE") != "1" {
		t.Skip("set TRAWL_E2E_LEDGER_OUTAGE=1 to run this; it refuses NetworkTap " +
			"mutations installation-wide while it runs")
	}

	// A tap that is already capturing before the ledger goes away. What must
	// survive the outage is this, not the ability to create another.
	existing := a.tapName(t)
	a.applyTap(t, existing, defaultTapOptions())
	before := a.waitForTap(t, existing, activeTimeout, "Active", isActive)

	restore := a.stopLedger(t)
	defer restore()

	// The refusal has to be observed after the manager has actually noticed,
	// so this retries until a mutation is refused rather than asserting on the
	// first attempt and racing the outage.
	name := a.tapName(t) + "-during-outage"
	refused := a.waitForRefusal(t, name)
	t.Logf("ledger outage: creating a tap was refused with %q", firstLine(refused))

	// Monitoring is a separate path: the sensor reads an interface and writes
	// to stdout, and touches storage nowhere. An outage that stopped it would
	// mean a storage failure blinds the sensor, which is the failure mode
	// fail-closed admission exists to avoid causing.
	during, exists := a.tapStatus(t, existing)
	if !exists {
		t.Fatalf("the running tap disappeared during the outage")
	}
	if !isActive(during) {
		t.Errorf("the running tap left Active during a ledger outage: phase=%q conditions=%s",
			during.Phase, formatConditions(during.Conditions))
	}
	if len(a.sensorDaemonSets(t, existing)) == 0 {
		t.Errorf("the sensor DaemonSet was removed during a ledger outage")
	}
	if before.ReadyTargets != during.ReadyTargets {
		t.Errorf("ready targets changed from %d to %d during a ledger outage",
			before.ReadyTargets, during.ReadyTargets)
	}

	restore()
	after := a.waitForTap(t, existing, settleTimeout, "Active after the ledger returned", isActive)

	// And mutations work again, so the refusal was the outage and not a lasting
	// change to the installation.
	a.updateTap(t, existing, defaultTapOptions())
	t.Logf("ledger restored: phase=%q, mutations accepted again", after.Phase)
}

// stopLedger scales the storage backend to zero and returns a restore function
// that is safe to call more than once.
func (a *acceptance) stopLedger(t *testing.T) func() {
	t.Helper()

	replicas, err := kubectlOut("get", "deployment", "minio", "-n", a.namespace,
		"-o", "jsonpath={.spec.replicas}")
	if err != nil {
		t.Fatalf("reading the storage deployment: %v: %s", err, replicas)
	}
	if out, err := kubectlOut("scale", "deployment", "minio", "-n", a.namespace,
		"--replicas=0"); err != nil {
		t.Fatalf("stopping the storage deployment: %v: %s", err, out)
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			if out, err := kubectlOut("scale", "deployment", "minio", "-n", a.namespace,
				"--replicas="+strings.TrimSpace(replicas)); err != nil {
				// A failure here leaves the installation refusing mutations, so
				// it is fatal rather than logged: the run must not end quietly
				// with the cluster in that state.
				t.Fatalf("restoring the storage deployment to %s replicas: %v: %s",
					strings.TrimSpace(replicas), err, out)
			}
			if out, err := kubectlOut("rollout", "status", "deployment/minio",
				"-n", a.namespace, "--timeout=3m"); err != nil {
				t.Fatalf("waiting for storage to return: %v: %s", err, out)
			}
			// Storage being back is not the same as admission being back. The
			// manager's readyz consults the ledger, so it was removed from the
			// webhook Service's endpoints during the outage and takes a moment
			// to return - and until it does, every mutation still fails, the
			// cleanup delete included. Without this wait the spec leaves behind
			// the tap it created, which it saw happen.
			a.waitForAdmission(t)
		})
	}
}

// waitForAdmission blocks until the webhook is admitting mutations again.
//
// It probes with the real thing rather than with an endpoint check: what the
// caller needs to know is that a NetworkTap mutation will now succeed, and only
// a NetworkTap mutation answers that.
func (a *acceptance) waitForAdmission(t *testing.T) {
	t.Helper()
	name := "acc-admission-probe-" + a.runID

	deadline := time.Now().Add(settleTimeout)
	var last error
	for time.Now().Before(deadline) {
		if err := a.apply(a.buildTap(name, defaultTapOptions())); err == nil {
			if out, err := kubectlOut("delete", "networktap", name, "-n", a.namespace,
				"--ignore-not-found", "--wait=true", "--timeout=2m"); err != nil {
				t.Fatalf("removing the admission probe tap: %v: %s", err, out)
			}
			return
		} else {
			last = err
		}
		time.Sleep(pollInterval)
	}
	t.Fatalf("admission did not recover within %s after storage returned; "+
		"the installation is still refusing mutations (last attempt: %v)", settleTimeout, last)
}

// waitForRefusal retries a create until it is refused, and fails if one is ever
// admitted while the ledger is down.
func (a *acceptance) waitForRefusal(t *testing.T, name string) string {
	t.Helper()
	deadline := time.Now().Add(settleTimeout)
	var last string
	for time.Now().Before(deadline) {
		err := a.apply(a.buildTap(name, defaultTapOptions()))
		if err != nil {
			return err.Error()
		}
		// Admitted. Clean it up before deciding: leaving it would leave the
		// installation with an unaudited tap that this test created.
		a.deleteTap(t, name)
		last = "admitted"
		time.Sleep(pollInterval)
	}
	t.Fatalf("a NetworkTap create was still being admitted %s after the audit "+
		"ledger was stopped; the durable-audit gate is not fail-closed (last attempt: %s)",
		settleTimeout, last)
	return ""
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return line
}

// decodeBase64 reads one Secret field, treating an empty value as an error.
// kubectl prints nothing for a key that is absent, so without this a missing
// credential would be written as an empty file and fail later as a permission
// error against the ledger.
func decodeBase64(s string) ([]byte, error) {
	if strings.TrimSpace(s) == "" {
		return nil, errors.New("the key is absent from the secret")
	}
	return base64.StdEncoding.DecodeString(strings.TrimSpace(s))
}

// SC-001: an operator declares one valid source and sees a structured record of
// test traffic within fifteen minutes, without logging into or modifying a host.
//
// This is the only spec that observes the thing the product is for. Every other
// spec here asserts that the control plane behaves — a tap reaches Active, a
// status tells the truth, a mutation is audited — and all of that can be
// perfectly correct while the sensor emits nothing anyone can use. Reading the
// records back is what separates "the tap says it is working" from "the tap is
// working", and those two have already come apart once in this codebase.
//
// The records are validated as the bytes the sensor emitted, not as a decoded
// and re-encoded Go value. The envelope schema sets additionalProperties:false,
// so a field the sensor adds that the contract does not describe is a violation
// the raw bytes reveal and a round trip through the Go type would quietly drop.
func TestAFirstStructuredObservationArrivesWithinFifteenMinutes(t *testing.T) {
	a := requireAcceptanceCluster(t)
	name := a.tapName(t)

	// The budget runs from the declaration, because that is the moment SC-001
	// measures from: the operator has done the only thing they are asked to do.
	declared := time.Now()
	a.applyTap(t, name, defaultTapOptions())
	a.waitForTap(t, name, activeTimeout, "Active", isActive)

	fx := traffic.Baseline(a.namespace, a.node, a.runID)
	a.runTraffic(t, fx)

	remaining := firstObservationBudget - time.Since(declared)
	if remaining <= 0 {
		t.Fatalf("the tap took %s to become Active and generate traffic, "+
			"leaving none of the %s budget for an observation",
			time.Since(declared).Round(time.Second), firstObservationBudget)
	}
	records := a.collectObservations(t, name, fx.UserAgent, fx.Requests, remaining)
	elapsed := time.Since(declared)

	if len(records) != fx.Requests {
		t.Errorf("the fixture made %d requests and the tap reported %d records",
			fx.Requests, len(records))
	}

	status, _ := a.tapStatus(t, name)
	uid := a.tapUID(t, name)
	for _, r := range records {
		if r.ObservationType != observation.TypeHTTP {
			t.Errorf("record %s is %q, not an http record", r.ID, r.ObservationType)
		}
		// A record that does not name the tap and target it came from cannot be
		// attributed by anyone reading the stream later, which is most of what
		// makes it evidence rather than a log line.
		if r.Tap == nil || r.Tap.Name != name || r.Tap.Namespace != a.namespace {
			t.Errorf("record %s does not attribute itself to tap %s/%s: %+v",
				r.ID, a.namespace, name, r.Tap)
		} else if r.Tap.UID != uid {
			t.Errorf("record %s carries tap UID %q, but the tap's is %q",
				r.ID, r.Tap.UID, uid)
		}
		if r.Target.Node != a.node || r.Target.Interface != acceptanceInterface {
			t.Errorf("record %s says it was observed on %s/%s, not %s/%s",
				r.ID, r.Target.Node, r.Target.Interface, a.node, acceptanceInterface)
		}
		// Each baseline request opens its own connection, so nothing here is a
		// duplicate of anything. A Suspected among them would mean the
		// heuristic fires on plainly distinct traffic.
		if r.Duplication == string(trawlv1alpha1.DuplicationSuspected) {
			t.Errorf("record %s is marked a suspected duplicate, but every "+
				"baseline request used its own connection", r.ID)
		}
	}

	t.Logf("first observation: %d/%d records %s after declaring the tap "+
		"(budget %s), phase %q",
		len(records), fx.Requests, elapsed.Round(time.Second),
		firstObservationBudget, status.Phase)
}

// Suspected duplicates are marked and counted, and never discarded.
//
// Mirrored and overlay traffic carries the same packet more than once, and the
// design's answer is to mark rather than drop: deciding two records describe one
// event is a judgement an analyst may need to overturn, and evidence deleted at
// ingest cannot be recovered. The unit tests cover the heuristic itself. What
// they cannot show is that a deployed sensor still emits what it marked, which
// is the whole of the guarantee — a cache that silently dropped its suspects
// would pass every test in internal/sensor.
//
// So the assertion that carries the weight is the count: as many records come
// back as the fixture made requests. The Suspected marks prove the heuristic
// ran; the count proves it cost nothing.
func TestSuspectedDuplicatesAreMarkedAndNotDropped(t *testing.T) {
	a := requireAcceptanceCluster(t)
	name := a.tapName(t)

	a.applyTap(t, name, defaultTapOptions())
	a.waitForTap(t, name, activeTimeout, "Active", isActive)

	fx := traffic.Duplicate(a.namespace, a.node, a.runID)
	a.runTraffic(t, fx)

	records := a.collectObservations(t, name, fx.UserAgent, fx.Requests, settleTimeout)

	if len(records) != fx.Requests {
		t.Errorf("the fixture made %d requests down one connection and the tap "+
			"reported %d records; marking must not discard evidence",
			fx.Requests, len(records))
	}

	states := map[string]int{}
	for _, r := range records {
		states[r.Duplication]++
	}
	if states[string(trawlv1alpha1.DuplicationSuspected)] == 0 {
		t.Errorf("no record was marked a suspected duplicate, so this spec "+
			"proved nothing about marking; states seen: %v", states)
	}
	// Unknown means the fingerprint could not be computed. These records all
	// carry a flow, so Unknown here would mean the heuristic never got to run.
	if states[string(trawlv1alpha1.DuplicationUnknown)] > 0 {
		t.Errorf("%d record(s) reported Unknown duplication despite carrying a "+
			"flow, so the fingerprint was not computed",
			states[string(trawlv1alpha1.DuplicationUnknown)])
	}

	// The per-record mark and the target's rolled-up state are written by
	// different code paths - the tailer marks each record as it parses it, the
	// status reporter publishes the cache's summary on its heartbeat - so a
	// status that never agreed with the records would send an operator looking
	// at the wrong tap.
	//
	// This waits rather than reading once. The two are not written together:
	// records reach the sensor's stdout as they are parsed, while the summary
	// only reaches the API on the next heartbeat, so reading immediately after
	// collecting records sees the state from before them. An empty cache
	// reports Unknown, which is what that read returns and what an earlier
	// draft of this spec mistook for the status contradicting its own records.
	status := a.waitForTap(t, name, settleTimeout,
		"the target to report suspected duplicates",
		func(s trawlv1alpha1.NetworkTapStatus) bool {
			return len(s.Targets) > 0 &&
				s.Targets[0].Duplication == trawlv1alpha1.DuplicationSuspected
		})

	t.Logf("duplicates: %d requests -> %d records, states %v, target reports %q",
		fx.Requests, len(records), states, status.Targets[0].Duplication)
}

// firstObservationBudget is SC-001's fifteen minutes, from declaring a source
// to seeing a structured record of test traffic.
const firstObservationBudget = 15 * time.Minute

// emittedObservation is a record as the sensor wrote it.
//
// It is not observation.Observation: the sensor stamps duplication onto the
// emitted document and the Go envelope type has no field for it, so decoding
// into that type alone would silently discard the value two specs here assert
// on. Raw keeps the original bytes, which is what gets validated - see the
// schema note on TestAFirstStructuredObservationArrivesWithinFifteenMinutes.
type emittedObservation struct {
	observation.Observation
	Duplication string `json:"duplication,omitempty"`

	Raw []byte `json:"-"`
}

// runTraffic runs a traffic fixture to completion and fails if it did not
// generate what it promised.
//
// The generator is checked rather than trusted. A curl that could not reach the
// target still exits a pod that ran, and a spec that went on to wait for
// records would spend its whole budget before failing with "no observations" -
// a message that points at the sensor when the fault was in the fixture.
func (a *acceptance) runTraffic(t *testing.T, fx traffic.Fixture) {
	t.Helper()

	name := fx.Pod.Name
	t.Cleanup(func() {
		if out, err := kubectlOut("delete", "pod", name, "-n", a.namespace,
			"--ignore-not-found", "--wait=false"); err != nil {
			t.Logf("deleting traffic pod %s: %v: %s", name, err, out)
		}
	})

	if err := applyObject(fx.Pod); err != nil {
		t.Fatalf("applying traffic fixture %s: %v", name, err)
	}

	deadline := time.Now().Add(settleTimeout)
	var phase string
	for time.Now().Before(deadline) {
		out, err := kubectlOut("get", "pod", name, "-n", a.namespace,
			"-o", "jsonpath={.status.phase}")
		if err == nil {
			phase = strings.TrimSpace(out)
		}
		if phase == "Succeeded" || phase == "Failed" {
			break
		}
		time.Sleep(pollInterval)
	}

	logs, err := kubectlOut("logs", name, "-n", a.namespace)
	if err != nil {
		t.Fatalf("reading traffic fixture logs: %v: %s", err, logs)
	}
	if phase != "Succeeded" {
		t.Fatalf("traffic fixture %s ended %q, not Succeeded: %s",
			name, phase, strings.TrimSpace(logs))
	}
	if !strings.Contains(logs, fmt.Sprintf("generated=%d", fx.Requests)) {
		t.Fatalf("traffic fixture %s did not report generating %d requests: %s",
			name, fx.Requests, strings.TrimSpace(logs))
	}
}

// collectObservations polls a tap's sensors for records carrying userAgent.
//
// It waits for want records rather than for the first one, and keeps the last
// reading if the deadline passes, so a spec reports "7 of 12" instead of
// failing with nothing to look at. Polling the sensor's stdout is deliberate:
// it is where the records exist before anything downstream has had a chance to
// reshape them, and the audit pipeline that would carry them to Loki is not
// deployed on this cluster.
func (a *acceptance) collectObservations(t *testing.T, tapName, userAgent string,
	want int, timeout time.Duration) []emittedObservation {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var found []emittedObservation
	for {
		found = a.readObservations(t, tapName, userAgent)
		if len(found) >= want || !time.Now().Before(deadline) {
			return found
		}
		time.Sleep(pollInterval)
	}
}

// readObservations reads every record a tap's sensors have emitted for
// userAgent, and validates each against the normative schema as it goes.
func (a *acceptance) readObservations(t *testing.T, tapName, userAgent string) []emittedObservation {
	t.Helper()

	schema, err := observation.Schema()
	if err != nil {
		t.Fatalf("compiling the observation schema: %v", err)
	}

	var found []emittedObservation
	for _, pod := range a.sensorPodNames(t, tapName) {
		// A bounded tail, because a sensor on a busy interface would otherwise
		// return more than this test needs to read. The fixtures are small and
		// recent, so what matters is only that the window comfortably exceeds
		// what one fixture produces.
		out, err := kubectlOut("logs", pod, "-n", a.namespace,
			"-c", "sensor-agent", "--tail=5000")
		if err != nil {
			// A sensor pod that restarted between listing and reading is not a
			// failure of what this spec is testing; the next poll re-reads it.
			t.Logf("reading sensor logs from %s: %v", pod, err)
			continue
		}

		for line := range strings.SplitSeq(out, "\n") {
			line = strings.TrimSpace(line)
			if !strings.Contains(line, userAgent) {
				continue
			}

			var rec emittedObservation
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				// The marker matched, so this line was meant to be one of ours.
				t.Errorf("a record carrying %s did not decode: %v", userAgent, err)
				continue
			}
			// Match on the decoded field rather than the substring that found
			// it: a User-Agent can appear in some other record's content, and
			// counting that would inflate the very number these specs assert.
			if rec.Details.HTTP == nil || rec.Details.HTTP.UserAgent != userAgent {
				continue
			}
			rec.Raw = []byte(line)

			var doc any
			if err := json.Unmarshal(rec.Raw, &doc); err != nil {
				t.Errorf("record %s did not re-decode for validation: %v", rec.ID, err)
				continue
			}
			if err := schema.Validate(doc); err != nil {
				t.Errorf("record %s does not satisfy %s: %v",
					rec.ID, observation.SchemaVersion, err)
			}
			found = append(found, rec)
		}
	}
	return found
}

// sensorPodNames lists the pods running a tap's sensors.
func (a *acceptance) sensorPodNames(t *testing.T, tapName string) []string {
	t.Helper()

	var pods []string
	for _, ds := range a.sensorDaemonSets(t, tapName) {
		out, err := kubectlOut("get", "pods", "-n", a.namespace,
			"-o", "jsonpath={range .items[?(@.metadata.ownerReferences[0].name==\""+ds+"\")]}{.metadata.name}{\"\\n\"}{end}")
		if err != nil {
			t.Fatalf("listing pods for DaemonSet %s: %v: %s", ds, err, out)
		}
		for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
			if line != "" {
				pods = append(pods, line)
			}
		}
	}
	if len(pods) == 0 {
		t.Fatalf("tap %s is running no sensor pods", tapName)
	}
	return pods
}

// tapUID reads the tap's UID, which its records must carry to be attributable
// to this tap rather than to another one that reused the name.
func (a *acceptance) tapUID(t *testing.T, name string) string {
	t.Helper()
	out, err := kubectlOut("get", "networktap", name, "-n", a.namespace,
		"-o", "jsonpath={.metadata.uid}")
	if err != nil {
		t.Fatalf("reading tap UID: %v: %s", err, out)
	}
	return strings.TrimSpace(out)
}
