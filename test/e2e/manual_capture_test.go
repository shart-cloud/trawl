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

// US3's cluster acceptance: a manual capture from request to expiry against a
// deployed Trawl.
//
// The integration suite already drives this logic against envtest and a real
// MinIO, and does it faster and in more shapes. What only a cluster can answer
// is whether the pieces are wired to each other: whether the runner Job is
// admitted and scheduled with the privileges dumpcap needs, whether the
// gateway's TokenReview accepts a token the API server actually minted,
// whether the SubjectAccessReview reads the RBAC that is really installed, and
// whether retention deletes an object from the bucket the cluster is using.
// Every spec here is chosen because faking any of its collaborators would
// remove the reason to run it.
package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/audit"
	"trawl.cloud/trawl/internal/config"
	"trawl.cloud/trawl/internal/storage"
)

const (
	// captureCompleteTimeout bounds request to Completed. It covers admission,
	// scheduling the runner Job, pulling its image, the bounded capture itself,
	// the upload, and the controller's verification.
	captureCompleteTimeout = 6 * time.Minute

	// captureDuration is how long each acceptance capture collects for. Short,
	// because every spec pays it and none of them is testing the bound itself.
	captureDuration = "10s"

	// expiryTimeout bounds a shortened retention being enforced. The retention
	// controller wakes on the deadline it computed, so this only has to cover
	// one reconcile and the deletes.
	expiryTimeout = 3 * time.Minute

	// analystSA and viewerSA are the two identities quickstart section 6
	// contrasts. They are left in place on the cluster between runs.
	analystSA = "trawl-acceptance-analyst"
	viewerSA  = "trawl-acceptance-viewer"

	// gatewayAudience is the audience the gateway requires. A service account's
	// default token carries the API server's audience and is refused, which is
	// what stops any pod's mounted token being replayed to fetch captures.
	gatewayAudience = "trawl-artifact-gateway"
)

// requireReachableObjectStore ensures the presigned redirect can actually be
// followed from this machine, and skips with the fix when it cannot.
//
// The gateway does not serve bytes. It authorizes and answers 303 with a
// presigned URL for the object store endpoint in the installation config, and
// the CLI follows that itself. The SigV4 signature covers the host header, so
// the bucket has to be reachable under exactly the name and port it was signed
// for - reaching the same bucket by another name fails. Against a production
// object store that is already true; against the in-cluster development MinIO
// it needs a forward on that exact port and a name that resolves to it, which
// is what quickstart section 6 documents.
//
// This is a skip rather than a failure because it describes the machine the
// test is running on, not the software under test. It is deliberately not
// silent about which.
func (a *acceptance) requireReachableObjectStore(t *testing.T) {
	t.Helper()
	// Like the ledger's forward, this one is not torn down per spec: several
	// specs need it and the process owns it for its lifetime.
	a.objectStoreOnce.Do(func() { a.objectStoreErr = a.reachObjectStore() })
	if a.objectStoreErr != nil {
		t.Skipf("the presigned redirect cannot be followed from here: %v\n"+
			"quickstart section 6 covers this: forward the object store on its own port "+
			"and make its hostname resolve to the forward.", a.objectStoreErr)
	}
}

func (a *acceptance) reachObjectStore() error {
	raw, err := kubectlOut("get", "configmap", "trawl-config", "-n", a.namespace,
		"-o", "jsonpath={.data.config\\.yaml}")
	if err != nil {
		return fmt.Errorf("reading the installation config: %w: %s", err, raw)
	}
	installCfg, err := config.Load([]byte(raw))
	if err != nil {
		return fmt.Errorf("parsing the installation config: %w", err)
	}
	endpoint := installCfg.Artifacts.Endpoint
	host, port, ok := strings.Cut(endpoint, ":")
	if !ok {
		return fmt.Errorf("artifact endpoint %q has no port", endpoint)
	}

	// If it already answers, something else is providing the route and this
	// must not add a second one.
	if conn, err := net.DialTimeout("tcp", endpoint, 2*time.Second); err == nil {
		_ = conn.Close()
		return nil
	}

	addrs, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("%s does not resolve here, so the redirect cannot be followed: %w", host, err)
	}
	if !isLoopback(addrs) {
		return fmt.Errorf("%s resolves to %v, which this machine is not serving", host, addrs)
	}

	// The name points at loopback, so the forward has to bind that exact port:
	// the signature is over host and port, and any other port is a different
	// URL as far as the signature is concerned.
	// The endpoint is a Service DNS name, so it names its own namespace:
	// minio.storage.svc... is in storage, not in Trawl's namespace. Forwarding
	// the wrong namespace fails only after kubectl has started, which shows up
	// as the 30s dial timeout below and reads as a DNS or port problem.
	service, namespace := splitServiceDNS(host, a.namespace)
	// #nosec G204 -- the service name and port come from the installation config.
	cmd := exec.Command("kubectl", "port-forward", "-n", namespace,
		"svc/"+service, port+":"+port)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("forwarding %s: %w", service, err)
	}
	// Not torn down on success: several specs need the route and the run owns
	// it, the same bargain the ledger and Loki forwards make.
	stop := func() { _ = cmd.Process.Kill() }

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := net.DialTimeout("tcp", endpoint, 2*time.Second); err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	stop()
	return fmt.Errorf("%s did not answer within 30s of forwarding it", endpoint)
}

// splitServiceDNS reads a Service name and namespace out of a cluster DNS name,
// falling back to the given namespace for a bare service name.
func splitServiceDNS(host, fallback string) (service, namespace string) {
	if net.ParseIP(host) != nil {
		// An address, not a name: there are no labels to read a namespace out
		// of, and splitting one gives a service called "127".
		return host, fallback
	}
	labels := strings.Split(host, ".")
	if len(labels) > 1 && labels[1] != "" {
		return labels[0], labels[1]
	}
	return labels[0], fallback
}

func isLoopback(addrs []string) bool {
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.IsLoopback() {
			return true
		}
	}
	return false
}

// retentionAdminGroup is the group the installation grants retention authority
// to. It is deliberately not a group a cluster administrator is in: changing
// how long evidence is kept is a separate authority from running the cluster,
// which is the point of checking it here rather than trusting a unit test.
const retentionAdminGroup = "trawl:retention-admins"

// grantRetentionAdmin binds the installation's retention-admin group to the
// ClusterRole the install bundle ships, for the life of one spec.
//
// The bundle ships the role and deliberately binds nothing to it: who the
// retention admins are is an installation decision, not something Trawl can
// choose. So the binding is the spec's to make, and making it is also what
// proves the shipped role carries the verbs a retention change needs - RBAC
// says who may ask, admission says what may change, and this exercises both.
func (a *acceptance) grantRetentionAdmin(t *testing.T) {
	t.Helper()
	binding := "trawl-e2e-retention-" + a.runID
	if out, err := kubectlOut("create", "clusterrolebinding", binding,
		"--clusterrole=trawl-retention-admin", "--group="+retentionAdminGroup); err != nil {
		if strings.Contains(out, "already exists") {
			return
		}
		t.Skipf("cannot grant retention-admin (%v: %s); this spec needs RBAC write on the cluster",
			err, firstLine(out))
	}
	t.Cleanup(func() {
		_ = kubectl("delete", "clusterrolebinding", binding, "--ignore-not-found")
	})
}

// patchRetentionAsAdmin changes a capture's retention while impersonating a
// retention admin.
//
// Impersonation rather than a service account because the check is on a group,
// and a service account's groups are fixed by Kubernetes to the
// system:serviceaccounts ones - there is no way to put one in an installation's
// own group. Impersonating exercises the real webhook path: the API server
// authenticates the impersonated identity and the webhook sees those groups.
func (a *acceptance) patchRetentionAsAdmin(t *testing.T, name, retention string) {
	t.Helper()
	a.grantRetentionAdmin(t)
	out, err := kubectlOut("patch", "capturejob", name, "-n", a.namespace,
		"--type=merge", "-p", fmt.Sprintf(`{"spec":{"retention":%q}}`, retention),
		"--as=acceptance-retention-admin", "--as-group="+retentionAdminGroup,
		"--as-group=system:authenticated")
	if err != nil {
		if strings.Contains(out, "forbidden") && strings.Contains(out, "impersonate") {
			t.Skipf("cannot impersonate a retention admin (%s); this spec needs impersonation rights", firstLine(out))
		}
		t.Fatalf("shortening retention as a retention admin: %v: %s", err, out)
	}
}

// captureName is unique per spec and per run, so a capture left behind by an
// interrupted run is visibly not this one's.
func (a *acceptance) captureName(t *testing.T, suffix string) string {
	t.Helper()
	name := fmt.Sprintf("accept-%s-%s", suffix, a.runID)
	t.Cleanup(func() {
		// Best effort: a leaked CaptureJob costs retention a sweep, not a
		// failure, and a cleanup error must not mask the spec's own result.
		_ = kubectl("delete", "capturejob", name, "-n", a.namespace, "--ignore-not-found")
	})
	return name
}

// captureOptions are the knobs the specs vary. Everything else is constant so a
// failure points at the thing under test.
type captureOptions struct {
	filter     string
	targetNode string
	retention  string
	duration   string
}

func (a *acceptance) defaultCaptureOptions() captureOptions {
	return captureOptions{
		// Loopback carries almost nothing on an idle node, so a filter that
		// matches DNS gives a capture that usually sees packets without
		// depending on any particular traffic existing.
		filter:     "udp port 53 or tcp port 443",
		targetNode: a.node,
		retention:  "1h",
		duration:   captureDuration,
	}
}

func (a *acceptance) applyCapture(t *testing.T, name string, opts captureOptions) {
	t.Helper()
	job := &trawlv1alpha1.CaptureJob{
		TypeMeta: metav1.TypeMeta{
			APIVersion: trawlv1alpha1.GroupVersion.String(),
			Kind:       "CaptureJob",
		},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: a.namespace},
		Spec: trawlv1alpha1.CaptureJobSpec{
			RequestType: trawlv1alpha1.CaptureRequestManual,
			TapRef:      corev1.LocalObjectReference{Name: a.productionTap(t)},
			TargetNode:  opts.targetNode,
			Filter:      opts.filter,
			Duration:    opts.duration,
			Retention:   opts.retention,
		},
	}
	job.Spec.MaxSize = resource.MustParse("16Mi")
	if err := applyObject(job); err != nil {
		t.Fatalf("applying capture %s: %v", name, err)
	}
}

// productionTap is the tap the specs capture through.
//
// Captures attach to an existing Active tap rather than creating one: a
// CaptureJob needs a target the tap reports with a fresh heartbeat, and
// standing up a tap and waiting for it to become Active would add six minutes
// to every spec while testing the tap controller, which the NetworkTap suite
// already does.
func (a *acceptance) productionTap(t *testing.T) string {
	t.Helper()
	out, err := kubectlOut("get", "networktap", "-n", a.namespace,
		"-o", "jsonpath={range .items[?(@.status.phase=='Active')]}{.metadata.name}{'\\n'}{end}")
	if err != nil {
		t.Fatalf("listing taps: %v: %s", err, out)
	}
	for name := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		if name = strings.TrimSpace(name); name != "" {
			return name
		}
	}
	t.Skip("no Active NetworkTap to capture through; US3 needs one running")
	return ""
}

func (a *acceptance) captureStatus(t *testing.T, name string) (trawlv1alpha1.CaptureJobStatus, bool) {
	t.Helper()
	out, err := kubectlOut("get", "capturejob", name, "-n", a.namespace, "-o", "json")
	if err != nil {
		return trawlv1alpha1.CaptureJobStatus{}, false
	}
	var job trawlv1alpha1.CaptureJob
	if err := json.Unmarshal([]byte(out), &job); err != nil {
		t.Fatalf("decoding capture %s: %v", name, err)
	}
	return job.Status, true
}

// waitForCapture polls until want is satisfied, and fails with the phase, the
// failure and the conditions rather than a bare timeout.
func (a *acceptance) waitForCapture(t *testing.T, name string, timeout time.Duration,
	describe string, want func(trawlv1alpha1.CaptureJobStatus) bool,
) trawlv1alpha1.CaptureJobStatus {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last trawlv1alpha1.CaptureJobStatus
	for time.Now().Before(deadline) {
		status, ok := a.captureStatus(t, name)
		if ok {
			last = status
			if want(status) {
				return status
			}
		}
		time.Sleep(pollInterval)
	}
	t.Fatalf("capture %s did not %s within %s: phase=%q failure=%+v\n%s",
		name, describe, timeout, last.Phase, last.Failure, formatConditions(last.Conditions))
	return last
}

func capturePhaseIs(phase trawlv1alpha1.CapturePhase) func(trawlv1alpha1.CaptureJobStatus) bool {
	return func(s trawlv1alpha1.CaptureJobStatus) bool { return s.Phase == phase }
}

// trawlctlPath is the supported client, built into bin/ by `make trawlctl`.
//
// The specs shell out to the real binary rather than calling the client
// library, because the credential handling is the part a cluster can falsify:
// the token has to be one the API server minted for this audience, and it has
// to reach the gateway without ever appearing in an argument.
func trawlctlPath(t *testing.T) string {
	t.Helper()
	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("locating the repository: %v", err)
	}
	path := filepath.Join(root, "..", "..", "bin", "trawlctl")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("no trawlctl at %s; run `make trawlctl` first", path)
	}
	return path
}

// gatewayCA writes the CA the gateway is issued from to a file and returns it.
func (a *acceptance) gatewayCA(t *testing.T) string {
	t.Helper()
	out, err := kubectlOut("get", "secret", "trawl-ca", "-n", a.namespace,
		"-o", "jsonpath={.data.ca\\.crt}")
	if err != nil {
		t.Fatalf("reading the gateway CA: %v: %s", err, out)
	}
	pem, err := decodeBase64(strings.TrimSpace(out))
	if err != nil {
		t.Fatalf("decoding the gateway CA: %v", err)
	}
	path := filepath.Join(t.TempDir(), "gateway-ca.crt")
	if err := os.WriteFile(path, pem, 0o600); err != nil {
		t.Fatalf("writing the gateway CA: %v", err)
	}
	return path
}

// forwardGateway opens a tunnel to the artifact gateway for one spec.
func (a *acceptance) forwardGateway(t *testing.T) string {
	t.Helper()
	local, err := reserveLocalPort()
	if err != nil {
		t.Fatalf("claiming a local port: %v", err)
	}
	// #nosec G204 -- the namespace comes from configuration, the port from the kernel.
	cmd := exec.Command("kubectl", "port-forward", "-n", a.namespace,
		"service/trawl-artifact-gateway", localPort(local)+":443")
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the gateway port-forward: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := net.DialTimeout("tcp", local, 2*time.Second); err == nil {
			_ = conn.Close()
			return "https://" + local
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("the gateway did not answer on %s within 30s", local)
	return ""
}

// mintToken asks the API server for a short-lived token for one service
// account, scoped to the gateway's audience.
func (a *acceptance) mintToken(t *testing.T, serviceAccount string) string {
	t.Helper()
	out, err := kubectlOut("create", "token", serviceAccount,
		"-n", a.namespace, "--audience="+gatewayAudience, "--duration=10m")
	if err != nil {
		t.Skipf("cannot mint a token for %s (%v); the acceptance service accounts must exist: %s",
			serviceAccount, err, out)
	}
	return strings.TrimSpace(out)
}

// download runs trawlctl exactly as quickstart section 6 documents it, with the
// token on stdin so it never appears in the process arguments.
func (a *acceptance) download(t *testing.T, capture, serviceAccount, output string) (string, error) {
	t.Helper()
	binary := trawlctlPath(t)
	gateway := a.forwardGateway(t)
	ca := a.gatewayCA(t)
	token := a.mintToken(t, serviceAccount)

	// #nosec G204 -- every argument is a constant, a path this test created, or
	// this run's capture name. The credential travels on stdin.
	cmd := exec.Command(binary, "capture", "download", capture,
		"--namespace", a.namespace,
		"--gateway", gateway,
		"--ca", ca,
		"--token-stdin",
		"--output", output)
	cmd.Stdin = strings.NewReader(token + "\n")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// --- Specs ------------------------------------------------------------------

// A manual capture reaches Completed with a verified artifact, and the analyst
// who is allowed to read it gets exactly the bytes the controller recorded.
//
// This is quickstart section 6's happy path, and the only spec that exercises
// the whole chain at once: admission, the runner Job with the privileges
// dumpcap needs, the reporter's progress, the controller's verification, the
// gateway's TokenReview and SubjectAccessReview against real RBAC, the
// presigned redirect, and the checksum the CLI verifies before it renames.
func TestAManualCaptureCompletesAndIsDownloadedByAnAnalyst(t *testing.T) {
	a := requireAcceptanceCluster(t)
	a.requireReachableObjectStore(t)
	name := a.captureName(t, "download")
	cursor := a.ledgerCursor(t)

	a.applyCapture(t, name, a.defaultCaptureOptions())

	status := a.waitForCapture(t, name, captureCompleteTimeout, "complete",
		capturePhaseIs(trawlv1alpha1.CapturePhaseCompleted))

	if status.SHA256 == "" || status.SizeBytes == nil {
		t.Fatalf("a completed capture has no artifact record: sha=%q size=%v", status.SHA256, status.SizeBytes)
	}
	if status.RetentionDeadline == nil {
		t.Error("a completed capture has no retention deadline, so nothing will ever remove it")
	}
	for _, typ := range []string{"ArtifactVerified", "Downloadable"} {
		if !conditionTrue(status.Conditions, typ) {
			t.Errorf("%s is not True on a completed capture:\n%s", typ, formatConditions(status.Conditions))
		}
	}

	output := filepath.Join(t.TempDir(), "capture.pcapng")
	out, err := a.download(t, name, analystSA, output)
	if err != nil {
		t.Fatalf("the analyst download failed: %v\n%s", err, out)
	}

	body, err := os.ReadFile(output) // #nosec G304 -- a path this test created
	if err != nil {
		t.Fatalf("reading the downloaded capture: %v", err)
	}
	sum := sha256.Sum256(body)
	if got := hex.EncodeToString(sum[:]); got != status.SHA256 {
		t.Errorf("downloaded bytes hash to %s, status records %s", got, status.SHA256)
	}
	if status.SizeBytes != nil && int64(len(body)) != *status.SizeBytes {
		t.Errorf("downloaded %d bytes, status records %d", len(body), *status.SizeBytes)
	}
	if !bytes.HasPrefix(body, []byte{0x0a, 0x0d, 0x0d, 0x0a}) {
		t.Error("the downloaded file is not a pcapng")
	}

	// The redirect is a bearer credential for one object. It must not be in
	// what the operator sees, and it must not be in the ledger.
	if strings.Contains(out, "X-Amz-Signature") {
		t.Error("the CLI printed a presigned URL")
	}
	assertLedgerHasDownload(t, a, cursor, name, audit.DecisionAllowed)
}

// A viewer may see that a capture happened and may not read the traffic.
//
// The difference between the two roles is the capturejobs/download
// subresource, and this is the only place that distinction is checked against
// the RBAC actually installed in the cluster rather than a fake reviewer.
func TestAViewerIsRefusedTheCaptureBytes(t *testing.T) {
	a := requireAcceptanceCluster(t)
	name := a.captureName(t, "viewer")
	cursor := a.ledgerCursor(t)

	a.applyCapture(t, name, a.defaultCaptureOptions())
	a.waitForCapture(t, name, captureCompleteTimeout, "complete",
		capturePhaseIs(trawlv1alpha1.CapturePhaseCompleted))

	// A different output from the analyst spec's on purpose: trawlctl refuses
	// an existing --output before it contacts the gateway, which would hide
	// the refusal this spec exists to observe.
	output := filepath.Join(t.TempDir(), "refused.pcapng")
	out, err := a.download(t, name, viewerSA, output)
	if err == nil {
		t.Fatal("the viewer downloaded a capture it may not read")
	}
	if !strings.Contains(out, "HTTP 403") {
		t.Errorf("the refusal does not report HTTP 403:\n%s", out)
	}
	if _, statErr := os.Stat(output); statErr == nil {
		t.Error("a refused download left a file behind")
	}
	// A refusal must not confirm what it refused. Anything naming the object,
	// its size or its checksum tells an unauthorized caller the capture exists.
	for _, leak := range []string{"captures/", "sha256", "presign", "X-Amz"} {
		if strings.Contains(out, leak) {
			t.Errorf("the refusal mentions %q, which tells the caller the artifact exists:\n%s", leak, out)
		}
	}
	assertLedgerHasDownload(t, a, cursor, name, audit.DecisionDenied)
}

// A filter libpcap cannot parse fails the capture without opening a socket.
func TestAnInvalidFilterFailsWithoutCapturing(t *testing.T) {
	a := requireAcceptanceCluster(t)
	name := a.captureName(t, "badfilter")

	opts := a.defaultCaptureOptions()
	opts.filter = "host 10.0.0.50 and tcp prot 443"
	a.applyCapture(t, name, opts)

	status := a.waitForCapture(t, name, captureCompleteTimeout, "fail",
		capturePhaseIs(trawlv1alpha1.CapturePhaseFailed))

	if status.Failure == nil || status.Failure.Reason != trawlv1alpha1.FailureInvalidFilter {
		t.Errorf("failure = %+v, want InvalidFilter", status.Failure)
	}
	if status.Artifact != nil {
		t.Errorf("an artifact exists for a capture whose filter never compiled: %+v", status.Artifact)
	}
	if conditionTrue(status.Conditions, "CaptureStarted") {
		t.Error("CaptureStarted is True for a filter that never compiled")
	}
}

// A capture aimed at a node no tap reports never starts.
func TestACaptureOnAnUnavailableTargetNeverStarts(t *testing.T) {
	a := requireAcceptanceCluster(t)
	name := a.captureName(t, "notarget")

	opts := a.defaultCaptureOptions()
	opts.targetNode = "node-that-does-not-exist-" + a.runID
	a.applyCapture(t, name, opts)

	status := a.waitForCapture(t, name, captureCompleteTimeout, "report an unavailable target",
		func(s trawlv1alpha1.CaptureJobStatus) bool {
			return s.Phase == trawlv1alpha1.CapturePhaseFailed ||
				conditionFalse(s.Conditions, "TargetReady")
		})

	if conditionTrue(status.Conditions, "CaptureStarted") {
		t.Error("a capture started on a node no tap reports")
	}
	if status.Artifact != nil {
		t.Error("an artifact exists for a capture that never ran")
	}
}

// An authorized shortening moves the deadline, and moves it relative to when
// the capture completed rather than when the change was made.
//
// That distinction is the whole of the rule. Recomputing from the moment of the
// change would let a retention admin extend an artifact's life indefinitely by
// repeatedly "shortening" it, and the difference is invisible unless the two
// are compared. The minimum the API accepts is an hour, so this spec observes
// the deadline rather than the deletion; the deletion is
// TestAnExpiredCaptureIsDeletedAndRefused, which has to wait for one.
func TestShorteningRetentionMovesTheDeadlineFromCompletion(t *testing.T) {
	a := requireAcceptanceCluster(t)
	name := a.captureName(t, "shorten")

	opts := a.defaultCaptureOptions()
	opts.retention = "24h"
	a.applyCapture(t, name, opts)

	completed := a.waitForCapture(t, name, captureCompleteTimeout, "complete",
		capturePhaseIs(trawlv1alpha1.CapturePhaseCompleted))
	if completed.CompletedAt == nil || completed.RetentionDeadline == nil {
		t.Fatalf("a completed capture is missing its times: completedAt=%v deadline=%v",
			completed.CompletedAt, completed.RetentionDeadline)
	}
	completedAt := completed.CompletedAt.Time

	a.patchRetentionAsAdmin(t, name, "1h")

	want := completedAt.Add(time.Hour)
	// Both, and in one wait: a retention change bumps the generation, and
	// DecideDownload refuses while status.observedGeneration lags it so that a
	// change the controller has not applied cannot be read as an extension.
	// The refusal is therefore expected and transient - but only if something
	// catches up. Waiting for both is what tells the two apart.
	shortened := a.waitForCapture(t, name, settleTimeout, "record the shortened deadline and stay downloadable",
		func(s trawlv1alpha1.CaptureJobStatus) bool {
			return s.RetentionDeadline != nil && s.RetentionDeadline.Time.Equal(want) &&
				conditionTrue(s.Conditions, "Downloadable")
		})

	// The deadline is completedAt + 1h. If it were now + 1h it would be later
	// than this, and the artifact would outlive what the admin asked for.
	if got := shortened.RetentionDeadline.Time; !got.Equal(want) {
		t.Errorf("deadline = %s, want %s (completedAt + the new period)", got, want)
	}
	if shortened.Phase != trawlv1alpha1.CapturePhaseCompleted {
		t.Errorf("phase = %q, want Completed while the shortened deadline is still ahead", shortened.Phase)
	}
	if !conditionTrue(shortened.Conditions, "Downloadable") {
		t.Error("a capture inside its shortened retention period is not downloadable")
	}
}

// An expired capture has its bytes deleted and is refused to the analyst who
// could read it an hour earlier.
//
// This is the only spec that proves deletion against the bucket the cluster
// actually uses. Everything upstream can be right while the object stays
// readable, which is the failure retention exists to prevent, and it is
// invisible from the CaptureJob alone: the status says Expired either way.
//
// It is opt-in because it cannot be made fast. The shortest retention the API
// accepts is an hour and the deadline runs from completion, so observing a real
// expiry means waiting a real hour; weakening the floor to suit the test would
// be testing something the cluster does not do.
func TestAnExpiredCaptureIsDeletedAndRefused(t *testing.T) {
	a := requireAcceptanceCluster(t)
	if os.Getenv("TRAWL_E2E_EXPIRY") != "1" {
		t.Skip("set TRAWL_E2E_EXPIRY=1 to run this; it waits an hour for a real retention deadline")
	}
	a.requireReachableObjectStore(t)
	name := a.captureName(t, "expiry")
	cursor := a.ledgerCursor(t)

	opts := a.defaultCaptureOptions()
	opts.retention = "1h"
	a.applyCapture(t, name, opts)

	completed := a.waitForCapture(t, name, captureCompleteTimeout, "complete",
		capturePhaseIs(trawlv1alpha1.CapturePhaseCompleted))
	if completed.Artifact == nil {
		t.Fatal("a completed capture has no artifact to expire")
	}
	key := completed.Artifact.Key
	if !a.artifactExists(t, key) {
		t.Fatalf("the artifact %s is not in the bucket before expiry, so its later absence would prove nothing", key)
	}

	if completed.RetentionDeadline == nil {
		t.Fatal("a completed capture has no retention deadline, so there is no expiry to wait for")
	}
	// The deadline plus a margin for the reconcile that acts on it.
	wait := time.Until(completed.RetentionDeadline.Time) + expiryTimeout
	expired := a.waitForCapture(t, name, wait, "expire",
		capturePhaseIs(trawlv1alpha1.CapturePhaseExpired))

	if conditionTrue(expired.Conditions, "Downloadable") {
		t.Error("an expired capture is still downloadable")
	}
	if !conditionTrue(expired.Conditions, "RetentionEnforced") {
		t.Errorf("RetentionEnforced is not True after expiry:\n%s", formatConditions(expired.Conditions))
	}
	// The record of what was collected survives the collection itself.
	if expired.SHA256 == "" || expired.CompletedAt == nil {
		t.Errorf("expiry lost the capture record: sha=%q completedAt=%v", expired.SHA256, expired.CompletedAt)
	}
	if a.artifactExists(t, key) {
		t.Errorf("the artifact %s is still in the bucket after the capture expired", key)
	}

	output := filepath.Join(t.TempDir(), "expired.pcapng")
	out, err := a.download(t, name, analystSA, output)
	if err == nil {
		t.Errorf("an expired capture was still served:\n%s", out)
	} else if !strings.Contains(out, "HTTP 410") {
		// It has to be the gateway refusing, not the object store being
		// unreachable: a transport error would satisfy "the download failed"
		// while proving nothing about expiry. 410 rather than 404: the
		// artifact API contract distinguishes a capture whose retention ended
		// from one that never existed, because an analyst who is told "no such
		// capture" goes looking for a typo instead of for the retention policy.
		// "HTTP 410" and not "410": the capture name carries a nine-digit run
		// id and the message carries a request id, either of which can hold
		// those three digits, and the refusal a bare match would wave through
		// is the 409 this commit exists to stop.
		t.Errorf("the refusal is not the gateway's HTTP 410, so this proves nothing about expiry:\n%s", out)
	}
	assertLedgerHasExpiry(t, a, cursor, name)
}

// artifactExists reports whether the object is still in the artifact bucket.
//
// It uses the artifact credential, not the ledger one. Reaching the bucket with
// the audit credential would prove nothing about the separation ADR-0003 draws
// between them, and would still answer the question, so a spec written that way
// would pass whether or not the separation held.
func (a *acceptance) artifactExists(t *testing.T, key string) bool {
	t.Helper()
	a.artifactsOnce.Do(func() { a.artifacts, a.artifactsErr = a.connectArtifacts() })
	if a.artifactsErr != nil {
		t.Fatalf("reaching the artifact bucket: %v", a.artifactsErr)
	}
	store := a.artifacts
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	if _, err := store.Head(ctx, key); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return false
		}
		t.Fatalf("asking the artifact bucket about %s: %v", key, err)
	}
	return true
}

func (a *acceptance) connectArtifacts() (storage.Store, error) {
	raw, err := kubectlOut("get", "configmap", "trawl-config", "-n", a.namespace,
		"-o", "jsonpath={.data.config\\.yaml}")
	if err != nil {
		return nil, fmt.Errorf("reading the installation config: %w: %s", err, raw)
	}
	installCfg, err := config.Load([]byte(raw))
	if err != nil {
		return nil, fmt.Errorf("parsing the installation config: %w", err)
	}

	credsDir, err := a.writeArtifactCredentials()
	if err != nil {
		return nil, err
	}
	// NewS3Store reads the credential files before it returns, so the copy on
	// disk is not needed past that point and is not left lying around.
	defer func() { _ = os.RemoveAll(credsDir) }()
	endpoint, err := a.forwardMinIO(installCfg.Artifacts.Endpoint)
	if err != nil {
		return nil, err
	}
	return storage.NewS3Store(config.BucketConfig{
		Endpoint:        endpoint,
		Bucket:          installCfg.Artifacts.Bucket,
		Region:          installCfg.Artifacts.Region,
		CredentialsPath: credsDir,
		UseTLS:          false,
	})
}

func (a *acceptance) writeArtifactCredentials() (string, error) {
	dir, err := os.MkdirTemp("", "trawl-acceptance-artifacts-")
	if err != nil {
		return "", fmt.Errorf("creating a credentials directory: %w", err)
	}
	for _, key := range []string{"accessKeyID", "secretAccessKey"} {
		value, err := kubectlOut("get", "secret", "trawl-artifact-storage",
			"-n", a.namespace, "-o", "jsonpath={.data."+key+"}")
		if err != nil {
			return "", fmt.Errorf("reading %s from the artifact secret: %w: %s", key, err, value)
		}
		decoded, err := decodeBase64(value)
		if err != nil {
			return "", fmt.Errorf("decoding %s: %w", key, err)
		}
		if err := os.WriteFile(filepath.Join(dir, key), decoded, 0o600); err != nil {
			return "", fmt.Errorf("writing %s: %w", key, err)
		}
	}
	return dir, nil
}

func assertLedgerHasDownload(t *testing.T, a *acceptance, cursor, capture, decision string) {
	t.Helper()
	for _, rec := range a.ledgerRecordsAfter(t, cursor) {
		if rec.Action == audit.ActionArtifactDownload &&
			rec.Resource.Name == capture && rec.Decision == decision {
			if rec.RequestID == "" {
				t.Error("a download record carries no request id, so the operator's error cannot be correlated with it")
			}
			return
		}
	}
	t.Errorf("no %s artifact.download record for %s in the ledger", decision, capture)
}

func assertLedgerHasExpiry(t *testing.T, a *acceptance, cursor, capture string) {
	t.Helper()
	var decisions []string
	for _, rec := range a.ledgerRecordsAfter(t, cursor) {
		if rec.Action == audit.ActionArtifactExpire && rec.Resource.Name == capture {
			decisions = append(decisions, rec.Decision)
		}
	}
	// The intent is durable before the delete and the outcome after it, so an
	// expiry that happened and lost its acknowledgement is still visible.
	if len(decisions) < 2 {
		t.Errorf("expiry of %s recorded %v, want an intent and an outcome", capture, decisions)
		return
	}
	if decisions[0] != audit.DecisionAllowed {
		t.Errorf("the first expiry record is %q, want %q before anything was deleted",
			decisions[0], audit.DecisionAllowed)
	}
	if decisions[len(decisions)-1] != audit.DecisionSucceeded {
		t.Errorf("the last expiry record is %q, want %q", decisions[len(decisions)-1], audit.DecisionSucceeded)
	}
}

func conditionTrue(conds []metav1.Condition, typ string) bool {
	for i := range conds {
		if conds[i].Type == typ {
			return conds[i].Status == metav1.ConditionTrue
		}
	}
	return false
}

func conditionFalse(conds []metav1.Condition, typ string) bool {
	for i := range conds {
		if conds[i].Type == typ {
			return conds[i].Status == metav1.ConditionFalse
		}
	}
	return false
}
