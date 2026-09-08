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
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

	// tapInactiveTimeout bounds a capture failing for want of an eligible
	// target. The controller gives the tap twice its heartbeat interval to
	// report before it decides, so this has to clear that grace and not merely
	// a reconcile.
	tapInactiveTimeout = 6 * time.Minute

	// restartCaptureDuration is long enough that the controller can be taken
	// away and brought back while packets are still being collected. The 10s
	// the other specs use would be over before a pod finished terminating,
	// which would test a restart between captures instead of during one.
	restartCaptureDuration = "90s"

	// artifactQuotaFloor is the ceiling the full-storage spec puts on the
	// artifact bucket. It is below what the bucket already holds, so writes are
	// refused from the moment it is set rather than after the next usage scan.
	artifactQuotaFloor = "1ki"

	// emptyCaptureFilter matches nothing. The address is RFC 5737 documentation
	// space, which is never routed, on a port nothing listens on: a filter that
	// merely looks unlikely can be satisfied by traffic that happens to arrive,
	// and would then fail the spec somewhere else and much later.
	emptyCaptureFilter = "host 203.0.113.7 and tcp port 65533"

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

// dropObjectStoreForward tears down the route to the object store so the next
// spec that needs it builds a new one.
//
// The presigned redirect is followed by the CLI over a port-forward this
// process owns, and a forward outlives the pod it was pointed at as a socket to
// nothing. After an outage the cluster is healthy and the next download fails
// inside the object store fetch, which reads like a broken bucket rather than a
// stale fixture - the memoized ledger and artifact clients have exactly this
// problem and are dropped for exactly this reason, and this is the third
// connection the run holds. Missing it cost a failed outage run.
//
// The forward is only killed when this process created it; quickstart section 6
// tells an operator to run their own, and that one is not this process's to
// stop. Resetting the memo is what covers both cases: the next caller re-checks
// that the endpoint actually serves - not merely that something is listening on
// it - and builds a new route when the old one is a socket to nothing.
func (a *acceptance) dropObjectStoreForward() {
	if a.objectStoreForward != nil && a.objectStoreForward.Process != nil {
		_ = a.objectStoreForward.Process.Kill()
		_ = a.objectStoreForward.Wait()
	}
	a.objectStoreForward = nil
	a.objectStoreOnce = sync.Once{}
	a.objectStoreErr = nil
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

	// If it already serves, something else is providing the route and this must
	// not add a second one.
	if objectStoreServes(endpoint, installCfg.Artifacts.UseTLS) {
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
	// it, the same bargain the ledger and Loki forwards make. It is held rather
	// than forgotten so that a spec which takes the object store away can drop
	// it - see dropObjectStoreForward.
	stop := func() { _ = cmd.Process.Kill() }

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if objectStoreServes(endpoint, installCfg.Artifacts.UseTLS) {
			a.objectStoreForward = cmd
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	stop()
	return fmt.Errorf("%s did not serve within 30s of forwarding it", endpoint)
}

// objectStoreServes reports whether the endpoint answers an HTTP request, not
// merely whether something is listening on the port.
//
// The difference matters twice over. A kubectl port-forward binds its local
// listener before it contacts anything and keeps it bound after the pod behind
// it is gone, so a TCP dial succeeds against a route that carries no bytes -
// which is how a forward that outlived an object store outage was mistaken for
// a working one, and reported as the gateway refusing a download it had in fact
// served. It also means a route this process did not create is checked the same
// way as one it did, so dropObjectStoreForward recovers even for the operator's
// own forward, which quickstart section 6 tells them to run and which this
// process cannot kill.
//
// Any status code counts. The question is whether bytes reach an HTTP server,
// not whether that server likes an unauthenticated request - S3 answers this
// one with 403, and another implementation might answer differently.
func objectStoreServes(endpoint string, useTLS bool) bool {
	scheme := "http://"
	client := &http.Client{Timeout: 3 * time.Second}
	if useTLS {
		scheme = "https://"
		// The bucket clients verify properly against the installation's CA;
		// here the handshake is only being used as proof of reachability.
		// #nosec G402 -- reachability probe; the real clients verify.
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	resp, err := client.Get(scheme + endpoint + "/")
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return true
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
	filter string
	// tapRef names the tap to capture through. Empty means the installation's
	// own Active tap, which is what every spec but the inactive-source one
	// wants: standing up a tap per spec would test the tap controller.
	tapRef     string
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

// buildCapture renders the request without applying it, so a spec that expects
// the request itself to be refused can see the refusal rather than a t.Fatal.
func (a *acceptance) buildCapture(t *testing.T, name string, opts captureOptions) *trawlv1alpha1.CaptureJob {
	t.Helper()
	tap := opts.tapRef
	if tap == "" {
		tap = a.productionTap(t)
	}
	job := &trawlv1alpha1.CaptureJob{
		TypeMeta: metav1.TypeMeta{
			APIVersion: trawlv1alpha1.GroupVersion.String(),
			Kind:       "CaptureJob",
		},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: a.namespace},
		Spec: trawlv1alpha1.CaptureJobSpec{
			RequestType: trawlv1alpha1.CaptureRequestManual,
			TapRef:      corev1.LocalObjectReference{Name: tap},
			TargetNode:  opts.targetNode,
			Filter:      opts.filter,
			Duration:    opts.duration,
			Retention:   opts.retention,
		},
	}
	job.Spec.MaxSize = resource.MustParse("16Mi")
	return job
}

func (a *acceptance) applyCapture(t *testing.T, name string, opts captureOptions) {
	t.Helper()
	if err := applyObject(a.buildCapture(t, name, opts)); err != nil {
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

// forwardGateway opens a tunnel to the artifact gateway Service for one spec.
func (a *acceptance) forwardGateway(t *testing.T) string {
	t.Helper()
	return a.forwardGatewayTarget(t, "service/trawl-artifact-gateway", "443")
}

// forwardGatewayPod forwards one gateway pod directly, bypassing the Service.
//
// It exists for the outage spec. The gateway's readiness probe consults the
// artifact bucket, so an object store outage takes every gateway pod out of the
// Service's endpoints and a forward to the Service then fails with no
// endpoints. That failure is the Service doing its job, and it says nothing
// about what the gateway would have answered - which is the thing under test.
func (a *acceptance) forwardGatewayPod(t *testing.T) string {
	t.Helper()
	pod := a.gatewayPod(t)
	// The Service maps its own 443 onto whatever the container listens on; a
	// pod forward has to name the container's port. Read rather than assumed,
	// because forwarding a port nothing listens on binds locally and succeeds,
	// and only fails at request time as a refused connection that reads like
	// the gateway being down.
	return a.forwardGatewayTarget(t, "pod/"+pod, a.gatewayContainerPort(t, pod))
}

// gatewayContainerPort is the port the gateway container serves HTTPS on.
func (a *acceptance) gatewayContainerPort(t *testing.T, pod string) string {
	t.Helper()
	// Scoped to the gateway container rather than every container in the pod:
	// kubectl joins multiple jsonpath results with a space, so a sidecar with
	// its own https port would silently turn the forward argument into two
	// ports and fail with an opaque kubectl error.
	out, err := kubectlOut("get", "pod", pod, "-n", a.namespace,
		"-o", `jsonpath={.spec.containers[?(@.name=="artifact-gateway")].ports[?(@.name=="https")].containerPort}`)
	if err != nil || strings.TrimSpace(out) == "" {
		t.Fatalf("reading the gateway container's https port from %s: %v: %s", pod, err, out)
	}
	return strings.TrimSpace(out)
}

// forwardGatewayTarget forwards a named target's port and returns the URL.
//
// It waits for a TLS handshake rather than for the local port to accept.
// kubectl binds the listener before it contacts anything, so a forward to a
// target that cannot serve accepts connections and reports itself ready; the
// handshake is the cheapest thing that cannot succeed unless bytes are really
// reaching the gateway. Waiting on the weaker signal cost a debugging session:
// a pod forward to the Service's port number bound happily and failed minutes
// later as a refused connection.
func (a *acceptance) forwardGatewayTarget(t *testing.T, target, remotePort string) string {
	t.Helper()
	local, err := reserveLocalPort()
	if err != nil {
		t.Fatalf("claiming a local port: %v", err)
	}
	// #nosec G204 -- the namespace comes from configuration, the target is a
	// constant or a pod name read from the cluster, the ports from the kernel
	// and from the pod spec.
	cmd := exec.Command("kubectl", "port-forward", "-n", a.namespace,
		target, localPort(local)+":"+remotePort)
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the gateway port-forward: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		// The certificate is checked properly by the download itself, against
		// the CA the cluster issued it from. Here the handshake is only being
		// used as proof that the tunnel carries bytes.
		// #nosec G402 -- reachability probe; the real request verifies the CA.
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second},
			"tcp", local, &tls.Config{InsecureSkipVerify: true})
		if err == nil {
			_ = conn.Close()
			return "https://" + local
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("the gateway did not complete a TLS handshake on %s (forwarding %s:%s) within 30s",
		local, target, remotePort)
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
	return a.downloadVia(t, a.forwardGateway(t), capture, serviceAccount, output)
}

// downloadVia is download against a gateway the caller chose to reach.
func (a *acceptance) downloadVia(t *testing.T, gateway, capture, serviceAccount, output string) (string, error) {
	t.Helper()
	binary := trawlctlPath(t)
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

// A capture through a tap that is not Active fails as TapInactive, and says
// which of the target's problems it was.
//
// TapInactive and TargetUnavailable are separate reasons because they have
// separate remedies: an inactive tap is fixed by looking at the tap, an
// unavailable target by looking at the node. They are also the two the
// controller can most easily conflate, since both arrive as "no eligible
// target" after the same grace window. So this asserts the reason and the
// message that distinguishes it, not merely that the capture failed - a spec
// that checked only the phase would pass against a controller that had lost
// the distinction entirely.
func TestACaptureThroughAnInactiveTapFailsAsTapInactive(t *testing.T) {
	a := requireAcceptanceCluster(t)
	name := a.captureName(t, "inactivetap")

	opts := a.defaultCaptureOptions()
	opts.tapRef = a.inactiveTap(t)
	a.applyCapture(t, name, opts)

	status := a.waitForCapture(t, name, tapInactiveTimeout, "fail for want of an active tap",
		capturePhaseIs(trawlv1alpha1.CapturePhaseFailed))

	if status.Failure == nil || status.Failure.Reason != trawlv1alpha1.FailureTapInactive {
		t.Errorf("failure = %+v, want TapInactive", status.Failure)
	}
	if conditionTrue(status.Conditions, "CaptureStarted") {
		t.Error("a capture started through a tap that is not Active")
	}
	if status.Artifact != nil || status.SHA256 != "" {
		t.Errorf("an artifact exists for a capture that never ran: artifact=%+v sha=%q",
			status.Artifact, status.SHA256)
	}
	if conditionTrue(status.Conditions, "Downloadable") {
		t.Error("a capture that never ran is downloadable")
	}
	// A tap that does not exist fails with TapInactive too, so the reason alone
	// does not tell an operator which object to go and look at. The condition
	// message is what does, and it is the only place the difference survives.
	if msg := conditionMessage(status.Conditions, "TargetReady"); !strings.Contains(msg, "not Active or Degraded") {
		t.Errorf("TargetReady does not say the tap is the problem: %q\n%s",
			msg, formatConditions(status.Conditions))
	}
}

// inactiveTap stands up a NetworkTap that cannot become Active, and returns its
// name.
//
// It matches no node rather than naming an interface that does not exist. A tap
// with a target places a sensor DaemonSet and waits on it, which costs minutes
// and puts the tap through failure modes the NetworkTap suite already covers;
// a selector no node carries leaves it out of Active immediately with nothing
// scheduled, which is the whole of what a CaptureJob needs to see.
//
// It is deliberately a tap of its own rather than the deployed one made
// inactive: taking the installation's monitoring down to observe a CaptureJob's
// status field would cost more than the spec is worth, and would make this a
// disruptive spec instead of one that can run in every acceptance pass.
func (a *acceptance) inactiveTap(t *testing.T) string {
	t.Helper()
	name := a.tapName(t)
	opts := defaultTapOptions()
	// The label is scoped to this run, so a concurrent run cannot label a node
	// into this tap's selector and quietly make it Active underneath the spec.
	opts.nodeLabel = map[string]string{"trawl.cloud/acceptance-" + a.runID: "no-node-carries-this"}
	a.applyTap(t, name, opts)

	// Waited for rather than assumed: applying a tap and capturing through it
	// immediately would race the tap controller writing its first status, and
	// an empty phase is not evidence of an inactive tap.
	a.waitForTap(t, name, settleTimeout, "match no target and stay out of Active",
		func(s trawlv1alpha1.NetworkTapStatus) bool {
			return s.MatchedTargets == 0 && s.Phase != "" && s.Phase != trawlv1alpha1.TapPhaseActive
		})
	return name
}

// A capture whose filter matches no traffic completes with zero packets, and
// the empty result is downloadable like any other.
//
// "Nothing matched" and "the capture failed" are different answers, and they
// send an analyst in different directions: the first says the filter or the
// window was wrong, the second says the installation was. The distinction has
// to survive the whole chain and not only the runner that first knows it.
//
// Zero is also the value most likely to be lost. It is the zero value of the
// count, the field is an optional pointer, and it passes through a manifest,
// a status write and JSON on the way to the analyst - so anywhere it is
// treated as unset, a real capture is reported as one that never ran.
func TestACaptureThatMatchesNoTrafficCompletesWithZeroPackets(t *testing.T) {
	a := requireAcceptanceCluster(t)
	a.requireReachableObjectStore(t)
	name := a.captureName(t, "zeropacket")

	opts := a.defaultCaptureOptions()
	opts.filter = emptyCaptureFilter
	a.applyCapture(t, name, opts)

	status := a.waitForCapture(t, name, captureCompleteTimeout, "complete",
		capturePhaseIs(trawlv1alpha1.CapturePhaseCompleted))

	if status.PacketCount == nil {
		t.Fatalf("a completed capture reports no packet count, so an empty capture "+
			"cannot be told from an unmeasured one:\n%s", formatConditions(status.Conditions))
	}
	if *status.PacketCount != 0 {
		t.Errorf("packetCount = %d, want 0; %q was meant to match nothing", *status.PacketCount, emptyCaptureFilter)
	}
	// An empty capture is still a file: pcapng's section and interface headers
	// are written whether or not a packet arrives, and they are what makes the
	// result readable rather than a zero-byte object nothing can open.
	if status.SizeBytes == nil || *status.SizeBytes == 0 {
		t.Errorf("sizeBytes = %v, want the pcapng headers of an empty capture", status.SizeBytes)
	}
	if status.SHA256 == "" {
		t.Error("an empty capture has no checksum, so nothing can verify what was stored")
	}
	// It ended because the clock ran out. This is the runner's own account,
	// relayed rather than verified by the controller, and it is checked because
	// any other stop reason would mean this spec is observing an abnormal end
	// that happened to yield no packets - a different case with the same
	// packet count, and one the assertions above cannot tell apart from this.
	stop := trawlv1alpha1.CaptureStopReason("")
	if status.RunnerResult != nil {
		stop = status.RunnerResult.StopReason
	}
	if stop != trawlv1alpha1.CaptureStopDuration {
		t.Errorf("the runner stopped for %q, want Duration for a capture that simply ran out its window", stop)
	}
	for _, typ := range []string{"ArtifactVerified", "Downloadable"} {
		if !conditionTrue(status.Conditions, typ) {
			t.Errorf("%s is not True on an empty but complete capture:\n%s", typ, formatConditions(status.Conditions))
		}
	}

	// And the analyst can fetch it. The empty case is the one a shortcut would
	// skip - there is nothing to serve, after all - and an analyst who is
	// refused their own empty capture learns nothing about why it was empty.
	output := filepath.Join(t.TempDir(), "empty.pcapng")
	out, err := a.download(t, name, analystSA, output)
	if err != nil {
		t.Fatalf("the analyst could not download an empty capture: %v\n%s", err, out)
	}
	body, err := os.ReadFile(output) // #nosec G304 -- a path this test created
	if err != nil {
		t.Fatalf("reading the downloaded capture: %v", err)
	}
	sum := sha256.Sum256(body)
	if got := hex.EncodeToString(sum[:]); got != status.SHA256 {
		t.Errorf("downloaded bytes hash to %s, status records %s", got, status.SHA256)
	}
	if !bytes.HasPrefix(body, []byte{0x0a, 0x0d, 0x0d, 0x0a}) {
		t.Error("the downloaded empty capture is not a pcapng, so nothing can open it to see that it is empty")
	}
	t.Logf("empty capture: %d bytes, %d packets, stop=%s", len(body), *status.PacketCount, stop)
}

// A capture that cannot be stored fails as UploadFailed, leaves no artifact
// behind, and is not reported as downloadable.
//
// The failure this guards against is the quiet one: a capture that ran, could
// not be stored, and is recorded as complete anyway. An analyst would then be
// told evidence exists that does not, which is worse than being told the
// capture failed. So the assertions are as much about what must not be in the
// status as about the reason that must be.
//
// It is opt-in. The lever is a quota on the artifact bucket, which refuses
// every capture on the installation for as long as it is set.
func TestAFullArtifactStoreFailsTheCaptureWithoutLeavingAnArtifact(t *testing.T) {
	a := requireAcceptanceCluster(t)
	if os.Getenv("TRAWL_E2E_FULL_STORAGE") != "1" {
		t.Skip("set TRAWL_E2E_FULL_STORAGE=1 to run this; it refuses every artifact " +
			"write installation-wide while it runs")
	}
	restore := a.fillArtifactStore(t)
	defer restore()

	name := a.captureName(t, "fullstore")
	a.applyCapture(t, name, a.defaultCaptureOptions())

	status := a.waitForCapture(t, name, captureCompleteTimeout, "fail on a full artifact store",
		capturePhaseIs(trawlv1alpha1.CapturePhaseFailed))

	if status.Failure == nil || status.Failure.Reason != trawlv1alpha1.FailureUploadFailed {
		t.Errorf("failure = %+v, want UploadFailed", status.Failure)
	}
	// The capture itself ran. Reporting a storage failure as a capture failure
	// would send an operator to the tap and the node, which are both fine.
	if !conditionTrue(status.Conditions, "CaptureStarted") {
		t.Errorf("CaptureStarted is not True, so a storage failure is being reported as a capture that never started:\n%s",
			formatConditions(status.Conditions))
	}
	if status.Artifact != nil {
		t.Errorf("an artifact reference survives a capture that was never stored: %+v", status.Artifact)
	}
	if conditionTrue(status.Conditions, "Downloadable") {
		t.Error("a capture whose bytes were never stored is downloadable")
	}
	if conditionTrue(status.Conditions, "ArtifactVerified") {
		t.Errorf("ArtifactVerified is True for an artifact that was never written:\n%s",
			formatConditions(status.Conditions))
	}
	if status.SHA256 != "" {
		t.Errorf("a capture that was never stored records a checksum %q", status.SHA256)
	}

	restore()

	// The refusal was the full store and not a lasting change to the
	// installation. Without this the spec cannot tell "storage was full" from
	// "captures stopped working", and it is also what proves the lever was
	// really lifted before the run ends.
	after := a.captureName(t, "fullstore-after")
	a.applyCapture(t, after, a.defaultCaptureOptions())
	a.waitForCapture(t, after, captureCompleteTimeout, "complete once there is room again",
		capturePhaseIs(trawlv1alpha1.CapturePhaseCompleted))
}

// fillArtifactStore makes every write to the artifact bucket fail, and returns
// a restore that is safe to call more than once.
//
// A quota below what the bucket already holds, rather than real bytes: filling
// a shared cluster's object store means writing gigabytes and then hoping they
// can all be removed, and the writer is told the same thing either way. The
// quota is set through the object store's own admin client inside its pod, so
// the root credential never leaves the pod and never appears in an argument.
func (a *acceptance) fillArtifactStore(t *testing.T) func() {
	t.Helper()
	bucket := a.artifactBucket(t)
	// Reachability first, and separately. Without this split any failure of the
	// command below - a renamed subcommand, a size this client no longer
	// parses, a bucket that moved - reads as "no admin client here" and skips
	// the spec while its gate is set, so a suite that has stopped exercising
	// the case still reports green.
	if out, err := a.objectStoreAdmin(t, "quota", "info", "q/"+bucket); err != nil {
		t.Skipf("cannot reach %s through the object store's admin client (%v: %s); this spec needs it",
			bucket, err, firstLine(out))
	}
	if out, err := a.objectStoreAdmin(t, "quota", "set", "q/"+bucket, "--size", artifactQuotaFloor); err != nil {
		t.Fatalf("imposing a %s quota on %s: %v: %s", artifactQuotaFloor, bucket, err, out)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			if out, err := a.objectStoreAdmin(t, "quota", "clear", "q/"+bucket); err != nil {
				// Leaving the quota would refuse every capture on the
				// installation, so this is fatal rather than logged: the run
				// must not end quietly with the cluster in that state.
				t.Fatalf("clearing the quota on %s: %v: %s", bucket, err, out)
			}
		})
	}
}

// objectStoreAdmin runs the object store's admin client inside the object
// store's own pod.
//
// The alias is built in the pod from the environment the object store already
// has, so the root credential is not an argument here, does not reach this
// machine, and does not appear in the process list on either.
func (a *acceptance) objectStoreAdmin(t *testing.T, args ...string) (string, error) {
	t.Helper()
	script := `mc alias set q http://localhost:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null && mc --quiet ` +
		strings.Join(args, " ")
	return kubectlOut("exec", "-n", a.namespace, "deploy/minio", "--", "sh", "-c", script)
}

// artifactBucket is the bucket the installation stores captures in, read from
// the installation config rather than assumed, for the reason connectArtifacts
// reads it: a spec that named its own bucket would keep passing after the
// installation moved.
func (a *acceptance) artifactBucket(t *testing.T) string {
	t.Helper()
	raw, err := kubectlOut("get", "configmap", "trawl-config", "-n", a.namespace,
		"-o", "jsonpath={.data.config\\.yaml}")
	if err != nil {
		t.Fatalf("reading the installation config: %v: %s", err, raw)
	}
	installCfg, err := config.Load([]byte(raw))
	if err != nil {
		t.Fatalf("parsing the installation config: %v", err)
	}
	return installCfg.Artifacts.Bucket
}

// An audit outage refuses new captures and serves no capture bytes, and both
// recover when the ledger does.
//
// The property is that nothing happens unrecorded. Admission refuses a capture
// it cannot audit, and the gateway refuses a download it cannot audit at the
// last point where refusing is still free - once the presigned URL is out, the
// download has happened whether or not the ledger ever hears about it.
//
// One honest limit: this installation keeps the ledger and the artifact bucket
// in the same object store, so stopping the ledger stops both, and the
// gateway's 503 does not say which dependency was missing. What it does say is
// that the gateway refused rather than served, which is the property under
// test. An installation with separate stores could tell the two apart; this one
// cannot, and a spec that claimed otherwise would be claiming more than the
// evidence carries.
//
// It is opt-in: stopping the ledger refuses mutations installation-wide for as
// long as it takes to run.
func TestAnAuditOutageRefusesCapturesAndServesNothingUnrecorded(t *testing.T) {
	a := requireAcceptanceCluster(t)
	if os.Getenv("TRAWL_E2E_LEDGER_OUTAGE") != "1" {
		t.Skip("set TRAWL_E2E_LEDGER_OUTAGE=1 to run this; it refuses mutations " +
			"installation-wide while it runs")
	}
	a.requireReachableObjectStore(t)

	// A capture that is complete and downloadable before the ledger goes away.
	// Without this the refusal during the outage would prove nothing: an
	// unfetchable capture is refused for many reasons, and the spec has to know
	// this one was fetchable a moment earlier.
	name := a.captureName(t, "auditoutage")
	a.applyCapture(t, name, a.defaultCaptureOptions())
	completed := a.waitForCapture(t, name, captureCompleteTimeout, "complete",
		capturePhaseIs(trawlv1alpha1.CapturePhaseCompleted))
	before := filepath.Join(t.TempDir(), "before.pcapng")
	if out, err := a.download(t, name, analystSA, before); err != nil {
		t.Fatalf("the analyst could not download before the outage, so a refusal during it would prove nothing: %v\n%s",
			err, out)
	}

	restore := a.stopLedger(t)
	defer restore()

	refused := a.waitForCaptureRefusal(t)
	t.Logf("audit outage: requesting a capture was refused with %q", firstLine(refused))

	// Reached by pod rather than by Service: the gateway's readiness probe
	// consults the artifact bucket, so the outage takes every gateway pod out
	// of the Service's endpoints and a forward to the Service fails before it
	// reaches anything. That failure is the Service behaving correctly and says
	// nothing about what the gateway would have answered.
	during := filepath.Join(t.TempDir(), "during.pcapng")
	out, err := a.downloadVia(t, a.forwardGatewayPod(t), name, analystSA, during)
	if err == nil {
		t.Errorf("the gateway served a capture it could not record a download for:\n%s", out)
	} else if !strings.Contains(out, "HTTP 503") {
		// "HTTP 503" and not "503": the capture name carries a nine-digit run
		// id and the message carries a request id, either of which can hold
		// those three digits. A bare match would be satisfied by a refusal
		// that is not this one - a 403, say, which would mean the outage had
		// broken authorization rather than closed the audit gate.
		t.Errorf("the refusal is not the gateway's HTTP 503, so this proves nothing about the audit gate:\n%s", out)
	}
	if _, statErr := os.Stat(during); statErr == nil {
		t.Error("a refused download left a file behind")
	}

	// The record of the capture survives the outage. A ledger that is
	// unreachable must not cost the installation what it already knows.
	stillThere, ok := a.captureStatus(t, name)
	if !ok {
		t.Fatal("the completed capture disappeared during an audit outage")
	}
	if stillThere.SHA256 != completed.SHA256 {
		t.Errorf("the capture record changed during the outage: sha was %q, is %q",
			completed.SHA256, stillThere.SHA256)
	}

	restore()

	// The route to the object store went with the pod that was scaled away, and
	// the CLI follows the presigned redirect over it, so it has to be rebuilt
	// before the download below can reach anything. Dropping it is stopLedger's
	// job - every later spec picks up a fresh one from the same reset - and
	// re-establishing it here is this spec's, because this spec downloads again
	// before any of them run.
	a.requireReachableObjectStore(t)

	// The same request the outage refused now succeeds and is recorded, so the
	// refusal was the outage and the gate closed rather than broke.
	cursor := a.ledgerCursor(t)
	after := filepath.Join(t.TempDir(), "after.pcapng")
	if out, err := a.download(t, name, analystSA, after); err != nil {
		t.Fatalf("the analyst is still refused after the ledger returned: %v\n%s", err, out)
	}
	assertLedgerHasDownload(t, a, cursor, name, audit.DecisionAllowed)
}

// auditGateDenial is the text the admission server refuses with when it cannot
// reach the ledger. It is asserted on rather than "the request failed" for the
// reason the download half asserts on "HTTP 503": during this outage the
// manager also fails its own readiness check and leaves the webhook Service's
// endpoints, so an unaudited create is refused by the API server with "no
// endpoints available" whether the gate holds or not. A spec that accepted any
// error would pass against a controller whose audit gate had been made
// fail-open, which is the regression it exists to catch.
const auditGateDenial = "audit ledger unavailable; mutation refused"

// waitForCaptureRefusal retries a capture request until the audit gate itself
// refuses one, and returns the refusal.
//
// It retries rather than asserting on the first attempt because the manager
// notices the outage on its own schedule, and because the webhook endpoint
// comes and goes underneath it. A spec that asserted immediately would be
// measuring how long a storage client takes to give up, and would fail on a
// timing difference that changes nothing about the gate.
func (a *acceptance) waitForCaptureRefusal(t *testing.T) string {
	t.Helper()
	opts := a.defaultCaptureOptions()
	deadline := time.Now().Add(settleTimeout)
	last := "no attempt was refused"
	for time.Now().Before(deadline) {
		name := fmt.Sprintf("accept-outage-%s-%d", a.runID, time.Now().UnixNano()%1e9)
		// Registered before the apply, and registered even when the apply is
		// refused: an apply that fails after the object was created leaves the
		// same mess as one that succeeded. Cleanups run after this spec's
		// deferred restore, so these deletes are attempted with the ledger
		// back - a delete is itself an audited mutation and is refused during
		// the outage, which is how an admitted capture could otherwise be left
		// running and unaudited on the installation.
		a.deleteCaptureOnCleanup(t, name)
		err := applyObject(a.buildCapture(t, name, opts))
		if err != nil {
			last = err.Error()
			if strings.Contains(last, auditGateDenial) {
				return last
			}
			// Refused, but by the API server for want of a webhook endpoint
			// rather than by the gate. That is the outage moving the manager
			// out of the Service and says nothing about the gate, so keep
			// trying: the endpoint returns and goes as readiness flaps.
		} else {
			last = "admitted"
			// Removed promptly as well as on cleanup, so an admitted capture
			// does not collect packets for the rest of the outage.
			_ = kubectl("delete", "capturejob", name, "-n", a.namespace, "--ignore-not-found")
		}
		time.Sleep(pollInterval)
	}
	t.Fatalf("no CaptureJob request was refused by the audit gate within %s of the ledger "+
		"being stopped; the durable-audit gate is not demonstrably fail-closed (last attempt: %s)",
		settleTimeout, firstLine(last))
	return ""
}

// deleteCaptureOnCleanup registers a capture for deletion at the end of the
// spec, for names that captureName did not mint.
func (a *acceptance) deleteCaptureOnCleanup(t *testing.T, name string) {
	t.Helper()
	t.Cleanup(func() {
		if out, err := kubectlOut("delete", "capturejob", name, "-n", a.namespace,
			"--ignore-not-found"); err != nil {
			// Reported rather than swallowed: what is left behind is a capture
			// this spec created and nothing else will remove.
			t.Errorf("could not remove the capture %s this spec created: %v: %s", name, err, firstLine(out))
		}
	})
}

// gatewayPod names one running artifact gateway pod.
func (a *acceptance) gatewayPod(t *testing.T) string {
	t.Helper()
	out, err := kubectlOut("get", "pods", "-n", a.namespace,
		"-l", "app.kubernetes.io/component=artifact-gateway",
		"--field-selector=status.phase=Running",
		"-o", "jsonpath={.items[0].metadata.name}")
	if err != nil || strings.TrimSpace(out) == "" {
		t.Fatalf("finding a running artifact gateway pod: %v: %s", err, out)
	}
	return strings.TrimSpace(out)
}

// A capture already collecting survives the controller being restarted.
//
// The controller holds no part of a running capture: the runner Job is doing
// the collecting, and everything the controller needs to finish the job is in
// the objects. That is a claim about where state lives, and the only way to
// falsify it is to take the process away in the middle and see whether the
// capture still lands - an in-memory deadline, a cached observation or an
// un-persisted phase would all survive every other spec in this file and lose
// exactly this capture.
//
// It is opt-in: the controller serves the admission webhooks, so restarting it
// refuses mutations installation-wide until it is back.
func TestACaptureInFlightSurvivesAControllerRestart(t *testing.T) {
	a := requireAcceptanceCluster(t)
	if os.Getenv("TRAWL_E2E_RESTART") != "1" {
		t.Skip("set TRAWL_E2E_RESTART=1 to run this; it restarts the controller, " +
			"which refuses mutations installation-wide until it is back")
	}
	a.requireReachableObjectStore(t)
	name := a.captureName(t, "restart")

	opts := a.defaultCaptureOptions()
	opts.duration = restartCaptureDuration
	a.applyCapture(t, name, opts)

	// Restart while packets are being collected, not merely while the object
	// exists. Before startedAt there may be no runner Job yet, and a restart
	// then would test the controller creating one - which is what every other
	// spec here already covers - rather than picking up work it did not start.
	starting := a.waitForCapture(t, name, captureCompleteTimeout, "start collecting",
		func(s trawlv1alpha1.CaptureJobStatus) bool { return s.StartedAt != nil })
	if starting.CaptureEndedAt != nil {
		t.Skipf("the capture finished before the restart could reach it; %s was not long enough on this cluster",
			restartCaptureDuration)
	}

	a.restartController(t)

	status := a.waitForCapture(t, name, captureCompleteTimeout, "complete after the controller restarted",
		capturePhaseIs(trawlv1alpha1.CapturePhaseCompleted))

	if status.SHA256 == "" || status.SizeBytes == nil {
		t.Fatalf("the capture completed without an artifact record across a restart: sha=%q size=%v",
			status.SHA256, status.SizeBytes)
	}
	// StartedAt was written by the process that was killed. Losing it would
	// mean the restart cost the record of when collection began, which is the
	// timestamp everything downstream of a capture is anchored to.
	if status.StartedAt == nil || !status.StartedAt.Time.Equal(starting.StartedAt.Time) {
		t.Errorf("startedAt was %v before the restart and is %v after it",
			starting.StartedAt, status.StartedAt)
	}
	if status.RetentionDeadline == nil {
		t.Error("a capture completed across a restart has no retention deadline, so nothing will ever remove it")
	}
	for _, typ := range []string{"ArtifactVerified", "Downloadable"} {
		if !conditionTrue(status.Conditions, typ) {
			t.Errorf("%s is not True after a restart:\n%s", typ, formatConditions(status.Conditions))
		}
	}

	// And the bytes are real. A status that says Completed is the easy half;
	// the artifact the replacement process verified has to be fetchable and
	// has to hash to what it recorded.
	output := filepath.Join(t.TempDir(), "restart.pcapng")
	out, err := a.download(t, name, analystSA, output)
	if err != nil {
		t.Fatalf("the analyst could not download a capture that spanned a restart: %v\n%s", err, out)
	}
	body, err := os.ReadFile(output) // #nosec G304 -- a path this test created
	if err != nil {
		t.Fatalf("reading the downloaded capture: %v", err)
	}
	sum := sha256.Sum256(body)
	if got := hex.EncodeToString(sum[:]); got != status.SHA256 {
		t.Errorf("downloaded bytes hash to %s, status records %s", got, status.SHA256)
	}
}

// restartController takes the controller away and waits until a different pod
// is serving.
//
// The before-and-after comparison is not ceremony. A label selector that
// matches nothing deletes nothing and reports success, and a rollout that never
// started reports success immediately - so without it this spec would pass
// having restarted nothing at all, which is the shape of failure a disruption
// spec is most likely to have and least likely to notice.
func (a *acceptance) restartController(t *testing.T) {
	t.Helper()
	before := a.controllerPods(t)
	if len(before) == 0 {
		t.Fatal("no controller pod to restart")
	}
	if out, err := kubectlOut("delete", "pod", "-n", a.namespace,
		"-l", "control-plane=controller-manager", "--wait=false"); err != nil {
		t.Fatalf("restarting the controller: %v: %s", err, out)
	}

	// Polled for a different, ready pod rather than asked of `rollout status`.
	// Deleting a pod does not change the Deployment's generation, so a rollout
	// status taken immediately reads the status the deployment controller has
	// not updated yet and reports success in milliseconds - after which the
	// replacement may not exist, the terminating pod is still listed, and the
	// comparison below fails a restart that did happen.
	deadline := time.Now().Add(settleTimeout)
	var after []string
	for time.Now().Before(deadline) {
		after = a.readyControllerPods(t)
		if len(after) > 0 && !slices.Equal(before, after) {
			break
		}
		time.Sleep(pollInterval)
	}
	if len(after) == 0 || slices.Equal(before, after) {
		t.Fatalf("no replacement controller pod became ready within %s: pods were %v and are %v",
			settleTimeout, before, after)
	}
	// A running pod is not an admitting one: the manager serves the webhooks
	// and joins the webhook Service's endpoints only once it is ready. Until
	// then every mutation still fails, this spec's own cleanup delete included.
	a.waitForAdmission(t)
	t.Logf("controller restarted: %v -> %v", before, after)
}

func (a *acceptance) controllerPods(t *testing.T) []string {
	t.Helper()
	names, _ := a.listControllerPods(t)
	return names
}

// readyControllerPods lists only the controller pods reporting Ready, so a
// terminating pod and one that has not finished starting are both excluded -
// the two states that would otherwise be mistaken for a completed restart.
func (a *acceptance) readyControllerPods(t *testing.T) []string {
	t.Helper()
	_, ready := a.listControllerPods(t)
	return ready
}

// listControllerPods returns every controller pod and the subset reporting
// Ready.
//
// The readiness is filtered here rather than in the jsonpath: kubectl's
// jsonpath does not support a filter inside a filter, and asking it for one
// fails the whole query with "unterminated filter" rather than returning
// nothing - so the expression that looked like it selected ready pods selected
// no pods at all, loudly.
func (a *acceptance) listControllerPods(t *testing.T) (all, ready []string) {
	t.Helper()
	out, err := kubectlOut("get", "pods", "-n", a.namespace,
		"-l", "control-plane=controller-manager",
		"-o", "jsonpath={range .items[*]}{.metadata.name}{'\\t'}"+
			`{.status.conditions[?(@.type=="Ready")].status}`+"{'\\n'}{end}")
	if err != nil {
		t.Fatalf("listing controller pods: %v: %s", err, out)
	}
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		name, status, _ := strings.Cut(strings.TrimSpace(line), "\t")
		if name = strings.TrimSpace(name); name == "" {
			continue
		}
		all = append(all, name)
		if strings.TrimSpace(status) == "True" {
			ready = append(ready, name)
		}
	}
	slices.Sort(all)
	slices.Sort(ready)
	return all, ready
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
			// Logged so an evidence run can name the object an assertion
			// passed against. A document that says "the ledger recorded it"
			// without saying which record cannot be checked by anyone later.
			t.Logf("ledger %s: action=%s decision=%s actor=%s requestID=%s",
				rec.LedgerKey, rec.Action, rec.Decision, rec.Actor.Username, rec.RequestID)
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

// conditionMessage is what the condition says, for the assertions where the
// status alone does not distinguish two causes that share a reason.
func conditionMessage(conds []metav1.Condition, typ string) string {
	for i := range conds {
		if conds[i].Type == typ {
			return conds[i].Message
		}
	}
	return ""
}

func conditionFalse(conds []metav1.Condition, typ string) bool {
	for i := range conds {
		if conds[i].Type == typ {
			return conds[i].Status == metav1.ConditionFalse
		}
	}
	return false
}

// SC-006 is a rate, not a single observation: 95% of manual capture requests
// begin collection within 10s, and their artifact becomes downloadable within
// 60s of collection ending. One capture cannot show that, so this spec takes a
// sample and reports the distribution, and T095's evidence document is written
// from its summary.
//
// The two measurements come from the record the controller already keeps, not
// from the test's own clock. A test that timed its own polling would be
// measuring its poll interval as much as the system, and would report a budget
// met or missed for reasons no operator could reproduce from the object.
//
// Those timestamps are metav1.Time, which serializes to whole seconds, so every
// figure here is quantized to a second and carries up to a second of rounding
// either way. Against a 10s and a 60s budget that is comfortably fine, and it
// is the reason the percentiles below are round numbers rather than a sign the
// sample is degenerate.
//
// Sample size is deliberately an argument. The suite runs a small one so a
// regression in the timings is caught with the rest; the evidence run uses a
// sample large enough for a 95th percentile to mean something.
func TestManualCaptureTimingMeetsSC006(t *testing.T) {
	a := requireAcceptanceCluster(t)

	samples := envInt(t, "TRAWL_E2E_TIMING_SAMPLES", 5)
	if samples < 1 {
		t.Fatalf("TRAWL_E2E_TIMING_SAMPLES=%d is not a sample", samples)
	}

	starts := make([]time.Duration, 0, samples)
	ready := make([]time.Duration, 0, samples)
	for i := range samples {
		name := a.captureName(t, fmt.Sprintf("sc006-%02d", i))
		a.applyCapture(t, name, a.defaultCaptureOptions())
		status := a.waitForCapture(t, name, captureCompleteTimeout, "complete",
			capturePhaseIs(trawlv1alpha1.CapturePhaseCompleted))

		start, err := startLatency(status)
		if err != nil {
			t.Fatalf("capture %d: %v", i, err)
		}
		downloadable, err := downloadableLatency(status)
		if err != nil {
			t.Fatalf("capture %d: %v", i, err)
		}
		starts = append(starts, start)
		ready = append(ready, downloadable)
		packets := int64(-1)
		if status.PacketCount != nil {
			packets = *status.PacketCount
		}
		t.Logf("sc006 sample=%d start=%s downloadable=%s packets=%d",
			i, start.Round(time.Millisecond), downloadable.Round(time.Millisecond), packets)
	}

	reportLatency(t, "start (requestedAt -> startedAt)", starts, 10*time.Second)
	reportLatency(t, "downloadable (captureEndedAt -> Downloadable)", ready, 60*time.Second)
}

// startLatency is the request-to-collection figure SC-006 budgets at 10s.
//
// StartedAt is the node clock and RequestedAt the controller's. On the
// reference single-node cluster they are the same clock; anywhere else this
// difference carries the skew between them, which is why the evidence document
// records the cluster it was measured on.
func startLatency(s trawlv1alpha1.CaptureJobStatus) (time.Duration, error) {
	if s.RequestedAt == nil || s.StartedAt == nil {
		return 0, fmt.Errorf("a completed capture is missing a timestamp: requestedAt=%v startedAt=%v",
			s.RequestedAt, s.StartedAt)
	}
	return s.StartedAt.Sub(s.RequestedAt.Time), nil
}

// downloadableLatency is measured from collection ending to the condition an
// analyst acts on, not to CompletedAt. Verification is most of the gap, and a
// figure that stopped at the artifact being verified would report a budget the
// person waiting to download does not experience.
func downloadableLatency(s trawlv1alpha1.CaptureJobStatus) (time.Duration, error) {
	if s.CaptureEndedAt == nil {
		return 0, fmt.Errorf("a completed capture has no captureEndedAt")
	}
	for i := range s.Conditions {
		c := &s.Conditions[i]
		if c.Type != "Downloadable" {
			continue
		}
		if c.Status != metav1.ConditionTrue {
			return 0, fmt.Errorf("Downloadable is %s on a completed capture", c.Status)
		}
		return c.LastTransitionTime.Sub(s.CaptureEndedAt.Time), nil
	}
	return 0, fmt.Errorf("a completed capture has no Downloadable condition")
}

// reportLatency logs the distribution and fails if fewer than 95% are within
// budget. The percentiles are logged whether or not the budget is met: a run
// that only says "failed" makes the next person measure it again to find out
// by how much.
func reportLatency(t *testing.T, label string, samples []time.Duration, budget time.Duration) {
	t.Helper()
	sorted := slices.Clone(samples)
	slices.Sort(sorted)

	within := 0
	for _, d := range sorted {
		if d <= budget {
			within++
		}
	}
	rate := float64(within) / float64(len(sorted)) * 100

	t.Logf("%s: n=%d p50=%s p95=%s max=%s within %s: %.2f%% (%d/%d)",
		label, len(sorted), percentile(sorted, 50).Round(time.Millisecond),
		percentile(sorted, 95).Round(time.Millisecond),
		sorted[len(sorted)-1].Round(time.Millisecond),
		budget, rate, within, len(sorted))

	if rate < 95 {
		t.Errorf("%s: only %.2f%% within %s, SC-006 budgets 95%%", label, rate, budget)
	}
}

// percentile is the nearest-rank value, which for a sample this size is the
// only definition that returns a figure that was actually observed.
func percentile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	rank := max((p*len(sorted)+99)/100, 1)
	return sorted[rank-1]
}

func envInt(t *testing.T, key string, fallback int) int {
	t.Helper()
	raw, ok := os.LookupEnv(key)
	if !ok || raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatalf("%s=%q is not a number: %v", key, raw, err)
	}
	return n
}
