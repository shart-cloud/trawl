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

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/audit"
	"trawl.cloud/trawl/internal/authz"
	"trawl.cloud/trawl/internal/gateway"
	"trawl.cloud/trawl/internal/storage"
	"trawl.cloud/trawl/internal/telemetry"
	"trawl.cloud/trawl/test/integration/harness"
)

// The two callers quickstart §6 contrasts: one bound to a role carrying
// capturejobs/download, one bound to a role without it.
const (
	analystToken = "analyst-token"
	viewerToken  = "viewer-token"

	analystUser = "system:serviceaccount:trawl-system:trawl-acceptance-analyst"
	viewerUser  = "system:serviceaccount:trawl-system:trawl-acceptance-viewer"
)

// fakeReviewer stands in for TokenReview and SubjectAccessReview.
//
// The API server envtest runs is real, but the authorization the gateway asks
// it for is not: envtest does not issue the audience-scoped service account
// tokens the gateway requires, and RBAC on a control plane with no bindings
// answers every SubjectAccessReview the same way. What this test exists to
// exercise is everything downstream of the decision - the CaptureJob status the
// controller actually wrote, a presigned URL from a real object store, the
// bytes it serves, and the ledger record - so the decision itself is stubbed
// where internal/authz's own tests drive the real reviewer.
type fakeReviewer struct {
	// downloads is the set of usernames the SubjectAccessReview allows.
	downloads map[string]bool

	// attributes records what was asked, so the test can prove the gateway
	// asks about the subresource that separates the two roles.
	attributes []authz.Attributes
}

func (f *fakeReviewer) Authenticate(_ context.Context, token string) (authz.Identity, error) {
	switch token {
	case analystToken:
		return authz.Identity{Username: analystUser, UID: "uid-analyst"}, nil
	case viewerToken:
		return authz.Identity{Username: viewerUser, UID: "uid-viewer"}, nil
	default:
		return authz.Identity{}, authz.ErrUnauthenticated
	}
}

func (f *fakeReviewer) Authorize(_ context.Context, id authz.Identity, attrs authz.Attributes) (authz.Decision, error) {
	f.attributes = append(f.attributes, attrs)
	if f.downloads[id.Username] {
		return authz.Decision{Allowed: true, Reason: "RBAC: allowed by ClusterRoleBinding"}, nil
	}
	return authz.Decision{Allowed: false, Reason: "RBAC: no binding grants capturejobs/download"}, nil
}

// downloadHarness is a completed capture, the object store holding its
// artifact, and a gateway serving it over TLS.
type downloadHarness struct {
	job    *trawlv1alpha1.CaptureJob
	store  storage.Store
	sink   *audit.Sink
	client *gateway.Client

	// errorLog is everything the gateway wrote about these requests, kept so
	// the test can prove the presigned URL and the bearer token are not in it.
	errorLog *bytes.Buffer

	reviewer *fakeReviewer
}

// completedCapture drives a CaptureJob to Completed through the real
// reconciler, with its artifact in a real bucket rather than the fake store the
// controller tests use.
func completedCapture(t *testing.T, ns string, store storage.Store) *trawlv1alpha1.CaptureJob {
	t.Helper()

	activeTap(t, ns, time.Now())
	job := createCapture(t, ns, "manual-tls")
	r := captureReconcilerWith(t, ns, store, &fakeCommitter{})

	reconcileCapture(t, r, job)
	job = reloadCapture(t, job)
	runner := runnerJobOf(t, job)

	storeArtifact(t, store, job, 0)
	finishRunner(t, runner, batchv1.JobComplete, "")
	reconcileCapture(t, r, job)

	job = reloadCapture(t, job)
	if job.Status.Phase != trawlv1alpha1.CapturePhaseCompleted {
		t.Fatalf("phase = %q, want Completed; failure=%+v", job.Status.Phase, job.Status.Failure)
	}
	return job
}

func newDownloadHarness(t *testing.T) *downloadHarness {
	t.Helper()
	m := harness.RequireMinIO(t)
	ns := NewNamespace(t)

	store := m.ArtifactStore(t)
	presigner, ok := store.(storage.Presigner)
	if !ok {
		t.Fatalf("the artifact store cannot presign: %T", store)
	}

	// The real ledger, on the real object-locked bucket. The gateway commits
	// through the mTLS sink in the cluster rather than holding these
	// credentials itself (ADR-0003); that hop has its own test in
	// internal/audit, and both ends satisfy audit.Committer, so what is
	// exercised here is the record that reaches the bucket.
	sink, err := audit.NewSink(audit.Options{
		Store:     m.AuditStore(t),
		Prefix:    audit.DefaultPrefix,
		Retention: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}

	h := &downloadHarness{
		job:      completedCapture(t, ns, store),
		store:    store,
		sink:     sink,
		errorLog: &bytes.Buffer{},
		reviewer: &fakeReviewer{downloads: map[string]bool{analystUser: true}},
	}

	handler, err := gateway.New(gateway.Options{
		Reviewer:  h.reviewer,
		Jobs:      gateway.NewKubeJobs(Client()),
		Store:     store,
		Presigner: presigner,
		Audit:     sink,
		Metrics:   telemetry.NewMetrics(),
		ErrorLog:  h.errorLog,
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}

	srv := httptest.NewTLSServer(handler.Routes())
	t.Cleanup(srv.Close)

	ca := filepath.Join(t.TempDir(), "gateway-ca.crt")
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(ca, encoded, 0o600); err != nil {
		t.Fatalf("writing the gateway CA: %v", err)
	}
	h.client, err = gateway.NewClient(gateway.ClientOptions{BaseURL: srv.URL, CAFile: ca})
	if err != nil {
		t.Fatalf("gateway.NewClient: %v", err)
	}
	return h
}

// download runs one download the way trawlctl does.
func (h *downloadHarness) download(t *testing.T, token string) ([]byte, error) {
	t.Helper()
	var out bytes.Buffer
	_, err := h.client.Download(t.Context(), token, h.job.Namespace, h.job.Name, &out)
	return out.Bytes(), err
}

// records returns the ledger records this capture produced, read back out of
// the bucket rather than taken from the sink's return value.
func (h *downloadHarness) records(t *testing.T) []audit.Record {
	t.Helper()
	var found []audit.Record
	_, err := h.sink.Replay(t.Context(), "", func(_ context.Context, rec audit.Record) error {
		// The bucket is shared with every other test in this package, and the
		// namespace is this test's own. Matching on it rather than on the
		// CaptureJob UID is deliberate: a denial is recorded before the job is
		// read, so it carries the name that was asked for and no UID at all.
		if rec.Resource.Namespace == h.job.Namespace && rec.Resource.Name == h.job.Name {
			found = append(found, rec)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("replaying the ledger: %v", err)
	}
	return found
}

// findRecord returns the artifact.download record carrying decision, or nil.
func findRecord(records []audit.Record, decision string) *audit.Record {
	for i, rec := range records {
		if rec.Action == audit.ActionArtifactDownload && rec.Decision == decision {
			return &records[i]
		}
	}
	return nil
}

// The end-to-end path quickstart §6 documents: an authorized analyst gets the
// bytes the controller verified, through a presigned URL a real object store
// signed, and the download is in the ledger before the redirect is served.
func TestAnAuthorizedAnalystDownloadsTheVerifiedArtifact(t *testing.T) {
	h := newDownloadHarness(t)

	got, err := h.download(t, analystToken)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if string(got) != captureArtifactBody {
		t.Errorf("downloaded %q, want the stored artifact", got)
	}

	// The client verifies this itself, so the assertion is about the status:
	// what an analyst compares their sha256sum output against is the CaptureJob.
	sum := sha256.Sum256(got)
	if hex.EncodeToString(sum[:]) != h.job.Status.SHA256 {
		t.Errorf("sha256 = %s, want status.sha256 %s", hex.EncodeToString(sum[:]), h.job.Status.SHA256)
	}

	download := findRecord(h.records(t), audit.DecisionAllowed)
	if download == nil {
		t.Fatal("no allowed artifact.download record reached the ledger")
	}
	if download.Actor.Username != analystUser {
		t.Errorf("ledger actor = %q, want %q", download.Actor.Username, analystUser)
	}
}

// The difference between the two acceptance roles is one subresource, and it
// has to be the one the gateway asks about.
func TestTheGatewayAuthorizesTheDownloadSubresource(t *testing.T) {
	h := newDownloadHarness(t)
	if _, err := h.download(t, analystToken); err != nil {
		t.Fatalf("Download: %v", err)
	}

	if len(h.reviewer.attributes) != 1 {
		t.Fatalf("%d authorization checks, want 1", len(h.reviewer.attributes))
	}
	got := h.reviewer.attributes[0]
	want := authz.Attributes{
		Namespace:   h.job.Namespace,
		Group:       "trawl.cloud",
		Resource:    "capturejobs",
		Subresource: "download",
		Name:        h.job.Name,
		Verb:        "get",
	}
	if got != want {
		t.Errorf("authorized %+v, want %+v", got, want)
	}
}

// A viewer may see that a capture happened and may not read the traffic. The
// refusal is recorded, and it does not produce a presigned URL.
func TestAViewerIsRefusedTheArtifact(t *testing.T) {
	h := newDownloadHarness(t)

	body, err := h.download(t, viewerToken)
	var apiErr *gateway.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v, want a gateway APIError", err)
	}
	if apiErr.StatusCode != 403 || apiErr.Code != gateway.CodeForbidden {
		t.Errorf("status = %d %s, want 403 %s", apiErr.StatusCode, apiErr.Code, gateway.CodeForbidden)
	}
	if len(body) != 0 {
		t.Errorf("a refused download still wrote %d bytes", len(body))
	}

	denial := findRecord(h.records(t), audit.DecisionDenied)
	if denial == nil {
		t.Fatal("no denied artifact.download record reached the ledger")
	}
	if denial.Actor.Username != viewerUser {
		t.Errorf("ledger actor = %q, want %q", denial.Actor.Username, viewerUser)
	}
}

// Retention is a promise about the artifact, so it has to hold at the download
// path too - independently of whether the sweeper has deleted the object yet,
// which here it has not.
func TestAnExpiredCaptureIsNotDownloadable(t *testing.T) {
	h := newDownloadHarness(t)

	expired := reloadCapture(t, h.job)
	expired.Status.RetentionDeadline = &metav1.Time{Time: time.Now().Add(-time.Minute)}
	if err := Client().Status().Update(t.Context(), expired); err != nil {
		t.Fatalf("expiring the capture: %v", err)
	}

	_, err := h.download(t, analystToken)
	var apiErr *gateway.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v, want a gateway APIError", err)
	}
	if apiErr.StatusCode != 410 || apiErr.Code != gateway.CodeExpired {
		t.Errorf("status = %d %s, want 410 %s", apiErr.StatusCode, apiErr.Code, gateway.CodeExpired)
	}

	// The object is still there: what refused the download was the deadline,
	// not a missing object.
	if _, err := h.store.Head(t.Context(), expired.Status.Artifact.Key); err != nil {
		t.Errorf("the artifact is already gone, so this proved nothing: %v", err)
	}
}

// Constitution III at the one place a credential and a signed URL meet.
func TestNeitherTheTokenNorThePresignedURLIsLogged(t *testing.T) {
	h := newDownloadHarness(t)
	if _, err := h.download(t, analystToken); err != nil {
		t.Fatalf("Download: %v", err)
	}
	if _, err := h.download(t, viewerToken); err == nil {
		t.Fatal("the viewer's download succeeded")
	}

	logged := h.errorLog.String()
	for _, secret := range []string{analystToken, viewerToken, "X-Amz-Signature", "X-Amz-Credential"} {
		if strings.Contains(logged, secret) {
			t.Errorf("the gateway logged %q: %s", secret, logged)
		}
	}
}
