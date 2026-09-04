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

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/audit"
	"trawl.cloud/trawl/internal/authz"
	"trawl.cloud/trawl/internal/status"
	"trawl.cloud/trawl/internal/storage"
	"trawl.cloud/trawl/internal/telemetry"
)

const (
	testNamespace = "trawl-system"
	testJobName   = "manual-tls"
	testKey       = "captures/trawl-system/uid-1/capture.pcapng"

	// A real service-account token shape: what a leak would actually look like.
	analystToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbmFseXN0In0.c2lnLWFuYWx5c3Qtc2VjcmV0"
)

var (
	now      = time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	deadline = now.Add(48 * time.Hour)
)

// fakeJobs is a CaptureJobGetter over a map.
type fakeJobs struct {
	jobs map[string]*trawlv1alpha1.CaptureJob
	err  error

	mu      sync.Mutex
	lookups int
}

func (f *fakeJobs) GetCaptureJob(_ context.Context, namespace, name string) (*trawlv1alpha1.CaptureJob, error) {
	f.mu.Lock()
	f.lookups++
	f.mu.Unlock()

	if f.err != nil {
		return nil, f.err
	}
	job, ok := f.jobs[namespace+"/"+name]
	if !ok {
		return nil, ErrJobNotFound
	}
	return job, nil
}

func (f *fakeJobs) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lookups
}

// recordingCommitter is an audit sink that can be switched off.
type recordingCommitter struct {
	mu       sync.Mutex
	err      error
	onCommit func()
	records  []audit.Record
}

func (c *recordingCommitter) Commit(_ context.Context, rec audit.Record) (audit.CommitResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, rec)
	if c.onCommit != nil {
		c.onCommit()
	}
	if c.err != nil {
		return audit.CommitResult{Result: audit.ResultUnavailable}, c.err
	}
	return audit.CommitResult{Result: audit.ResultSuccess, LedgerKey: "ledger/1"}, nil
}

func (c *recordingCommitter) all() []audit.Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]audit.Record(nil), c.records...)
}

// completedJob is a CaptureJob in the one state a download is allowed from.
func completedJob() *trawlv1alpha1.CaptureJob {
	job := &trawlv1alpha1.CaptureJob{
		ObjectMeta: metav1.ObjectMeta{
			Name:       testJobName,
			Namespace:  testNamespace,
			UID:        types.UID("uid-1"),
			Generation: 1,
		},
	}
	job.Status.Phase = trawlv1alpha1.CapturePhaseCompleted
	job.Status.ObservedGeneration = 1
	job.Status.SHA256 = strings.Repeat("ab", 32)
	job.Status.Artifact = &trawlv1alpha1.ArtifactReference{Key: testKey, VerifiedAt: metav1.Time{Time: now}}
	job.Status.RetentionDeadline = &metav1.Time{Time: deadline}
	status.Set(&job.Status.Conditions, status.New(
		status.TypeArtifactVerified, metav1.ConditionTrue, status.ReasonArtifactVerified, "", 1))
	return job
}

// fixture is a handler and everything it was built from, so a test can steer
// any collaborator and inspect what the handler did with it.
type fixture struct {
	handler   *Handler
	reviewer  *authz.Fake
	jobs      *fakeJobs
	store     *storage.Fake
	presigner *storage.FakePresigner
	audit     *recordingCommitter
	logs      *bytes.Buffer
	metrics   *telemetry.Metrics
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	store := storage.NewFake()
	if _, err := store.Put(t.Context(), testKey, []byte("pcap bytes"), storage.PutOptions{}); err != nil {
		t.Fatalf("seeding the store: %v", err)
	}

	f := &fixture{
		reviewer: &authz.Fake{Tokens: map[string]authz.Identity{
			analystToken: {Username: "system:serviceaccount:trawl-system:analyst", UID: "sa-uid", Groups: []string{"g"}},
		}},
		jobs:      &fakeJobs{jobs: map[string]*trawlv1alpha1.CaptureJob{testNamespace + "/" + testJobName: completedJob()}},
		store:     store,
		presigner: &storage.FakePresigner{},
		audit:     &recordingCommitter{},
		logs:      &bytes.Buffer{},
		metrics:   telemetry.NewMetrics(),
	}

	h, err := New(Options{
		Reviewer:  f.reviewer,
		Jobs:      f.jobs,
		Store:     f.store,
		Presigner: f.presigner,
		Audit:     f.audit,
		Metrics:   f.metrics,
		Now:       func() time.Time { return now },
		ErrorLog:  f.logs,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f.handler = h
	return f
}

// get issues a download request with the given token; an empty token sends no
// Authorization header at all.
func (f *fixture) get(token, namespace, name string) *httptest.ResponseRecorder {
	target := "/api/v1/namespaces/" + namespace + "/capturejobs/" + name + "/download"
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.handler.Routes().ServeHTTP(rec, req)
	return rec
}

func TestDownloadRedirectsAnAuthorizedCaller(t *testing.T) {
	f := newFixture(t)

	rec := f.get(analystToken, testNamespace, testJobName)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d, want 303; body %s", rec.Code, rec.Body)
	}

	location := rec.Header().Get("Location")
	if location == "" || !strings.Contains(location, testKey) {
		t.Errorf("Location = %q, want a presigned URL for %s", location, testKey)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if rec.Header().Get("X-Request-ID") == "" {
		t.Error("no X-Request-ID on a successful redirect")
	}

	// The one record the ledger must carry, with the identity that asked.
	records := f.audit.all()
	if len(records) != 1 {
		t.Fatalf("committed %d records, want 1", len(records))
	}
	rc := records[0]
	if rc.Action != audit.ActionArtifactDownload || rc.Decision != audit.DecisionAllowed {
		t.Errorf("record action/decision = %s/%s", rc.Action, rc.Decision)
	}
	if rc.Actor.Username != "system:serviceaccount:trawl-system:analyst" {
		t.Errorf("record actor = %+v", rc.Actor)
	}
	if rc.Resource.Name != testJobName || rc.Resource.Namespace != testNamespace || rc.Resource.UID != "uid-1" {
		t.Errorf("record resource = %+v", rc.Resource)
	}
	if rc.RequestID != rec.Header().Get("X-Request-ID") {
		t.Errorf("record request ID %q does not match the response header %q", rc.RequestID, rec.Header().Get("X-Request-ID"))
	}
	if err := rc.Validate(); err != nil {
		t.Errorf("committed an invalid record: %v", err)
	}
}

// The SubjectAccessReview must ask about the download subresource. An SAR for
// plain `get capturejobs` would be satisfied by ordinary read access to the
// CRD, which every viewer has — and no status-code assertion would notice.
func TestDownloadAuthorizesTheDownloadSubresource(t *testing.T) {
	f := newFixture(t)
	f.get(analystToken, testNamespace, testJobName)

	checked := f.reviewer.Authorized()
	if len(checked) != 1 {
		t.Fatalf("made %d authorization checks, want 1", len(checked))
	}
	want := authz.Attributes{
		Namespace: testNamespace, Group: "trawl.cloud", Resource: "capturejobs",
		Subresource: "download", Name: testJobName, Verb: "get",
	}
	if checked[0] != want {
		t.Errorf("authorized %+v, want %+v", checked[0], want)
	}
}

// An unauthorized caller must not be able to tell an existing capture from one
// that never existed. The handler achieves that by deciding authorization
// before it reads anything, so the two cases are literally the same code path.
func TestDownloadIsEnumerationSafe(t *testing.T) {
	for _, name := range []string{testJobName, "does-not-exist"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.reviewer.Allow = func(authz.Identity, authz.Attributes) authz.Decision {
				return authz.Decision{Allowed: false, Reason: "RBAC: no binding for system:serviceaccount:trawl-system:viewer"}
			}

			rec := f.get(analystToken, testNamespace, name)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status %d, want 403", rec.Code)
			}

			// The job is never read, so there is nothing for the response to
			// differ on.
			if f.jobs.count() != 0 {
				t.Errorf("read the CaptureJob %d times before authorizing", f.jobs.count())
			}

			var body errorBody
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decoding the body: %v", err)
			}
			if body.Code != CodeForbidden {
				t.Errorf("code = %q, want %q", body.Code, CodeForbidden)
			}
			// The API server's reason names the roles it consulted, which is
			// the cluster structure a denied caller must not be able to map.
			if strings.Contains(rec.Body.String(), "RBAC") || strings.Contains(rec.Body.String(), "binding") {
				t.Errorf("the denial echoed the authorizer's reason: %s", rec.Body)
			}
		})
	}

	// Both denials must be byte-identical apart from the correlation ID.
	f1, f2 := newFixture(t), newFixture(t)
	deny := func(authz.Identity, authz.Attributes) authz.Decision { return authz.Decision{Allowed: false} }
	f1.reviewer.Allow, f2.reviewer.Allow = deny, deny

	existing := f1.get(analystToken, testNamespace, testJobName)
	missing := f2.get(analystToken, testNamespace, "does-not-exist")
	strip := func(rec *httptest.ResponseRecorder) string {
		var b errorBody
		_ = json.Unmarshal(rec.Body.Bytes(), &b)
		b.RequestID = ""
		out, _ := json.Marshal(b)
		return string(out)
	}
	if strip(existing) != strip(missing) {
		t.Errorf("denials differ:\n existing: %s\n missing:  %s", strip(existing), strip(missing))
	}
}

// A denied attempt still belongs in the ledger: "who tried to fetch this
// evidence" is exactly the question the ledger exists to answer.
func TestDownloadRecordsADeniedAttempt(t *testing.T) {
	f := newFixture(t)
	f.reviewer.Allow = func(authz.Identity, authz.Attributes) authz.Decision {
		return authz.Decision{Allowed: false, Reason: "no binding"}
	}

	f.get(analystToken, testNamespace, testJobName)

	records := f.audit.all()
	if len(records) != 1 {
		t.Fatalf("committed %d records, want 1", len(records))
	}
	if records[0].Decision != audit.DecisionDenied {
		t.Errorf("decision = %q, want %q", records[0].Decision, audit.DecisionDenied)
	}
	if err := records[0].Validate(); err != nil {
		t.Errorf("committed an invalid record: %v", err)
	}
}

// A ledger outage must not stop the gateway answering a denial. Refusing to say
// "no" because the audit sink is busy protects nothing and turns an audit blip
// into an outage.
func TestDeniedAttemptsSurviveALedgerOutage(t *testing.T) {
	f := newFixture(t)
	f.audit.err = errors.New("sink unavailable")
	f.reviewer.Allow = func(authz.Identity, authz.Attributes) authz.Decision {
		return authz.Decision{Allowed: false}
	}

	rec := f.get(analystToken, testNamespace, testJobName)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403 despite the ledger being down", rec.Code)
	}
}

// The inverse, and the property FR-036 actually turns on: a download that the
// ledger did not hear about must not happen.
func TestGrantFailsClosedWhenTheLedgerIsUnavailable(t *testing.T) {
	f := newFixture(t)
	f.audit.err = errors.New("sink unavailable")

	rec := f.get(analystToken, testNamespace, testJobName)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("redirected anyway, to %q", loc)
	}
	// Nothing was signed, so no URL exists for anyone to have captured.
	if calls := f.presigner.Calls(); len(calls) != 0 {
		t.Errorf("presigned %d URLs after the audit commit failed", len(calls))
	}
}

func TestDownloadStatusForEachState(t *testing.T) {
	cases := []struct {
		name    string
		arrange func(*fixture)
		token   string
		status  int
		code    string
		metric  string
	}{
		{
			name:   "no authorization header",
			token:  "",
			status: http.StatusUnauthorized,
			code:   CodeUnauthenticated,
			metric: telemetry.DownloadUnauthenticated,
		},
		{
			name:   "unknown token",
			token:  "not-a-known-token",
			status: http.StatusUnauthorized,
			code:   CodeUnauthenticated,
			metric: telemetry.DownloadUnauthenticated,
		},
		{
			name:    "api server unreachable",
			arrange: func(f *fixture) { f.reviewer.AuthenticateErr = errors.New("apiserver down") },
			status:  http.StatusServiceUnavailable,
			code:    CodeUnavailable,
			metric:  telemetry.DownloadUnavailable,
		},
		{
			name:    "authorizer cannot decide",
			arrange: func(f *fixture) { f.reviewer.AuthorizeErr = errors.New("webhook authorizer down") },
			status:  http.StatusServiceUnavailable,
			code:    CodeUnavailable,
			metric:  telemetry.DownloadUnavailable,
		},
		{
			name:    "authorized but no such capture",
			arrange: func(f *fixture) { f.jobs.jobs = nil },
			status:  http.StatusNotFound,
			code:    CodeNotFound,
			metric:  telemetry.DownloadNotFound,
		},
		{
			name:    "reading the capture failed",
			arrange: func(f *fixture) { f.jobs.err = errors.New("etcd unavailable") },
			status:  http.StatusServiceUnavailable,
			code:    CodeUnavailable,
			metric:  telemetry.DownloadUnavailable,
		},
		{
			name: "capture still running",
			arrange: func(f *fixture) {
				job := completedJob()
				job.Status.Phase = trawlv1alpha1.CapturePhaseCapturing
				f.jobs.jobs[testNamespace+"/"+testJobName] = job
			},
			status: http.StatusConflict,
			code:   CodeNotDownloadable,
			metric: telemetry.DownloadNotReady,
		},
		{
			name: "capture failed",
			arrange: func(f *fixture) {
				job := completedJob()
				job.Status.Phase = trawlv1alpha1.CapturePhaseFailed
				f.jobs.jobs[testNamespace+"/"+testJobName] = job
			},
			status: http.StatusConflict,
			code:   CodeNotDownloadable,
			metric: telemetry.DownloadNotReady,
		},
		{
			name: "past the retention deadline",
			arrange: func(f *fixture) {
				job := completedJob()
				job.Status.RetentionDeadline = &metav1.Time{Time: now.Add(-time.Second)}
				f.jobs.jobs[testNamespace+"/"+testJobName] = job
			},
			status: http.StatusGone,
			code:   CodeExpired,
			metric: telemetry.DownloadExpired,
		},
		{
			// Status says verified; retention already removed the object. The
			// live check is the only thing that catches this.
			name:    "artifact already deleted",
			arrange: func(f *fixture) { _ = f.store.Delete(context.Background(), testKey) },
			status:  http.StatusNotFound,
			code:    CodeNotFound,
			metric:  telemetry.DownloadNotFound,
		},
		{
			// Distinct from an absent object: an unreachable bucket is a 503 to
			// retry, while a missing one is a 404. Collapsing them would report
			// a storage outage as a deleted capture.
			name:    "artifact storage unreachable",
			arrange: func(f *fixture) { f.store.FailHead(errors.New("connection refused")) },
			status:  http.StatusServiceUnavailable,
			code:    CodeUnavailable,
			metric:  telemetry.DownloadUnavailable,
		},
		{
			name:    "presigning failed",
			arrange: func(f *fixture) { f.presigner.Err = errors.New("signing failed") },
			status:  http.StatusServiceUnavailable,
			code:    CodeUnavailable,
			metric:  telemetry.DownloadUnavailable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			if tc.arrange != nil {
				tc.arrange(f)
			}
			token := tc.token
			if token == "" && tc.name != "no authorization header" {
				token = analystToken
			}

			rec := f.get(token, testNamespace, testJobName)
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d; body %s", rec.Code, tc.status, rec.Body)
			}
			if loc := rec.Header().Get("Location"); loc != "" {
				t.Errorf("a refused request still carried a Location: %q", loc)
			}
			if got := rec.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", got)
			}
			if rec.Header().Get("X-Request-ID") == "" {
				t.Error("no X-Request-ID on the response")
			}

			var body errorBody
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decoding the body: %v", err)
			}
			if body.Code != tc.code {
				t.Errorf("code = %q, want %q", body.Code, tc.code)
			}
			if body.RequestID != rec.Header().Get("X-Request-ID") {
				t.Errorf("body request_id %q does not match the header %q", body.RequestID, rec.Header().Get("X-Request-ID"))
			}
			if len(body.Message) > 512 {
				t.Errorf("message is %d bytes, over the contract's 512", len(body.Message))
			}
			if !telemetry.IsValidDownloadDecision(tc.metric) {
				t.Errorf("%q is not a contract download decision", tc.metric)
			}
		})
	}
}

func TestDownloadRejectsMalformedPathParameters(t *testing.T) {
	for _, tc := range []struct{ namespace, name string }{
		{"Trawl-System", testJobName},
		{"trawl_system", testJobName},
		{testNamespace, "Manual-TLS"},
		{testNamespace, "-leading-dash"},
		{strings.Repeat("a", 64), testJobName},
		{testNamespace, strings.Repeat("a", 254)},
	} {
		f := newFixture(t)
		rec := f.get(analystToken, tc.namespace, tc.name)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s/%s: status %d, want 400", tc.namespace, tc.name, rec.Code)
		}
		// A malformed name must not become a lookup against the API server or
		// a token review against a caller we have not validated the request of.
		if f.jobs.count() != 0 {
			t.Errorf("%s/%s: looked the job up anyway", tc.namespace, tc.name)
		}
	}
}

// The presigned URL must never outlive the retention deadline. A URL minted a
// minute before the deadline and valid for five would be redeemable four
// minutes after the capture was supposed to be unreachable.
func TestPresignTTLIsClampedToTheRetentionDeadline(t *testing.T) {
	cases := []struct {
		name     string
		deadline time.Time
		want     time.Duration
	}{
		{"far from the deadline", now.Add(48 * time.Hour), storage.MaxPresignTTL},
		{"exactly the ceiling away", now.Add(storage.MaxPresignTTL), storage.MaxPresignTTL},
		{"inside the ceiling", now.Add(90 * time.Second), 90 * time.Second},
		{"a second away", now.Add(time.Second), time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			job := completedJob()
			job.Status.RetentionDeadline = &metav1.Time{Time: tc.deadline}
			f.jobs.jobs[testNamespace+"/"+testJobName] = job

			if rec := f.get(analystToken, testNamespace, testJobName); rec.Code != http.StatusSeeOther {
				t.Fatalf("status %d, want 303; body %s", rec.Code, rec.Body)
			}
			calls := f.presigner.Calls()
			if len(calls) != 1 {
				t.Fatalf("presigned %d times, want 1", len(calls))
			}
			if calls[0].TTL != tc.want {
				t.Errorf("TTL = %s, want %s", calls[0].TTL, tc.want)
			}
			if calls[0].Key != testKey {
				t.Errorf("presigned %q, want %q", calls[0].Key, testKey)
			}
		})
	}
}

// Constitution III. The token, the presigned URL and its signature are the
// three things that must never reach a log line, an error body, or the ledger.
func TestNoSecretReachesALogLineOrABody(t *testing.T) {
	secrets := []string{analystToken, "sig-analyst-secret", "X-Amz-Signature", "fake-signature"}

	scenarios := map[string]func(*fixture){
		"success": func(*fixture) {},
		"authenticate unavailable": func(f *fixture) {
			f.reviewer.AuthenticateErr = errors.New("Post https://10.96.0.1/apis/authentication.k8s.io/v1/tokenreviews: token " + analystToken)
		},
		"presign unavailable": func(f *fixture) {
			f.presigner.Err = errors.New("GET https://minio:9000/artifacts/o?X-Amz-Signature=deadbeefcafe: 403")
		},
		"store unavailable": func(f *fixture) {
			f.store.FailHead(errors.New("credentials secretAccessKey=hunter2 rejected"))
		},
		"denied": func(f *fixture) {
			f.reviewer.Allow = func(authz.Identity, authz.Attributes) authz.Decision {
				return authz.Decision{Allowed: false, Reason: "token " + analystToken + " has no binding"}
			}
		},
	}

	for name, arrange := range scenarios {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			arrange(f)
			rec := f.get(analystToken, testNamespace, testJobName)

			body := rec.Body.String()
			logs := f.logs.String()
			for _, secret := range secrets {
				if strings.Contains(body, secret) {
					t.Errorf("response body leaked %q: %s", secret, body)
				}
				if strings.Contains(logs, secret) {
					t.Errorf("log leaked %q: %s", secret, logs)
				}
			}
			// The ledger is durable and widely readable; a token in a record is
			// a token that outlives its own expiry.
			for _, r := range f.audit.all() {
				encoded, err := json.Marshal(r.Sanitized())
				if err != nil {
					t.Fatalf("encoding the record: %v", err)
				}
				for _, secret := range secrets {
					if bytes.Contains(encoded, []byte(secret)) {
						t.Errorf("audit record leaked %q: %s", secret, encoded)
					}
				}
			}
		})
	}
}

// A client-chosen correlation ID would be part of the audit record's
// idempotency key. Replaying a previous request's ID would then collapse the
// second download onto the first record, letting a caller suppress the evidence
// of their own download by setting a header.
func TestRequestIDIsNotTakenFromTheCaller(t *testing.T) {
	f := newFixture(t)
	const forged = "forged-correlation-id"

	target := "/api/v1/namespaces/" + testNamespace + "/capturejobs/" + testJobName + "/download"
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("Authorization", "Bearer "+analystToken)
	req.Header.Set("X-Request-ID", forged)
	rec := httptest.NewRecorder()
	f.handler.Routes().ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Request-ID"); got == forged {
		t.Error("the gateway echoed a caller-supplied request ID")
	}
	records := f.audit.all()
	if len(records) != 1 {
		t.Fatalf("committed %d records, want 1", len(records))
	}
	if strings.Contains(records[0].StableKey, forged) || records[0].RequestID == forged {
		t.Error("a caller-supplied request ID reached the audit record's identity")
	}

	// Two downloads of the same capture are two records, not one.
	second := f.get(analystToken, testNamespace, testJobName)
	if second.Code != http.StatusSeeOther {
		t.Fatalf("second download status %d, want 303", second.Code)
	}
	all := f.audit.all()
	if len(all) != 2 {
		t.Fatalf("committed %d records for two downloads, want 2", len(all))
	}
	if all[0].StableKey == all[1].StableKey {
		t.Error("two separate downloads shared one idempotency key; the second is invisible in the ledger")
	}
}

func TestHealthEndpointsMatchTheContract(t *testing.T) {
	f := newFixture(t)

	for _, path := range []string{"/healthz", "/readyz"} {
		rec := httptest.NewRecorder()
		f.handler.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d, want 200; body %s", path, rec.Code, rec.Body)
		}
		var body healthBody
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: decoding %q: %v", path, rec.Body, err)
		}
		if body.Status != "ok" {
			t.Errorf("%s: status = %q, want ok", path, body.Status)
		}
	}

	// Readiness must follow the dependencies a download actually needs, or a
	// gateway that cannot serve anything stays in the Service's endpoints.
	t.Run("unready when kubernetes is unreachable", func(t *testing.T) {
		f := newFixture(t)
		f.reviewer.AuthenticateErr = errors.New("apiserver down")
		rec := httptest.NewRecorder()
		f.handler.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("status %d, want 503", rec.Code)
		}
	})
}

func TestNewRequiresEveryCollaborator(t *testing.T) {
	base := func() Options {
		return Options{
			Reviewer: &authz.Fake{}, Jobs: &fakeJobs{}, Store: storage.NewFake(),
			Presigner: &storage.FakePresigner{}, Audit: &recordingCommitter{}, Metrics: telemetry.NewMetrics(),
		}
	}
	if _, err := New(base()); err != nil {
		t.Fatalf("a complete Options was rejected: %v", err)
	}
	// The audit committer especially: a nil one would be a silent, permanent
	// audit gap rather than a startup failure.
	for name, drop := range map[string]func(*Options){
		"Reviewer":  func(o *Options) { o.Reviewer = nil },
		"Jobs":      func(o *Options) { o.Jobs = nil },
		"Store":     func(o *Options) { o.Store = nil },
		"Presigner": func(o *Options) { o.Presigner = nil },
		"Audit":     func(o *Options) { o.Audit = nil },
		"Metrics":   func(o *Options) { o.Metrics = nil },
	} {
		opts := base()
		drop(&opts)
		if _, err := New(opts); err == nil {
			t.Errorf("a nil %s was accepted", name)
		}
	}
}

// Guards the contract's own numbers rather than trusting the constants.
func TestPresignCeilingMatchesTheContract(t *testing.T) {
	if storage.MaxPresignTTL != 5*time.Minute {
		t.Errorf("MaxPresignTTL = %s, want the contract's 5m", storage.MaxPresignTTL)
	}
	if got := strconv.Itoa(int(storage.MaxPresignTTL.Seconds())); got != "300" {
		t.Errorf("ceiling in seconds = %s, want 300", got)
	}
}

// A rate limit on downloads is not about load: the gateway serves a redirect,
// not the bytes. It is about what an authorized credential can do if it is
// stolen — sweeping every capture in the cluster — and it turns that from as
// fast as the network allows into something slow enough to notice in the
// ledger.
func TestDownloadRateLimitIsPerCaller(t *testing.T) {
	f := newFixture(t)
	const burst = 3
	h, err := New(Options{
		Reviewer: f.reviewer, Jobs: f.jobs, Store: f.store, Presigner: f.presigner,
		Audit: f.audit, Metrics: f.metrics, ErrorLog: f.logs,
		Now:                func() time.Time { return now },
		DownloadsPerMinute: 1,
		DownloadBurst:      burst,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f.handler = h

	// A second caller, so the limit can be shown to be per-identity.
	const otherToken = "other-analyst-token"
	f.reviewer.Tokens[otherToken] = authz.Identity{Username: "system:serviceaccount:trawl-system:other", UID: "sa-uid-2"}

	for i := range burst {
		if rec := f.get(analystToken, testNamespace, testJobName); rec.Code != http.StatusSeeOther {
			t.Fatalf("request %d: status %d, want 303", i+1, rec.Code)
		}
	}

	rec := f.get(analystToken, testNamespace, testJobName)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d after exhausting the burst, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("a 429 carried no Retry-After, which the contract requires")
	}
	var body errorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding the body: %v", err)
	}
	if body.Code != CodeRateLimited {
		t.Errorf("code = %q, want %q", body.Code, CodeRateLimited)
	}

	// One caller's exhausted budget must not deny anyone else. Limiting on
	// source address instead would fail here: in this deployment every request
	// arrives from the same proxy.
	if rec := f.get(otherToken, testNamespace, testJobName); rec.Code != http.StatusSeeOther {
		t.Errorf("a second caller got %d; one analyst's limit throttled another", rec.Code)
	}

	// A throttled request must not have reached authorization, presigning or
	// the ledger — otherwise the limit would still let a caller hammer the API
	// server's SubjectAccessReview path.
	// The burst, plus the second caller's one successful download. The
	// throttled request must add nothing.
	if got := len(f.presigner.Calls()); got != burst+1 {
		t.Errorf("presigned %d times, want %d: a throttled request still signed a URL", got, burst+1)
	}
	if got := len(f.reviewer.Authorized()); got != burst+1 {
		t.Errorf("made %d authorization checks, want %d (burst plus the second caller)", got, burst+1)
	}
}

// The budget refills, or a busy hour would lock an analyst out until a restart.
func TestDownloadRateLimitRefills(t *testing.T) {
	f := newFixture(t)
	clock := now
	h, err := New(Options{
		Reviewer: f.reviewer, Jobs: f.jobs, Store: f.store, Presigner: f.presigner,
		Audit: f.audit, Metrics: f.metrics, ErrorLog: f.logs,
		Now:                func() time.Time { return clock },
		DownloadsPerMinute: 60,
		DownloadBurst:      1,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f.handler = h

	if rec := f.get(analystToken, testNamespace, testJobName); rec.Code != http.StatusSeeOther {
		t.Fatalf("first request: status %d, want 303", rec.Code)
	}
	if rec := f.get(analystToken, testNamespace, testJobName); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: status %d, want 429", rec.Code)
	}

	// 60 per minute is one per second.
	clock = clock.Add(2 * time.Second)
	if rec := f.get(analystToken, testNamespace, testJobName); rec.Code != http.StatusSeeOther {
		t.Errorf("after the budget refilled: status %d, want 303", rec.Code)
	}
}

// The per-caller limit is keyed on an identity a rejected token never has, so
// it cannot bound a flood of garbage tokens. Each of those is a TokenReview
// against the API server, and the gateway's ingress is open to any source.
func TestRejectedTokensCannotDriveUnboundedTokenReviews(t *testing.T) {
	f := newFixture(t)
	const ceiling = 4
	h, err := New(Options{
		Reviewer: f.reviewer, Jobs: f.jobs, Store: f.store, Presigner: f.presigner,
		Audit: f.audit, Metrics: f.metrics, ErrorLog: f.logs,
		Now:                   func() time.Time { return now },
		AuthAttemptsPerMinute: 60,
		AuthAttemptBurst:      ceiling,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f.handler = h

	// Count what actually reaches the API server.
	var reviews int
	f.reviewer.OnAuthenticate = func() { reviews++ }

	for i := range ceiling {
		if rec := f.get("garbage-token", testNamespace, testJobName); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d, want 401", i+1, rec.Code)
		}
	}

	rec := f.get("garbage-token", testNamespace, testJobName)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d past the ceiling, want 429", rec.Code)
	}
	if reviews != ceiling {
		t.Errorf("submitted %d token reviews for %d attempts past the ceiling; "+
			"a rejected token still reached the API server", reviews, ceiling)
	}
}

// The URL must not outlive the deadline even when the steps between the
// decision and the signature take time — the live Head, and an audit commit
// that is allowed ten seconds.
func TestPresignTTLIsRecomputedAfterTheAuditCommit(t *testing.T) {
	f := newFixture(t)
	clock := now

	job := completedJob()
	job.Status.RetentionDeadline = &metav1.Time{Time: now.Add(5 * time.Second)}
	f.jobs.jobs[testNamespace+"/"+testJobName] = job

	// The commit is where the time goes, so that is where the clock advances.
	f.audit.onCommit = func() { clock = clock.Add(30 * time.Second) }

	h, err := New(Options{
		Reviewer: f.reviewer, Jobs: f.jobs, Store: f.store, Presigner: f.presigner,
		Audit: f.audit, Metrics: f.metrics, ErrorLog: f.logs,
		Now: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f.handler = h

	rec := f.get(analystToken, testNamespace, testJobName)
	if rec.Code != http.StatusGone {
		t.Fatalf("status %d, want 410: the deadline passed while the commit was in flight", rec.Code)
	}
	if calls := f.presigner.Calls(); len(calls) != 0 {
		t.Errorf("minted a URL valid for %s past the retention deadline", calls[0].TTL)
	}
}

// The one response where an operator most needs something to search for must
// still satisfy the contract's error shape — including when the correlation ID
// itself could not be generated, which is the path that produced an empty
// request_id and no header at all.
func TestUnavailableResponsesAlwaysCarryARequestID(t *testing.T) {
	t.Run("when the request id cannot be generated", func(t *testing.T) {
		original := randRead
		randRead = func([]byte) (int, error) { return 0, errors.New("entropy source failed") }
		t.Cleanup(func() { randRead = original })

		f := newFixture(t)
		rec := f.get(analystToken, testNamespace, testJobName)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status %d, want 503", rec.Code)
		}
		var body errorBody
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decoding the body: %v", err)
		}
		if body.RequestID == "" {
			t.Error("request_id is empty; the contract requires a non-empty value")
		}
		if rec.Header().Get("X-Request-ID") == "" {
			t.Error("no X-Request-ID header on an error response")
		}
		// Nothing may be served on this path: without a unique ID two
		// downloads would share an audit key and the second would vanish.
		if calls := f.presigner.Calls(); len(calls) != 0 {
			t.Error("served a download with no usable correlation ID")
		}
	})

	f := newFixture(t)
	f.reviewer.AuthenticateErr = errors.New("apiserver down")

	rec := f.get(analystToken, testNamespace, testJobName)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", rec.Code)
	}
	var body errorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding the body: %v", err)
	}
	// minLength 1 in the contract, and a required response header.
	if body.RequestID == "" {
		t.Error("request_id is empty; the contract requires a non-empty value")
	}
	if rec.Header().Get("X-Request-ID") == "" {
		t.Error("no X-Request-ID header on an error response")
	}
}
