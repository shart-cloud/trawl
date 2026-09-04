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

// Package gateway serves the artifact download API.
//
// The gateway never serves packet bytes itself. It authenticates the caller
// against Kubernetes, authorizes them with ordinary RBAC, records the decision
// in the audit ledger, and only then redirects to a short-lived presigned URL.
// It holds read-only artifact-bucket credentials and no ledger credentials at
// all (ADR-0003), so a compromise of this process cannot rewrite the history of
// who downloaded what.
package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/time/rate"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/audit"
	"trawl.cloud/trawl/internal/authz"
	"trawl.cloud/trawl/internal/capture"
	"trawl.cloud/trawl/internal/sanitize"
	"trawl.cloud/trawl/internal/storage"
	"trawl.cloud/trawl/internal/telemetry"
)

// DownloadPath is the route the CLI calls, per contracts/artifact-api.openapi.yaml.
const DownloadPath = "GET /api/v1/namespaces/{namespace}/capturejobs/{name}/download"

// Error codes, fixed by the OpenAPI contract's Error.code enum.
const (
	CodeBadRequest      = "BadRequest"
	CodeUnauthenticated = "Unauthenticated"
	CodeForbidden       = "Forbidden"
	CodeNotFound        = "NotFound"
	CodeNotDownloadable = "NotDownloadable"
	CodeExpired         = "Expired"
	CodeRateLimited     = "RateLimited"
	CodeUnavailable     = "Unavailable"
)

// HeaderSHA256 carries the artifact's expected checksum on a 303.
//
// A contract extension, for the same reason status.runnerResult was one: the
// CLI has to verify what it downloaded, and the gateway is the only party it
// talks to. Without this the CLI could only check that the bytes arrived, not
// that they are the bytes the controller verified — and a truncated or
// substituted object would pass. The value is already public in the
// CaptureJob's status and is only served to a caller who has just been
// authorized for this artifact.
const HeaderSHA256 = "X-Trawl-SHA256"

// The CaptureJob API group, and the subresource RBAC grants download on.
const (
	apiGroup           = "trawl.cloud"
	capturejobResource = "capturejobs"
	downloadSubresouce = "download"
	verbGet            = "get"
)

// Path parameter shapes, from the contract. Validated before anything is done
// with them so a malformed name cannot reach the API server or the object
// store as a lookup.
var (
	namespaceRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	nameRE      = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)
)

const (
	maxNamespaceLen = 63
	maxNameLen      = 253
)

// unavailableRequestID stands in when no correlation ID could be generated.
//
// A fixed value, and deliberately not one that could be mistaken for a real ID:
// no download is served on this path, so it never reaches the ledger and cannot
// collapse two records onto one key.
const unavailableRequestID = "unavailable"

// ErrJobNotFound is returned by a CaptureJobGetter when no such job exists.
var ErrJobNotFound = errors.New("capturejob not found")

// CaptureJobGetter reads a CaptureJob by namespace and name.
//
// An interface rather than a client so the handler's decision table can be
// tested without an API server, and so the gateway's read of a job stays a
// single named capability rather than a general client it could grow other uses
// for.
type CaptureJobGetter interface {
	GetCaptureJob(ctx context.Context, namespace, name string) (*trawlv1alpha1.CaptureJob, error)
}

// Options are the collaborators a Handler needs. All but Now and ErrorLog are
// required.
type Options struct {
	Reviewer  authz.Reviewer
	Jobs      CaptureJobGetter
	Store     storage.Store
	Presigner storage.Presigner
	Audit     audit.Committer
	Metrics   *telemetry.Metrics

	// DownloadsPerMinute and DownloadBurst bound one caller's request rate.
	// Zero means the defaults.
	DownloadsPerMinute int
	DownloadBurst      int

	// AuthAttemptsPerMinute and AuthAttemptBurst bound authentication attempts
	// across all callers, valid or not. Zero means the defaults.
	AuthAttemptsPerMinute int
	AuthAttemptBurst      int

	// Now defaults to time.Now. The retention deadline is a time comparison, so
	// tests need to stand either side of it without sleeping.
	Now func() time.Time

	// ErrorLog defaults to os.Stderr. Every line written to it is sanitized.
	ErrorLog io.Writer
}

// Handler serves the artifact download API.
type Handler struct {
	opts     Options
	limit    *limiter
	attempts *rate.Limiter
}

// New validates opts and returns a Handler.
func New(opts Options) (*Handler, error) {
	var missing []string
	if opts.Reviewer == nil {
		missing = append(missing, "Reviewer")
	}
	if opts.Jobs == nil {
		missing = append(missing, "Jobs")
	}
	if opts.Store == nil {
		missing = append(missing, "Store")
	}
	if opts.Presigner == nil {
		missing = append(missing, "Presigner")
	}
	// Not optional. A gateway that cannot record a download must not serve one
	// (FR-036), so a nil committer would be a silent, permanent audit gap
	// rather than a misconfiguration anybody notices.
	if opts.Audit == nil {
		missing = append(missing, "Audit")
	}
	if opts.Metrics == nil {
		missing = append(missing, "Metrics")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("gateway handler requires %s", strings.Join(missing, ", "))
	}

	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.ErrorLog == nil {
		opts.ErrorLog = os.Stderr
	}
	return &Handler{
		opts:     opts,
		limit:    newLimiter(opts.DownloadsPerMinute, opts.DownloadBurst, opts.Now),
		attempts: newAttemptLimiter(opts.AuthAttemptsPerMinute, opts.AuthAttemptBurst),
	}, nil
}

// Routes returns the mux serving the contract's endpoints.
func (h *Handler) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc(DownloadPath, h.download)
	mux.HandleFunc("GET /healthz", h.healthz)
	mux.HandleFunc("GET /readyz", h.readyz)
	return mux
}

// download implements the one interesting route.
//
// The order of the steps is the security property, not an implementation
// detail. Authorization is decided before the CaptureJob is read, so a caller
// who may not download learns nothing about whether the name they asked for
// exists. The audit record is committed before the redirect, so a download that
// the ledger does not know about cannot happen.
func (h *Handler) download(w http.ResponseWriter, r *http.Request) {
	// Generated here, never taken from the request. A client-supplied
	// correlation ID would be part of the audit record's idempotency key, and
	// replaying a previous request's ID would then collapse a second download
	// onto the first record - letting a caller suppress the evidence of their
	// own download by choosing a header value.
	requestID, err := newRequestID()
	if err != nil {
		// Fail closed rather than serve with a placeholder. The request ID is
		// part of the audit record's idempotency key, so a constant fallback
		// would make every download after the first collapse onto one record -
		// the same evidence-suppression hole that keeping the ID out of the
		// caller's hands exists to close.
		// Still a contract-shaped response: request_id is required and must be
		// non-empty, and this is the reply where an operator most needs
		// something to search for. The marker says plainly that correlation is
		// unavailable rather than leaving an empty string to puzzle over.
		h.opts.Metrics.ArtifactDownloadTotal.WithLabelValues(telemetry.DownloadUnavailable).Inc()
		writeError(w, unavailableRequestID, http.StatusServiceUnavailable, CodeUnavailable,
			"a dependency is unavailable; retry shortly")
		return
	}
	ctx := r.Context()

	namespace := r.PathValue("namespace")
	name := r.PathValue("name")
	if !validNamespace(namespace) || !validName(name) {
		h.deny(w, requestID, http.StatusBadRequest, CodeBadRequest,
			"namespace or name is not a valid Kubernetes identifier", telemetry.DownloadBadRequest)
		return
	}

	token, ok := bearerToken(r)
	if !ok {
		h.deny(w, requestID, http.StatusUnauthorized, CodeUnauthenticated,
			"a bearer token is required", telemetry.DownloadUnauthenticated)
		return
	}

	// Before Authenticate, because Authenticate is a TokenReview against the API
	// server and a rejected token never reaches the per-caller limiter below -
	// that one is keyed on an identity a rejected token does not have. Without
	// this, anyone who can reach the port could make Trawl generate unbounded
	// API server load with garbage tokens.
	if !h.attempts.AllowN(h.opts.Now(), 1) {
		w.Header().Set("Retry-After", "1")
		h.deny(w, requestID, http.StatusTooManyRequests, CodeRateLimited,
			"too many authentication attempts; retry shortly", telemetry.DownloadRateLimited)
		return
	}

	identity, err := h.opts.Reviewer.Authenticate(ctx, token)
	switch {
	case errors.Is(err, authz.ErrUnauthenticated):
		h.deny(w, requestID, http.StatusUnauthorized, CodeUnauthenticated,
			"the bearer token was not accepted", telemetry.DownloadUnauthenticated)
		return
	case err != nil:
		h.unavailable(w, requestID, "authenticating the caller", err)
		return
	}

	// The per-caller limit, which needs an identity and so can only be applied
	// once there is one. It bounds what a single authorized credential can do -
	// notably, sweeping every capture in the cluster - while the global ceiling
	// above bounds what an unauthenticated flood can cost.
	if !h.limit.allow(identity) {
		w.Header().Set("Retry-After", "1")
		h.deny(w, requestID, http.StatusTooManyRequests, CodeRateLimited,
			"too many download requests; retry shortly", telemetry.DownloadRateLimited)
		return
	}

	decision, err := h.opts.Reviewer.Authorize(ctx, identity, authz.Attributes{
		Namespace:   namespace,
		Group:       apiGroup,
		Resource:    capturejobResource,
		Subresource: downloadSubresouce,
		Name:        name,
		Verb:        verbGet,
	})
	if err != nil {
		h.unavailable(w, requestID, "authorizing the caller", err)
		return
	}
	if !decision.Allowed {
		// Recorded, but not blocking: the contract requires a durable
		// acknowledgement before a *successful* authorization is acted on, and
		// refusing to answer a denial because the ledger is busy would turn an
		// audit blip into a denial-of-service on an answer that reveals
		// nothing.
		h.auditDenial(ctx, requestID, identity, namespace, name, decision.Reason)
		h.deny(w, requestID, http.StatusForbidden, CodeForbidden,
			"the caller may not download this capture", telemetry.DownloadDenied)
		return
	}

	job, err := h.opts.Jobs.GetCaptureJob(ctx, namespace, name)
	switch {
	case errors.Is(err, ErrJobNotFound):
		h.deny(w, requestID, http.StatusNotFound, CodeNotFound,
			"no such capture", telemetry.DownloadNotFound)
		return
	case err != nil:
		h.unavailable(w, requestID, "reading the capture", err)
		return
	}

	now := h.opts.Now()
	switch capture.DecideDownload(job, now) {
	case capture.DownloadExpired:
		h.deny(w, requestID, http.StatusGone, CodeExpired,
			"the capture's retention deadline has passed", telemetry.DownloadExpired)
		return
	case capture.DownloadNotReady:
		h.deny(w, requestID, http.StatusConflict, CodeNotDownloadable,
			"the capture has no verified artifact to download", telemetry.DownloadNotReady)
		return
	case capture.DownloadAllowed:
	}

	// DecideDownload reads status, which records what was true when the
	// controller last looked. Retention may have deleted the object since. Head
	// is the live check that stops the gateway signing a URL for an object that
	// is already gone.
	key := job.Status.Artifact.Key
	if _, err := h.opts.Store.Head(ctx, key); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			h.deny(w, requestID, http.StatusNotFound, CodeNotFound,
				"the capture's artifact is no longer stored", telemetry.DownloadNotFound)
			return
		}
		h.unavailable(w, requestID, "verifying the artifact", err)
		return
	}

	// Audit before the redirect, and fail closed. This is the last point at
	// which refusing costs nothing: once the URL is out, the download has
	// happened whether or not the ledger heard about it.
	if err := h.auditGrant(ctx, requestID, identity, job); err != nil {
		h.unavailable(w, requestID, "recording the download", err)
		return
	}

	// Never past the retention deadline, and never longer than the presign
	// ceiling. Without the clamp a URL minted a minute before the deadline
	// would still be redeemable four minutes after it, which is a retention
	// policy that quietly does not hold.
	//
	// Computed here rather than from the `now` used for the decision above: the
	// live Head and the blocking audit commit sit in between, and the commit
	// alone is allowed ten seconds. For a capture whose deadline is seconds
	// away, a lifetime that was positive when the decision was taken can be
	// negative by the time the URL is actually minted.
	ttl := min(storage.MaxPresignTTL, job.Status.RetentionDeadline.Sub(h.opts.Now()))
	if ttl <= 0 {
		h.deny(w, requestID, http.StatusGone, CodeExpired,
			"the capture's retention deadline has passed", telemetry.DownloadExpired)
		return
	}

	signed, err := h.opts.Presigner.PresignGet(ctx, key, ttl)
	if err != nil {
		if errors.Is(err, storage.ErrPresignExpired) {
			h.deny(w, requestID, http.StatusGone, CodeExpired,
				"the capture's retention deadline has passed", telemetry.DownloadExpired)
			return
		}
		h.unavailable(w, requestID, "presigning the artifact", err)
		return
	}

	h.opts.Metrics.ArtifactOperationsTotal.
		WithLabelValues(telemetry.ArtifactOpPresign, telemetry.ArtifactResultSuccess).Inc()
	h.opts.Metrics.ArtifactDownloadTotal.WithLabelValues(telemetry.DownloadAllowed).Inc()

	noStore(w, requestID)
	w.Header().Set(HeaderSHA256, job.Status.SHA256)
	w.Header().Set("Location", signed.String())
	w.WriteHeader(http.StatusSeeOther)
}

// auditGrant records an authorized download and waits for the ledger.
func (h *Handler) auditGrant(ctx context.Context, requestID string, id authz.Identity, job *trawlv1alpha1.CaptureJob) error {
	rec := audit.Record{
		SchemaVersion: audit.SchemaVersion,
		RecordedAt:    h.opts.Now().UTC(),
		Action:        audit.ActionArtifactDownload,
		Decision:      audit.DecisionAllowed,
		Reason:        "authorized by subject access review",
		Actor:         actorOf(id),
		Resource:      resourceOf(job.Namespace, job.Name, string(job.UID)),
		RequestID:     requestID,
		// The request ID is generated per request, so each download attempt
		// gets its own record and a retry of the same attempt collapses onto
		// one.
		StableKey: audit.StableKeyForAutomatic(audit.ActionArtifactDownload, string(job.UID), requestID),
	}
	if _, err := h.opts.Audit.Commit(ctx, rec); err != nil {
		return err
	}
	return nil
}

// auditDenial records a refused download without blocking the response.
func (h *Handler) auditDenial(ctx context.Context, requestID string, id authz.Identity, namespace, name, reason string) {
	rec := audit.Record{
		SchemaVersion: audit.SchemaVersion,
		RecordedAt:    h.opts.Now().UTC(),
		Action:        audit.ActionArtifactDownload,
		Decision:      audit.DecisionDenied,
		Reason:        reason,
		Actor:         actorOf(id),
		// No UID: the job was deliberately not read, so the gateway knows the
		// name that was asked for and nothing more. Recording the attempt
		// matters even when the name never existed.
		Resource:  resourceOf(namespace, name, ""),
		RequestID: requestID,
		StableKey: audit.StableKeyForAutomatic(audit.ActionArtifactDownload, namespace+"/"+name, requestID),
	}
	if _, err := h.opts.Audit.Commit(ctx, rec); err != nil {
		h.logf("request %s: recording a denied download: %v", requestID, err)
	}
}

func actorOf(id authz.Identity) audit.Actor {
	return audit.Actor{Username: id.Username, UID: id.UID, Groups: id.Groups}
}

func resourceOf(namespace, name, uid string) audit.Resource {
	return audit.Resource{
		Group:     apiGroup,
		Kind:      "CaptureJob",
		Namespace: namespace,
		Name:      name,
		UID:       uid,
	}
}

// errorBody is the contract's Error schema.
type errorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

// deny writes a contract error response and counts the decision.
func (h *Handler) deny(w http.ResponseWriter, requestID string, status int, code, message, metric string) {
	h.opts.Metrics.ArtifactDownloadTotal.WithLabelValues(metric).Inc()
	writeError(w, requestID, status, code, message)
}

// unavailable logs the underlying cause and returns the contract's 503.
//
// The cause is never in the response. A dependency error routinely names the
// object store endpoint or echoes a request body, and the caller can do nothing
// with it but learn about the inside of the cluster.
func (h *Handler) unavailable(w http.ResponseWriter, requestID, what string, cause error) {
	h.logf("request %s: %s: %v", requestID, what, sanitize.Error(cause))
	h.opts.Metrics.ArtifactDownloadTotal.WithLabelValues(telemetry.DownloadUnavailable).Inc()
	w.Header().Set("Retry-After", "5")
	writeError(w, requestID, http.StatusServiceUnavailable, CodeUnavailable,
		"a dependency is unavailable; retry shortly")
}

func writeError(w http.ResponseWriter, requestID string, status int, code, message string) {
	noStore(w, requestID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// Messages here are fixed strings, but they go through sanitize anyway so
	// that a future edit cannot turn one into a formatted dependency error
	// without the redaction coming with it.
	_ = json.NewEncoder(w).Encode(errorBody{
		Code:      code,
		Message:   sanitize.String(message),
		RequestID: requestID,
	})
}

// noStore sets the headers every response in this API must carry.
//
// no-store on every path, not just the redirect: a cached 403 is an
// authorization decision served without asking, and a cached 404 leaks that a
// name was once absent.
func noStore(w http.ResponseWriter, requestID string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Request-ID", requestID)
}

type healthBody struct {
	Status string `json:"status"`
}

func (h *Handler) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, healthBody{Status: "ok"})
}

// readyz reports whether the gateway can actually answer a download right now.
//
// The dependencies it names are the ones a download cannot proceed without: the
// API server for both reviews, and the artifact bucket for the liveness check
// and the signature. The audit sink is deliberately not probed here — commits
// are the controller manager's listener, and a sink blip should fail the
// download that needs it rather than take the whole gateway out of service.
func (h *Handler) readyz(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// An empty token is rejected without a round trip, so this asks about a
	// token shaped like one and expects a rejection, not an error.
	if _, err := h.opts.Reviewer.Authenticate(ctx, "readiness-probe"); err != nil && !errors.Is(err, authz.ErrUnauthenticated) {
		h.logf("readiness: kubernetes authentication: %v", sanitize.Error(err))
		writeJSON(w, http.StatusServiceUnavailable, healthBody{Status: "unavailable"})
		return
	}
	if _, err := h.opts.Store.Head(ctx, readinessProbeKey); err != nil && !errors.Is(err, storage.ErrNotFound) {
		h.logf("readiness: artifact storage: %v", sanitize.Error(err))
		writeJSON(w, http.StatusServiceUnavailable, healthBody{Status: "unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, healthBody{Status: "ok"})
}

// readinessProbeKey is a key nothing writes. A HEAD of it is the cheapest call
// that proves the bucket answers and the credential is accepted: ErrNotFound is
// the healthy answer, and anything else is the outage.
const readinessProbeKey = ".trawl-readiness-probe"

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// logf writes one sanitized line. Everything the gateway handles is either a
// credential or names one, so the sanitizer is on the only path out.
func (h *Handler) logf(format string, args ...any) {
	_, _ = fmt.Fprintln(h.opts.ErrorLog, "artifact-gateway: "+sanitize.String(fmt.Sprintf(format, args...)))
}

// bearerToken extracts the credential without ever putting it anywhere else.
func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", false
	}
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}
	return token, true
}

func validNamespace(s string) bool {
	return len(s) > 0 && len(s) <= maxNamespaceLen && namespaceRE.MatchString(s)
}

func validName(s string) bool {
	return len(s) > 0 && len(s) <= maxNameLen && nameRE.MatchString(s)
}

// newRequestID returns an opaque correlation identifier.
//
// Random rather than derived from anything about the request: the contract says
// it carries no user or artifact data, and it appears in the ledger, in logs and
// in the response. It must also be unique, because the audit record's
// idempotency key is built from it.
//
// randRead is a variable so the failure branch can be exercised. crypto/rand
// does not fail on any supported platform, which is exactly why the branch
// would otherwise be written once and never run - and an unrun branch on the
// audit path is how the placeholder-ID bug got written in the first place.
var randRead = rand.Read

func newRequestID() (string, error) {
	var b [16]byte
	if _, err := randRead(b[:]); err != nil {
		return "", sanitize.Errorf("generating a request id: %v", err)
	}
	return hex.EncodeToString(b[:]), nil
}
