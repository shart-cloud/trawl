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

// Package config holds Trawl's installation-level configuration: the settings an
// operator sets once when installing, as distinct from the per-resource settings
// expressed through CRDs.
//
// The split matters for security. Storage endpoints, bucket names, credential
// mount paths, retention ceilings, and image digests live here precisely so a
// NetworkTap or CapturePolicy author cannot change them. A policy that could name
// its own bucket could redirect evidence out of the audited path (ADR-0003).
//
// Validation is strict and reports every problem at once. A partially valid
// install that starts anyway is worse than one that refuses to start, because the
// unset field is usually the security-relevant one.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
	"sigs.k8s.io/yaml"

	"trawl.cloud/trawl/internal/sanitize"
)

// Defaults applied before validation.
const (
	// DefaultSystemNamespace is the only namespace in which Trawl custom
	// resources are accepted unless the installation overrides it (FR-001).
	DefaultSystemNamespace = "trawl-system"

	// DefaultAuditRetention is the middle of the permitted 90-730 day range.
	DefaultAuditRetention = 365 * 24 * time.Hour

	// DefaultAuditSinkListenAddr is the port the audit sink listens on. It is
	// deliberately not the webhook's: the webhook is dialled by the API server
	// with its own self-signed certificate, while this is dialled by Trawl's
	// own components with client certificates from the installation CA.
	DefaultAuditSinkListenAddr = ":9444"

	// DefaultGatewayListenAddr is the port the artifact gateway serves HTTPS on.
	DefaultGatewayListenAddr = ":8443"

	// DefaultGatewayTokenAudience is the audience a download token must be
	// bound to.
	//
	// It is deliberately not the API server's own audience. A service account's
	// default token carries that one, so accepting it would let a token read
	// out of any pod in the cluster be replayed to fetch packet captures; a
	// Trawl-specific audience means the token had to be minted for this
	// gateway on purpose.
	//nolint:gosec // G101: an audience is a public identifier that tokens are
	// bound to, not a credential. It is published in the CLI's own
	// documentation and in every quickstart command.
	DefaultGatewayTokenAudience = "trawl-artifact-gateway"

	// DefaultCaptureRetentionCeiling caps how long any capture may be kept.
	DefaultCaptureRetentionCeiling = 30 * 24 * time.Hour

	// DefaultCaptureStartupBudget bounds the time from Job creation to the
	// first packet: image pull, interface open, filter compilation.
	DefaultCaptureStartupBudget = 5 * time.Minute

	// DefaultCaptureUploadBudget bounds the time from capture end to a verified
	// artifact. A 1 GiB capture over a modest link fits comfortably.
	DefaultCaptureUploadBudget = 15 * time.Minute

	// DefaultEventWorkerServiceAccount is the identity permitted to create
	// Policy-typed CaptureJobs. It is a service account name in the system
	// namespace; the webhook matches it against the API server's user info.
	DefaultEventWorkerServiceAccount = "event-worker"

	// DefaultCaptureCredentialsSecret is the name of the Secret the capture
	// runner mounts for artifact-bucket credentials. It is a reference, not a
	// credential; the operator never reads the Secret.
	DefaultCaptureCredentialsSecret = "trawl-artifact-credentials" //nolint:gosec // Secret name, not a secret.

	// DefaultContentRefreshInterval is how often analyzer workloads roll to
	// pick up upstream detection content (FR-044).
	DefaultContentRefreshInterval = 24 * time.Hour
)

// Audit retention bounds from data-model.md.
const (
	MinAuditRetention = 90 * 24 * time.Hour
	MaxAuditRetention = 730 * 24 * time.Hour
)

// Config is the complete installation configuration.
type Config struct {
	// ClusterID is the bounded cluster identifier used as a Loki and metric
	// label. It must stay low-cardinality.
	ClusterID string `json:"clusterID"`

	// SystemNamespace is the single namespace in which Trawl custom resources
	// are accepted and privileged workloads are created.
	SystemNamespace string `json:"systemNamespace,omitempty"`

	Loki   LokiConfig   `json:"loki"`
	Hubble HubbleConfig `json:"hubble"`

	// Artifacts and AuditLedger are separate buckets with separate credentials.
	// Validation enforces that separation rather than trusting the operator.
	Artifacts   BucketConfig `json:"artifacts"`
	AuditLedger BucketConfig `json:"auditLedger"`

	// AuditRetention is how long ledger objects are kept, within 90-730 days.
	AuditRetention Duration `json:"auditRetention,omitempty"`

	// AuditClientIdentities are the mTLS client identities permitted to commit
	// audit records to the sink.
	AuditClientIdentities []string `json:"auditClientIdentities"`

	// AuditSink is the listener that serves those clients.
	AuditSink AuditSinkConfig `json:"auditSink,omitempty"`

	// CaptureRetentionCeiling is the longest retention any capture may request.
	CaptureRetentionCeiling Duration `json:"captureRetentionCeiling,omitempty"`

	// SensorAgentResources are the requests and limits the operator renders for
	// the sensor sidecar in every analyzer pod. Deliberately not a NetworkTap
	// field: an under-provisioned sensor drops observations silently.
	SensorAgentResources ResourceRequirements `json:"sensorAgentResources"`

	// Capture governs capture runner Jobs and who may act on CaptureJobs.
	Capture CaptureConfig `json:"capture,omitempty"`

	// Gateway configures the artifact download API.
	Gateway GatewayConfig `json:"gateway,omitempty"`

	Content ContentConfig `json:"content"`
	Images  ImageConfig   `json:"images"`
}

// CaptureConfig governs the capture runner and CaptureJob authorization.
//
// Identity fields are matched against the API server's authenticated user info
// in the admission webhook. They are configuration, not policy the object can
// carry, so a requester cannot promote itself.
type CaptureConfig struct {
	// EventWorkerServiceAccount is the only identity permitted to create
	// Policy-typed CaptureJobs. Name only; the namespace is SystemNamespace.
	EventWorkerServiceAccount string `json:"eventWorkerServiceAccount,omitempty"`

	// RetentionAdminGroups and RetentionAdminUsers may change a CaptureJob's
	// retention after creation. Nobody else can, including the requester.
	RetentionAdminGroups []string `json:"retentionAdminGroups,omitempty"`
	RetentionAdminUsers  []string `json:"retentionAdminUsers,omitempty"`

	// CredentialsSecret is the Secret in SystemNamespace the runner mounts for
	// artifact-bucket credentials. The operator never reads it.
	CredentialsSecret string `json:"credentialsSecret,omitempty"`

	// StartupBudget and UploadBudget, added to the requested duration, form
	// the runner Job's activeDeadlineSeconds. They are the only way a hung
	// runner ends.
	StartupBudget Duration `json:"startupBudget,omitempty"`
	UploadBudget  Duration `json:"uploadBudget,omitempty"`

	// RunnerResources and ReporterResources are rendered into every runner
	// Job. The runner's memory limit is separate from the capture size bound,
	// which lives on the work volume.
	RunnerResources   ResourceRequirements `json:"runnerResources,omitempty"`
	ReporterResources ResourceRequirements `json:"reporterResources,omitempty"`
}

// AuditSinkConfig is the mTLS listener through which everything that is not
// the controller manager commits audit records.
//
// ADR-0003 gives ledger credentials to the manager alone, so the gateway, the
// event worker and the webhooks have no way to write history except through
// this listener. That makes it a hard dependency of theirs rather than an
// optional feature: without it they cannot record what they did, and FR-036
// says an action that cannot be recorded must not complete.
//
// TLS material is mounted, never inlined, and the client certificate's common
// name is checked against AuditClientIdentities. The CA that signs these is
// Trawl's own, not the webhook's self-signed issuer, because here both ends
// are Trawl components and each must authenticate the other.
type AuditSinkConfig struct {
	// ListenAddr defaults to DefaultAuditSinkListenAddr.
	ListenAddr string `json:"listenAddr,omitempty"`

	// CertFile and KeyFile are the sink's serving certificate; CAFile is the
	// bundle its clients' certificates are verified against.
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
	CAFile   string `json:"caFile"`
}

// GatewayConfig configures the artifact gateway: how it is reached, whose
// tokens it accepts, and how it records what it served.
//
// The gateway is the only component that hands packet data to a human, so every
// field here is a control on that path rather than a tuning knob. None of them
// is defaulted to something permissive: an unset certificate is a gateway that
// does not start, which is the correct failure.
type GatewayConfig struct {
	// ListenAddr defaults to DefaultGatewayListenAddr.
	ListenAddr string `json:"listenAddr,omitempty"`

	// TokenAudience defaults to DefaultGatewayTokenAudience. Tokens not bound
	// to it are refused.
	TokenAudience string `json:"tokenAudience,omitempty"`

	// CertFile and KeyFile are the gateway's serving certificate. There is no
	// self-signed fallback: the CLI sends a bearer token to whatever answers,
	// so an unauthenticated server is a credential-harvesting opportunity.
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`

	// DownloadsPerMinute and DownloadBurst bound one caller's download rate.
	// Zero means the gateway's defaults.
	//
	// The bound is per authenticated identity, not per address: in any real
	// deployment every request arrives from the same ingress, so an
	// address-based limit would either do nothing or let one analyst throttle
	// the rest. What it is for is an authorized credential being used to sweep
	// every capture at once.
	DownloadsPerMinute int `json:"downloadsPerMinute,omitempty"`
	DownloadBurst      int `json:"downloadBurst,omitempty"`

	// AuthAttemptsPerMinute and AuthAttemptBurst bound authentication attempts
	// across all callers, valid or not. Zero means the gateway's defaults.
	//
	// A separate ceiling from the two above because the per-caller limit is
	// keyed on an identity a rejected token never has: without this, anyone who
	// can reach the port could make Trawl submit unbounded TokenReviews to the
	// API server. Set it well above real use - it is a ceiling on abuse, not a
	// throttle on work.
	AuthAttemptsPerMinute int `json:"authAttemptsPerMinute,omitempty"`
	AuthAttemptBurst      int `json:"authAttemptBurst,omitempty"`

	// AuditClient is how the gateway reaches the sink. It holds no ledger
	// credentials of its own (ADR-0003), so this is its only way to record a
	// download - and FR-036 means a download it cannot record is one it must
	// refuse.
	AuditClient AuditClientConfig `json:"auditClient"`
}

// AuditClientConfig is the mTLS client half of the audit sink connection.
//
// The certificate's common name has to appear in the sink's
// AuditClientIdentities exactly. A mismatch is not a degraded mode: it is a 403
// on every commit, and therefore a gateway that refuses every download.
type AuditClientConfig struct {
	// Endpoint is the sink base URL, e.g.
	// https://trawl-audit.trawl-system.svc:8443
	Endpoint string `json:"endpoint"`

	// ServerName is the name verified in the sink's certificate.
	ServerName string `json:"serverName"`

	CAFile   string `json:"caFile"`
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

// LokiConfig addresses the log store used for observations and audit replay.
type LokiConfig struct {
	Endpoint string `json:"endpoint"`
	TenantID string `json:"tenantID,omitempty"`
}

// HubbleConfig addresses Hubble Relay for cluster-flow observations and
// denied-flow triggers. TLS material is mounted, never inlined.
type HubbleConfig struct {
	Endpoint   string `json:"endpoint"`
	CAFile     string `json:"caFile"`
	CertFile   string `json:"certFile"`
	KeyFile    string `json:"keyFile"`
	ServerName string `json:"serverName"`
}

// BucketConfig describes one private object-store bucket.
//
// CredentialsPath is a mount path, not a credential. Secrets come from the
// cluster's secret boundary and never appear in this structure.
type BucketConfig struct {
	Endpoint        string `json:"endpoint"`
	Bucket          string `json:"bucket"`
	Region          string `json:"region,omitempty"`
	CredentialsPath string `json:"credentialsPath"`
	UseTLS          bool   `json:"useTLS,omitempty"`
}

// ResourceRequirements mirrors the Kubernetes requests/limits pair as strings so
// the configuration stays plain YAML; values are parsed during validation.
type ResourceRequirements struct {
	RequestsCPU    string `json:"requestsCPU"`
	RequestsMemory string `json:"requestsMemory"`
	LimitsCPU      string `json:"limitsCPU"`
	LimitsMemory   string `json:"limitsMemory"`
}

// ContentConfig configures the two-layer analyzer content model (ADR-0005).
type ContentConfig struct {
	SuricataFeedURL string   `json:"suricataFeedURL"`
	ZeekScriptRepo  string   `json:"zeekScriptRepo"`
	RefreshInterval Duration `json:"refreshInterval,omitempty"`
}

// ImageConfig holds digest-pinned references for every image Trawl renders.
type ImageConfig struct {
	Suricata        string `json:"suricata"`
	Zeek            string `json:"zeek"`
	SensorAgent     string `json:"sensorAgent"`
	CaptureRunner   string `json:"captureRunner"`
	CaptureReporter string `json:"captureReporter"`
	ContentInit     string `json:"contentInit"`
}

// Default runner and reporter sizing. The runner's memory limit is separate
// from the capture size bound, which lives on the work volume; the reporter
// only polls a directory and patches status.
var (
	defaultRunnerResources = ResourceRequirements{
		RequestsCPU: "100m", RequestsMemory: "128Mi", LimitsCPU: "1", LimitsMemory: "1Gi", //nolint:goconst // Sizing literals, not a shared constant.
	}
	defaultReporterResources = ResourceRequirements{
		RequestsCPU: "10m", RequestsMemory: "32Mi", LimitsCPU: "100m", LimitsMemory: "128Mi",
	}
)

// RFC 1123 label, the Kubernetes namespace rule.
var namespaceRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// A digest-pinned reference: repository@sha256:<64 hex>.
var digestRE = regexp.MustCompile(`^[^@\s]+@sha256:[0-9a-f]{64}$`)

// durationRE additionally accepts a day suffix, which Go's ParseDuration does not.
var durationRE = regexp.MustCompile(`^(\d+)d$`)

// Duration is a time.Duration that reads as a string in configuration.
//
// The plain time.Duration marshals as an integer count of nanoseconds, so an
// operator writing `auditRetention: 90d` - the form this file's own
// documentation uses - got "cannot unmarshal string into Go struct field of
// type time.Duration" and the only accepted spelling was 7776000000000000.
// ParseDuration existed for exactly this and nothing called it.
type Duration time.Duration

// UnmarshalJSON accepts either a duration string or a raw nanosecond count.
//
// The number is still accepted because it is what previously-written
// configurations contain, and rejecting them would turn this fix into a
// breaking change for anyone who worked around the bug.
func (d *Duration) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		// An explicit null asks for the default, so leave the field at its zero
		// value for ApplyDefaults to fill. Falling through would unmarshal it
		// as a string no-op, leaving "", which ParseDuration rejects.
		return nil
	}

	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		parsed, err := ParseDuration(s)
		if err != nil {
			return err
		}
		*d = Duration(parsed)
		return nil
	}

	var n int64
	if err := json.Unmarshal(data, &n); err != nil {
		return errors.New("duration must be a string such as \"90d\" or a nanosecond count")
	}
	*d = Duration(n)
	return nil
}

// MarshalJSON writes the string form, so a round-trip does not silently convert
// a readable configuration into nanoseconds.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// Duration returns the value as a time.Duration.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

// ParseDuration parses a Go duration, extended with a `d` (day) unit so
// retention can be written as `30d` rather than `720h`.
func ParseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, errors.New("empty duration")
	}
	if m := durationRE.FindStringSubmatch(s); m != nil {
		days, err := strconv.Atoi(m[1])
		if err != nil {
			return 0, sanitize.Errorf("invalid day count: %v", err)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, sanitize.Errorf("invalid duration: %v", err)
	}
	if d <= 0 {
		return 0, errors.New("duration must be positive")
	}
	return d, nil
}

// ApplyDefaults fills unset optional fields. It never overwrites a set value and
// never supplies a default for a security-relevant required field: an unset
// bucket or image must fail validation, not silently acquire a value.
func (c *Config) ApplyDefaults() {
	if c.SystemNamespace == "" {
		c.SystemNamespace = DefaultSystemNamespace
	}
	if c.AuditRetention == 0 {
		c.AuditRetention = Duration(DefaultAuditRetention)
	}
	if c.AuditSink.ListenAddr == "" {
		c.AuditSink.ListenAddr = DefaultAuditSinkListenAddr
	}
	if c.CaptureRetentionCeiling == 0 {
		c.CaptureRetentionCeiling = Duration(DefaultCaptureRetentionCeiling)
	}
	if c.Content.RefreshInterval == 0 {
		c.Content.RefreshInterval = Duration(DefaultContentRefreshInterval)
	}
	c.Capture.applyDefaults()
	c.Gateway.applyDefaults()
}

func (g *GatewayConfig) applyDefaults() {
	if g.ListenAddr == "" {
		g.ListenAddr = DefaultGatewayListenAddr
	}
	if g.TokenAudience == "" {
		g.TokenAudience = DefaultGatewayTokenAudience
	}
}

func (c *CaptureConfig) applyDefaults() {
	if c.EventWorkerServiceAccount == "" {
		c.EventWorkerServiceAccount = DefaultEventWorkerServiceAccount
	}
	if c.CredentialsSecret == "" {
		c.CredentialsSecret = DefaultCaptureCredentialsSecret
	}
	if c.StartupBudget == 0 {
		c.StartupBudget = Duration(DefaultCaptureStartupBudget)
	}
	if c.UploadBudget == 0 {
		c.UploadBudget = Duration(DefaultCaptureUploadBudget)
	}
	if c.RunnerResources == (ResourceRequirements{}) {
		c.RunnerResources = defaultRunnerResources
	}
	if c.ReporterResources == (ResourceRequirements{}) {
		c.ReporterResources = defaultReporterResources
	}
}

// Load parses YAML installation configuration, applies defaults, and validates.
//
// Unknown fields are rejected. A typo in a ConfigMap key would otherwise leave
// the mistyped setting at its default, and the settings here are exactly the
// ones where a silent default is dangerous.
func Load(data []byte) (*Config, error) {
	var c Config
	if err := yaml.UnmarshalStrict(data, &c); err != nil {
		return nil, sanitize.Errorf("parsing installation configuration: %v", err)
	}
	c.ApplyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate checks every field and aggregates the failures.
//
// Errors name the field but never echo its value: an endpoint can carry embedded
// credentials, and a validation error is logged and surfaced in status.
func (c *Config) Validate() error {
	var errs []string

	req := func(field, value string) {
		if strings.TrimSpace(value) == "" {
			errs = append(errs, field+" is required")
		}
	}

	req("clusterID", c.ClusterID)
	if len(c.ClusterID) > 63 {
		errs = append(errs, "clusterID must be at most 63 characters")
	}

	if !namespaceRE.MatchString(c.SystemNamespace) || len(c.SystemNamespace) > 63 {
		errs = append(errs, "systemNamespace must be a valid RFC 1123 label")
	}

	req("loki.endpoint", c.Loki.Endpoint)

	req("hubble.endpoint", c.Hubble.Endpoint)
	req("hubble.caFile", c.Hubble.CAFile)
	req("hubble.certFile", c.Hubble.CertFile)
	req("hubble.keyFile", c.Hubble.KeyFile)
	req("hubble.serverName", c.Hubble.ServerName)

	// The sink has no self-signed fallback. Serving it without a certificate,
	// or without a CA to check clients against, would either not start or
	// accept anyone, so these are required rather than defaulted.
	req("auditSink.certFile", c.AuditSink.CertFile)
	req("auditSink.keyFile", c.AuditSink.KeyFile)
	req("auditSink.caFile", c.AuditSink.CAFile)
	req("auditSink.listenAddr", c.AuditSink.ListenAddr)

	errs = append(errs, validateBucket("artifacts", c.Artifacts)...)
	errs = append(errs, validateBucket("auditLedger", c.AuditLedger)...)

	// ADR-0003: the ledger must not be writable by the artifact credential, and
	// must not share the bucket whose retention policy differs.
	if c.Artifacts.Bucket != "" && c.Artifacts.Bucket == c.AuditLedger.Bucket {
		errs = append(errs, "auditLedger.bucket must differ from artifacts.bucket")
	}
	if c.Artifacts.CredentialsPath != "" && c.Artifacts.CredentialsPath == c.AuditLedger.CredentialsPath {
		errs = append(errs, "auditLedger.credentialsPath must differ from artifacts.credentialsPath")
	}

	switch {
	case c.AuditRetention <= 0:
		errs = append(errs, "auditRetention must be positive")
	case c.AuditRetention.Duration() < MinAuditRetention:
		errs = append(errs, "auditRetention must be at least 90d")
	case c.AuditRetention.Duration() > MaxAuditRetention:
		errs = append(errs, "auditRetention must be at most 730d")
	}

	if c.CaptureRetentionCeiling <= 0 {
		errs = append(errs, "captureRetentionCeiling must be positive")
	}
	// Audit records describe how a capture was handled. If they expired first,
	// the evidence would outlive its own provenance.
	if c.AuditRetention > 0 && c.CaptureRetentionCeiling > 0 && c.AuditRetention <= c.CaptureRetentionCeiling {
		errs = append(errs, "auditRetention must exceed captureRetentionCeiling")
	}

	if len(c.AuditClientIdentities) == 0 {
		errs = append(errs, "auditClientIdentities must list at least one mTLS client identity")
	}

	errs = append(errs, validateResources("sensorAgentResources", c.SensorAgentResources)...)

	req("capture.eventWorkerServiceAccount", c.Capture.EventWorkerServiceAccount)
	req("capture.credentialsSecret", c.Capture.CredentialsSecret)
	if c.Capture.StartupBudget <= 0 {
		errs = append(errs, "capture.startupBudget must be positive")
	}
	if c.Capture.UploadBudget <= 0 {
		errs = append(errs, "capture.uploadBudget must be positive")
	}
	// Every one of these is required for the same reason the sink's are: there
	// is no safe fallback for a missing certificate on a path that serves
	// packet data, and no way to record a download without the client half.
	req("gateway.listenAddr", c.Gateway.ListenAddr)
	req("gateway.tokenAudience", c.Gateway.TokenAudience)
	req("gateway.certFile", c.Gateway.CertFile)
	req("gateway.keyFile", c.Gateway.KeyFile)
	req("gateway.auditClient.endpoint", c.Gateway.AuditClient.Endpoint)
	req("gateway.auditClient.serverName", c.Gateway.AuditClient.ServerName)
	req("gateway.auditClient.caFile", c.Gateway.AuditClient.CAFile)
	req("gateway.auditClient.certFile", c.Gateway.AuditClient.CertFile)
	req("gateway.auditClient.keyFile", c.Gateway.AuditClient.KeyFile)
	// Negative would be nonsense; zero is "use the default" and is allowed.
	if c.Gateway.DownloadsPerMinute < 0 {
		errs = append(errs, "gateway.downloadsPerMinute must not be negative")
	}
	if c.Gateway.DownloadBurst < 0 {
		errs = append(errs, "gateway.downloadBurst must not be negative")
	}
	if c.Gateway.AuthAttemptsPerMinute < 0 {
		errs = append(errs, "gateway.authAttemptsPerMinute must not be negative")
	}
	if c.Gateway.AuthAttemptBurst < 0 {
		errs = append(errs, "gateway.authAttemptBurst must not be negative")
	}

	errs = append(errs, validateResources("capture.runnerResources", c.Capture.RunnerResources)...)
	errs = append(errs, validateResources("capture.reporterResources", c.Capture.ReporterResources)...)

	req("content.suricataFeedURL", c.Content.SuricataFeedURL)
	req("content.zeekScriptRepo", c.Content.ZeekScriptRepo)
	if c.Content.RefreshInterval <= 0 {
		errs = append(errs, "content.refreshInterval must be positive")
	}

	for field, ref := range map[string]string{
		"images.suricata":        c.Images.Suricata,
		"images.zeek":            c.Images.Zeek,
		"images.sensorAgent":     c.Images.SensorAgent,
		"images.captureRunner":   c.Images.CaptureRunner,
		"images.captureReporter": c.Images.CaptureReporter,
		"images.contentInit":     c.Images.ContentInit,
	} {
		if !digestRE.MatchString(ref) {
			errs = append(errs, field+" must be digest-pinned (repository@sha256:...)")
		}
	}

	if len(errs) == 0 {
		return nil
	}
	// Field names only. Values are never interpolated, so this cannot leak.
	return fmt.Errorf("invalid installation configuration: %s", strings.Join(sorted(errs), "; "))
}

func validateBucket(prefix string, b BucketConfig) []string {
	var errs []string
	if strings.TrimSpace(b.Endpoint) == "" {
		errs = append(errs, prefix+".endpoint is required")
	}
	if strings.TrimSpace(b.Bucket) == "" {
		errs = append(errs, prefix+".bucket is required")
	}
	if strings.TrimSpace(b.CredentialsPath) == "" {
		errs = append(errs, prefix+".credentialsPath is required")
	}
	return errs
}

func validateResources(prefix string, r ResourceRequirements) []string {
	var errs []string
	for field, value := range map[string]string{
		prefix + ".requestsCPU":    r.RequestsCPU,
		prefix + ".requestsMemory": r.RequestsMemory,
		prefix + ".limitsCPU":      r.LimitsCPU,
		prefix + ".limitsMemory":   r.LimitsMemory,
	} {
		if strings.TrimSpace(value) == "" {
			errs = append(errs, field+" is required")
			continue
		}
		if _, err := resource.ParseQuantity(value); err != nil {
			errs = append(errs, field+" is not a valid Kubernetes quantity")
		}
	}
	return errs
}

// sorted gives the aggregate error a stable order so tests and operators see the
// same message for the same configuration.
func sorted(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
