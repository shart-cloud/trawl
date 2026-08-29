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

	// DefaultCaptureRetentionCeiling caps how long any capture may be kept.
	DefaultCaptureRetentionCeiling = 30 * 24 * time.Hour

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
	AuditRetention time.Duration `json:"auditRetention,omitempty"`

	// AuditClientIdentities are the mTLS client identities permitted to commit
	// audit records to the sink.
	AuditClientIdentities []string `json:"auditClientIdentities"`

	// CaptureRetentionCeiling is the longest retention any capture may request.
	CaptureRetentionCeiling time.Duration `json:"captureRetentionCeiling,omitempty"`

	// SensorAgentResources are the requests and limits the operator renders for
	// the sensor sidecar in every analyzer pod. Deliberately not a NetworkTap
	// field: an under-provisioned sensor drops observations silently.
	SensorAgentResources ResourceRequirements `json:"sensorAgentResources"`

	Content ContentConfig `json:"content"`
	Images  ImageConfig   `json:"images"`
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
	SuricataFeedURL string        `json:"suricataFeedURL"`
	ZeekScriptRepo  string        `json:"zeekScriptRepo"`
	RefreshInterval time.Duration `json:"refreshInterval,omitempty"`
}

// ImageConfig holds digest-pinned references for every image Trawl renders.
type ImageConfig struct {
	Suricata      string `json:"suricata"`
	Zeek          string `json:"zeek"`
	SensorAgent   string `json:"sensorAgent"`
	CaptureRunner string `json:"captureRunner"`
	ContentInit   string `json:"contentInit"`
}

// RFC 1123 label, the Kubernetes namespace rule.
var namespaceRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// A digest-pinned reference: repository@sha256:<64 hex>.
var digestRE = regexp.MustCompile(`^[^@\s]+@sha256:[0-9a-f]{64}$`)

// durationRE additionally accepts a day suffix, which Go's ParseDuration does not.
var durationRE = regexp.MustCompile(`^(\d+)d$`)

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
		c.AuditRetention = DefaultAuditRetention
	}
	if c.CaptureRetentionCeiling == 0 {
		c.CaptureRetentionCeiling = DefaultCaptureRetentionCeiling
	}
	if c.Content.RefreshInterval == 0 {
		c.Content.RefreshInterval = DefaultContentRefreshInterval
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
	case c.AuditRetention < MinAuditRetention:
		errs = append(errs, "auditRetention must be at least 90d")
	case c.AuditRetention > MaxAuditRetention:
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

	req("content.suricataFeedURL", c.Content.SuricataFeedURL)
	req("content.zeekScriptRepo", c.Content.ZeekScriptRepo)
	if c.Content.RefreshInterval <= 0 {
		errs = append(errs, "content.refreshInterval must be positive")
	}

	for field, ref := range map[string]string{
		"images.suricata":      c.Images.Suricata,
		"images.zeek":          c.Images.Zeek,
		"images.sensorAgent":   c.Images.SensorAgent,
		"images.captureRunner": c.Images.CaptureRunner,
		"images.contentInit":   c.Images.ContentInit,
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
