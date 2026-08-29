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

package config

import (
	"strings"
	"testing"
	"time"
)

// valid returns a configuration that passes validation, so each test can mutate
// exactly one field and assert on that field alone.
func valid() *Config {
	return &Config{
		ClusterID:       "homelab",
		SystemNamespace: "trawl-system",
		Loki: LokiConfig{
			Endpoint: "http://loki.monitoring.svc:3100",
		},
		Hubble: HubbleConfig{
			Endpoint:   "hubble-relay.kube-system.svc:80",
			CAFile:     "/etc/hubble/ca.crt",
			CertFile:   "/etc/hubble/tls.crt",
			KeyFile:    "/etc/hubble/tls.key",
			ServerName: "hubble-relay",
		},
		Artifacts: BucketConfig{
			Endpoint:        "minio.storage.svc:9000",
			Bucket:          "trawl-artifacts",
			CredentialsPath: "/etc/trawl/artifacts",
			UseTLS:          true,
		},
		AuditLedger: BucketConfig{
			Endpoint:        "minio.storage.svc:9000",
			Bucket:          "trawl-audit",
			CredentialsPath: "/etc/trawl/audit",
			UseTLS:          true,
		},
		AuditRetention: 365 * 24 * time.Hour,
		AuditClientIdentities: []string{
			"trawl-controller-manager", "trawl-event-worker", "trawl-artifact-gateway",
		},
		CaptureRetentionCeiling: 30 * 24 * time.Hour,
		SensorAgentResources: ResourceRequirements{
			RequestsCPU:    "50m",
			RequestsMemory: "64Mi",
			LimitsCPU:      "200m",
			LimitsMemory:   "256Mi",
		},
		Content: ContentConfig{
			SuricataFeedURL: "https://rules.emergingthreats.net/open/suricata-8.0/emerging.rules.tar.gz",
			ZeekScriptRepo:  "https://github.com/zeek/packages",
			RefreshInterval: 24 * time.Hour,
		},
		Images: ImageConfig{
			Suricata:      "ghcr.io/example/suricata@sha256:" + strings.Repeat("a", 64),
			Zeek:          "ghcr.io/example/zeek@sha256:" + strings.Repeat("b", 64),
			SensorAgent:   "ghcr.io/example/sensor-agent@sha256:" + strings.Repeat("c", 64),
			CaptureRunner: "ghcr.io/example/capture-runner@sha256:" + strings.Repeat("d", 64),
			ContentInit:   "ghcr.io/example/content-init@sha256:" + strings.Repeat("e", 64),
		},
	}
}

func TestValidAcceptsReferenceConfiguration(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatalf("reference configuration rejected: %v", err)
	}
}

func TestSystemNamespaceIsRequiredAndBounded(t *testing.T) {
	// FR-001: Trawl resources are accepted only in the configured system
	// namespace. An empty or invalid value would silently widen that boundary.
	cases := map[string]string{
		"empty":        "",
		"uppercase":    "Trawl-System",
		"leading dash": "-trawl",
		"underscore":   "trawl_system",
		"too long":     strings.Repeat("n", 64),
		"trailing dot": "trawl.",
	}
	for name, ns := range cases {
		t.Run(name, func(t *testing.T) {
			c := valid()
			c.SystemNamespace = ns
			if err := c.Validate(); err == nil {
				t.Errorf("Validate accepted invalid system namespace %q", ns)
			}
		})
	}
}

func TestDefaultsFillSystemNamespaceAndRetention(t *testing.T) {
	c := &Config{ClusterID: "homelab"}
	c.ApplyDefaults()

	if c.SystemNamespace != DefaultSystemNamespace {
		t.Errorf("SystemNamespace = %q, want %q", c.SystemNamespace, DefaultSystemNamespace)
	}
	if c.AuditRetention != DefaultAuditRetention {
		t.Errorf("AuditRetention = %v, want %v", c.AuditRetention, DefaultAuditRetention)
	}
	if c.CaptureRetentionCeiling != DefaultCaptureRetentionCeiling {
		t.Errorf("CaptureRetentionCeiling = %v, want %v", c.CaptureRetentionCeiling, DefaultCaptureRetentionCeiling)
	}
	if c.Content.RefreshInterval != DefaultContentRefreshInterval {
		t.Errorf("Content.RefreshInterval = %v, want %v", c.Content.RefreshInterval, DefaultContentRefreshInterval)
	}
}

func TestArtifactAndAuditBucketsMustBeDistinct(t *testing.T) {
	// ADR-0003: a shared bucket means a compromised artifact writer can rewrite
	// the audit trail. Distinct buckets AND distinct credentials are required.
	t.Run("same bucket rejected", func(t *testing.T) {
		c := valid()
		c.AuditLedger.Bucket = c.Artifacts.Bucket
		if err := c.Validate(); err == nil {
			t.Error("Validate accepted identical artifact and audit buckets")
		}
	})
	t.Run("shared credentials rejected", func(t *testing.T) {
		c := valid()
		c.AuditLedger.CredentialsPath = c.Artifacts.CredentialsPath
		if err := c.Validate(); err == nil {
			t.Error("Validate accepted shared artifact and audit credentials")
		}
	})
}

func TestAuditRetentionBounds(t *testing.T) {
	// data-model.md: installation-controlled within 90-730 days.
	day := 24 * time.Hour
	cases := []struct {
		name    string
		d       time.Duration
		wantErr bool
	}{
		{"below floor", 89 * day, true},
		{"at floor", 90 * day, false},
		{"default", 365 * day, false},
		{"at ceiling", 730 * day, false},
		{"above ceiling", 731 * day, true},
		{"zero", 0, true},
		{"negative", -day, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := valid()
			c.AuditRetention = tc.d
			err := c.Validate()
			if tc.wantErr != (err != nil) {
				t.Errorf("AuditRetention %v: err = %v, wantErr %v", tc.d, err, tc.wantErr)
			}
		})
	}
}

func TestAuditRetentionMustExceedCaptureRetention(t *testing.T) {
	// plan.md: audit objects outlive the captures they describe, or the record
	// of a capture's handling disappears before the capture does.
	c := valid()
	c.AuditRetention = 90 * 24 * time.Hour
	c.CaptureRetentionCeiling = 120 * 24 * time.Hour
	if err := c.Validate(); err == nil {
		t.Error("Validate accepted audit retention shorter than capture retention")
	}
}

func TestCaptureRetentionCeilingIsBounded(t *testing.T) {
	c := valid()
	c.CaptureRetentionCeiling = 0
	if err := c.Validate(); err == nil {
		t.Error("Validate accepted a zero capture retention ceiling")
	}
}

func TestImagesMustBeDigestPinned(t *testing.T) {
	// Constitution: no floating tags in release manifests. A tag can be
	// repointed after review; a digest cannot.
	for _, ref := range []string{
		"ghcr.io/example/suricata:latest",
		"ghcr.io/example/suricata:8.0.6",
		"suricata",
		"",
	} {
		t.Run(ref, func(t *testing.T) {
			c := valid()
			c.Images.Suricata = ref
			if err := c.Validate(); err == nil {
				t.Errorf("Validate accepted non-digest image reference %q", ref)
			}
		})
	}
}

func TestAuditClientIdentitiesRequired(t *testing.T) {
	// The mTLS sink authorizes by client identity; an empty list would mean
	// either no client can commit, or the check is skipped.
	c := valid()
	c.AuditClientIdentities = nil
	if err := c.Validate(); err == nil {
		t.Error("Validate accepted an empty audit client identity list")
	}
}

func TestSensorAgentResourcesRequired(t *testing.T) {
	// Sensor-agent resources come from installation config, never the
	// NetworkTap CRD, so an operator cannot under-provision it per tap.
	c := valid()
	c.SensorAgentResources = ResourceRequirements{}
	if err := c.Validate(); err == nil {
		t.Error("Validate accepted empty sensor-agent resources")
	}
}

func TestSensorAgentResourceQuantitiesMustParse(t *testing.T) {
	c := valid()
	c.SensorAgentResources.LimitsMemory = "256Megabytes"
	if err := c.Validate(); err == nil {
		t.Error("Validate accepted an unparseable resource quantity")
	}
}

func TestValidationErrorsAreSecretSafe(t *testing.T) {
	// A validation error is logged and surfaced in status. It must name the
	// field, never echo the value, which may be a credential path or endpoint
	// carrying embedded auth.
	c := valid()
	c.Artifacts.Endpoint = "https://user:hunter2trombone@minio.example:9000?token=s3cr3t"
	c.Artifacts.Bucket = ""

	err := c.Validate()
	if err == nil {
		t.Fatal("expected validation to fail")
	}
	msg := err.Error()
	for _, leak := range []string{"hunter2trombone", "s3cr3t"} {
		if strings.Contains(msg, leak) {
			t.Errorf("validation error leaked %q: %s", leak, msg)
		}
	}
	if !strings.Contains(msg, "artifacts.bucket") {
		t.Errorf("validation error does not name the offending field: %s", msg)
	}
}

func TestValidateReportsAllFieldErrors(t *testing.T) {
	// Returning one error at a time makes fixing a broken install a guessing
	// game across restarts.
	c := valid()
	c.ClusterID = ""
	c.Artifacts.Bucket = ""
	c.Loki.Endpoint = ""

	err := c.Validate()
	if err == nil {
		t.Fatal("expected validation to fail")
	}
	for _, field := range []string{"clusterID", "artifacts.bucket", "loki.endpoint"} {
		if !strings.Contains(err.Error(), field) {
			t.Errorf("aggregate error missing %q: %s", field, err.Error())
		}
	}
}

func TestParseDurationAcceptsDayUnits(t *testing.T) {
	// Retention is naturally expressed in days; Go's ParseDuration stops at
	// hours, so operators would otherwise write 8760h.
	cases := map[string]time.Duration{
		"30d":  30 * 24 * time.Hour,
		"365d": 365 * 24 * time.Hour,
		"12h":  12 * time.Hour,
		"90m":  90 * time.Minute,
	}
	for in, want := range cases {
		got, err := ParseDuration(in)
		if err != nil {
			t.Errorf("ParseDuration(%q) error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseDuration(%q) = %v, want %v", in, got, want)
		}
	}
	for _, bad := range []string{"", "30", "d", "-5d", "abc", "30x"} {
		if _, err := ParseDuration(bad); err == nil {
			t.Errorf("ParseDuration(%q) accepted invalid input", bad)
		}
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	// A typo in an installation ConfigMap must fail loudly rather than leave a
	// security-relevant setting at its default.
	yaml := []byte("clusterID: homelab\nsystemNamesapce: trawl-system\n")
	if _, err := Load(yaml); err == nil {
		t.Error("Load accepted an unknown field")
	}
}

func TestLoadAppliesDefaultsThenValidates(t *testing.T) {
	yaml := []byte(`
clusterID: homelab
loki:
  endpoint: http://loki:3100
hubble:
  endpoint: hubble-relay:80
  caFile: /etc/hubble/ca.crt
  certFile: /etc/hubble/tls.crt
  keyFile: /etc/hubble/tls.key
  serverName: hubble-relay
artifacts:
  endpoint: minio:9000
  bucket: trawl-artifacts
  credentialsPath: /etc/trawl/artifacts
auditLedger:
  endpoint: minio:9000
  bucket: trawl-audit
  credentialsPath: /etc/trawl/audit
auditClientIdentities: [trawl-controller-manager]
sensorAgentResources:
  requestsCPU: 50m
  requestsMemory: 64Mi
  limitsCPU: 200m
  limitsMemory: 256Mi
content:
  suricataFeedURL: https://rules.example/emerging.rules.tar.gz
  zeekScriptRepo: https://github.com/zeek/packages
images:
  suricata: ghcr.io/e/suricata@sha256:` + strings.Repeat("a", 64) + `
  zeek: ghcr.io/e/zeek@sha256:` + strings.Repeat("b", 64) + `
  sensorAgent: ghcr.io/e/sensor@sha256:` + strings.Repeat("c", 64) + `
  captureRunner: ghcr.io/e/runner@sha256:` + strings.Repeat("d", 64) + `
  contentInit: ghcr.io/e/content@sha256:` + strings.Repeat("e", 64) + `
`)
	c, err := Load(yaml)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if c.SystemNamespace != DefaultSystemNamespace {
		t.Errorf("default system namespace not applied: %q", c.SystemNamespace)
	}
	if c.AuditRetention != DefaultAuditRetention {
		t.Errorf("default audit retention not applied: %v", c.AuditRetention)
	}
}
