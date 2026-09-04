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

	"sigs.k8s.io/yaml"
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
		AuditRetention: Duration(365 * 24 * time.Hour),
		AuditClientIdentities: []string{
			"trawl-controller-manager", "trawl-event-worker", "trawl-artifact-gateway",
		},
		AuditSink: AuditSinkConfig{
			ListenAddr: DefaultAuditSinkListenAddr,
			CertFile:   "/var/run/secrets/trawl/audit-sink/tls.crt",
			KeyFile:    "/var/run/secrets/trawl/audit-sink/tls.key",
			CAFile:     "/var/run/secrets/trawl/audit-sink/ca.crt",
		},
		CaptureRetentionCeiling: Duration(30 * 24 * time.Hour),
		SensorAgentResources: ResourceRequirements{
			RequestsCPU:    "50m",
			RequestsMemory: "64Mi",
			LimitsCPU:      "200m",
			LimitsMemory:   "256Mi",
		},
		Content: ContentConfig{
			SuricataFeedURL: "https://rules.emergingthreats.net/open/suricata-8.0/emerging.rules.tar.gz",
			ZeekScriptRepo:  "https://github.com/zeek/packages",
			RefreshInterval: Duration(24 * time.Hour),
		},
		Images: ImageConfig{
			Suricata:        "ghcr.io/example/suricata@sha256:" + strings.Repeat("a", 64),
			Zeek:            "ghcr.io/example/zeek@sha256:" + strings.Repeat("b", 64),
			SensorAgent:     "ghcr.io/example/sensor-agent@sha256:" + strings.Repeat("c", 64),
			CaptureRunner:   "ghcr.io/example/capture-runner@sha256:" + strings.Repeat("d", 64),
			CaptureReporter: "ghcr.io/example/capture-reporter@sha256:" + strings.Repeat("f", 64),
			ContentInit:     "ghcr.io/example/content-init@sha256:" + strings.Repeat("e", 64),
		},
		Capture: CaptureConfig{
			EventWorkerServiceAccount: "trawl-event-worker",
			RetentionAdminGroups:      []string{"trawl:retention-admins"},
			CredentialsSecret:         "trawl-artifact-credentials",
			StartupBudget:             Duration(5 * time.Minute),
			UploadBudget:              Duration(15 * time.Minute),
			RunnerResources: ResourceRequirements{
				RequestsCPU: "100m", RequestsMemory: "128Mi", LimitsCPU: "1", LimitsMemory: "1Gi",
			},
			ReporterResources: ResourceRequirements{
				RequestsCPU: "10m", RequestsMemory: "32Mi", LimitsCPU: "100m", LimitsMemory: "128Mi",
			},
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
	if c.AuditRetention.Duration() != DefaultAuditRetention {
		t.Errorf("AuditRetention = %v, want %v", c.AuditRetention, DefaultAuditRetention)
	}
	if c.CaptureRetentionCeiling.Duration() != DefaultCaptureRetentionCeiling {
		t.Errorf("CaptureRetentionCeiling = %v, want %v", c.CaptureRetentionCeiling, DefaultCaptureRetentionCeiling)
	}
	if c.Content.RefreshInterval.Duration() != DefaultContentRefreshInterval {
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
			c.AuditRetention = Duration(tc.d)
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
	c.AuditRetention = Duration(90 * 24 * time.Hour)
	c.CaptureRetentionCeiling = Duration(120 * 24 * time.Hour)
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

func TestAuditSinkTLSMaterialRequired(t *testing.T) {
	// There is no self-signed fallback for the sink. Without a serving
	// certificate it cannot start, and without a CA it would accept any
	// client, so each of these is required rather than defaulted.
	for name, clear := range map[string]func(*Config){
		"certFile": func(c *Config) { c.AuditSink.CertFile = "" },
		"keyFile":  func(c *Config) { c.AuditSink.KeyFile = "" },
		"caFile":   func(c *Config) { c.AuditSink.CAFile = "" },
	} {
		t.Run(name, func(t *testing.T) {
			c := valid()
			clear(c)
			if err := c.Validate(); err == nil {
				t.Errorf("Validate accepted an audit sink with no %s", name)
			}
		})
	}
}

func TestAuditSinkListenAddrDefaults(t *testing.T) {
	c := valid()
	c.AuditSink.ListenAddr = ""
	c.ApplyDefaults()
	if c.AuditSink.ListenAddr != DefaultAuditSinkListenAddr {
		t.Errorf("listenAddr = %q, want %q", c.AuditSink.ListenAddr, DefaultAuditSinkListenAddr)
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
	doc := []byte("clusterID: homelab\nsystemNamesapce: trawl-system\n")
	if _, err := Load(doc); err == nil {
		t.Error("Load accepted an unknown field")
	}
}

func TestLoadAppliesDefaultsThenValidates(t *testing.T) {
	doc := []byte(`
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
auditSink:
  certFile: /etc/trawl/audit-sink/tls.crt
  keyFile: /etc/trawl/audit-sink/tls.key
  caFile: /etc/trawl/audit-sink/ca.crt
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
  captureReporter: ghcr.io/e/reporter@sha256:` + strings.Repeat("f", 64) + `
  contentInit: ghcr.io/e/content@sha256:` + strings.Repeat("e", 64) + `
`)
	c, err := Load(doc)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if c.SystemNamespace != DefaultSystemNamespace {
		t.Errorf("default system namespace not applied: %q", c.SystemNamespace)
	}
	if c.AuditRetention.Duration() != DefaultAuditRetention {
		t.Errorf("default audit retention not applied: %v", c.AuditRetention)
	}
}

func TestDurationsAreWrittenAsStrings(t *testing.T) {
	// The documented spelling. Before Duration existed, Load rejected this with
	// "cannot unmarshal string into Go struct field ... of type time.Duration",
	// and the only accepted form was a raw nanosecond count - which no operator
	// writes correctly and which the comments in this file never suggested.
	// ParseDuration had handled the `d` suffix all along; nothing called it.
	c := valid()
	raw, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	// Marshalling produces the string form; confirm that is what is on the wire
	// before asserting Load can read it back.
	if !strings.Contains(string(raw), "auditRetention: 8760h0m0s") {
		t.Fatalf("durations did not marshal as strings:\n%s", raw)
	}

	withDays := strings.ReplaceAll(string(raw), "auditRetention: 8760h0m0s", "auditRetention: 90d")
	withDays = strings.ReplaceAll(withDays, "captureRetentionCeiling: 720h0m0s", "captureRetentionCeiling: 7d")

	loaded, err := Load([]byte(withDays))
	if err != nil {
		t.Fatalf("Load rejected string durations: %v", err)
	}
	if got := loaded.AuditRetention.Duration(); got != 90*24*time.Hour {
		t.Errorf("auditRetention = %v, want 90d", got)
	}
	if got := loaded.CaptureRetentionCeiling.Duration(); got != 7*24*time.Hour {
		t.Errorf("captureRetentionCeiling = %v, want 7d", got)
	}
}

func TestDurationRoundTripsAsAString(t *testing.T) {
	// A config read and written back must stay readable, rather than turning
	// into nanoseconds the next person has to decode.
	d := Duration(90 * 24 * time.Hour)
	out, err := d.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `"2160h0m0s"` {
		t.Errorf("marshalled to %s, want a duration string", out)
	}
}

func TestAnExplicitNullLeavesADurationForTheDefaults(t *testing.T) {
	// `auditRetention: null` is a normal way to spell "leave it defaulted" in
	// YAML. Unmarshalling it as a string succeeded as a no-op and left "",
	// which ParseDuration rejects - so the spelling that asks for the default
	// was the one spelling that failed to load.
	c := valid()
	raw, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	withNull := strings.ReplaceAll(string(raw), "auditRetention: 8760h0m0s", "auditRetention: null")

	loaded, err := Load([]byte(withNull))
	if err != nil {
		t.Fatalf("Load rejected a null duration: %v", err)
	}
	if got := loaded.AuditRetention.Duration(); got != DefaultAuditRetention {
		t.Errorf("auditRetention = %v after null, want the default %v", got, DefaultAuditRetention)
	}
}

func TestCaptureDefaultsFillBudgetsIdentityAndResources(t *testing.T) {
	// The capture block is new in US3 and every installation predates it, so
	// each field needs a default that is safe rather than merely present.
	var c Config
	c.ApplyDefaults()

	if c.Capture.StartupBudget.Duration() != DefaultCaptureStartupBudget {
		t.Errorf("startupBudget default = %v, want %v", c.Capture.StartupBudget, DefaultCaptureStartupBudget)
	}
	if c.Capture.UploadBudget.Duration() != DefaultCaptureUploadBudget {
		t.Errorf("uploadBudget default = %v, want %v", c.Capture.UploadBudget, DefaultCaptureUploadBudget)
	}
	if c.Capture.EventWorkerServiceAccount != DefaultEventWorkerServiceAccount {
		t.Errorf("eventWorkerServiceAccount default = %q", c.Capture.EventWorkerServiceAccount)
	}
	if c.Capture.CredentialsSecret != DefaultCaptureCredentialsSecret {
		t.Errorf("credentialsSecret default = %q", c.Capture.CredentialsSecret)
	}
	for name, r := range map[string]ResourceRequirements{
		"runnerResources":   c.Capture.RunnerResources,
		"reporterResources": c.Capture.ReporterResources,
	} {
		if errs := validateResources(name, r); len(errs) != 0 {
			t.Errorf("%s default does not validate: %v", name, errs)
		}
	}
}

func TestCaptureBudgetsMustBePositive(t *testing.T) {
	for _, field := range []string{"startupBudget", "uploadBudget"} {
		c := valid()
		switch field {
		case "startupBudget":
			c.Capture.StartupBudget = Duration(-time.Second)
		case "uploadBudget":
			c.Capture.UploadBudget = 0
		}
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), "capture."+field) {
			t.Errorf("%s: expected a capture.%s error, got %v", field, field, err)
		}
	}
}

func TestCaptureIdentitiesAndSecretAreRequired(t *testing.T) {
	c := valid()
	c.Capture.EventWorkerServiceAccount = " "
	c.Capture.CredentialsSecret = ""
	err := c.Validate()
	for _, want := range []string{
		"capture.eventWorkerServiceAccount is required",
		"capture.credentialsSecret is required",
	} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
}

func TestCaptureRunnerAndReporterResourcesMustParse(t *testing.T) {
	c := valid()
	c.Capture.RunnerResources.LimitsMemory = "lots"
	c.Capture.ReporterResources.RequestsCPU = ""
	err := c.Validate()
	for _, want := range []string{
		"capture.runnerResources.limitsMemory is not a valid Kubernetes quantity",
		"capture.reporterResources.requestsCPU is required",
	} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
}

func TestCaptureReporterImageMustBeDigestPinned(t *testing.T) {
	c := valid()
	c.Images.CaptureReporter = "ghcr.io/example/capture-reporter:latest"
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "images.captureReporter must be digest-pinned") {
		t.Errorf("tag reference accepted: %v", err)
	}
}
