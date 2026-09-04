package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// The worked example in config/dev has to satisfy the same validation a real
// installation does. A reference configuration that does not load is worse than
// none: it is the first thing an operator copies.
func TestDevConfigMapValidates(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "config", "dev", "trawl-config.yaml"))
	if err != nil {
		t.Skipf("dev configuration absent: %v", err)
	}
	var cm struct {
		Data map[string]string `json:"data"`
	}
	if err := yaml.Unmarshal(raw, &cm); err != nil {
		t.Fatalf("the dev ConfigMap is not valid YAML: %v", err)
	}
	body, ok := cm.Data["config.yaml"]
	if !ok {
		t.Fatal("the dev ConfigMap has no config.yaml key, which is what the pods mount")
	}
	if _, err := Load([]byte(body)); err != nil {
		t.Fatalf("the dev configuration does not satisfy config.Validate: %v", err)
	}
}

// Defect: manager.yaml declared no credential mounts at all, so the manager
// read its configuration, found credentialsPath pointing at a directory that
// did not exist in the container, and could not construct the audit store.
// Nothing caught it, because the configuration was valid and the deployment was
// valid - they were only wrong about each other. This asserts the pair agrees:
// every credentialsPath the reference configuration declares is backed by a
// read-only Secret mount at exactly that path.
func TestDevConfigCredentialPathsAreMounted(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "config", "dev", "trawl-config.yaml"))
	if err != nil {
		t.Skipf("dev configuration absent: %v", err)
	}
	var cm struct {
		Data map[string]string `json:"data"`
	}
	if err := yaml.Unmarshal(raw, &cm); err != nil {
		t.Fatalf("the dev ConfigMap is not valid YAML: %v", err)
	}
	cfg, err := Load([]byte(cm.Data["config.yaml"]))
	if err != nil {
		t.Fatalf("the dev configuration does not load: %v", err)
	}

	mounts, volumes := managerCredentialSurface(t)

	for _, want := range []struct {
		field string
		path  string
	}{
		{"artifacts.credentialsPath", cfg.Artifacts.CredentialsPath},
		{"auditLedger.credentialsPath", cfg.AuditLedger.CredentialsPath},
	} {
		volume, ok := mounts[want.path]
		if !ok {
			t.Errorf("%s is %s, but the manager mounts nothing there; storage.NewS3Store would find no accessKeyID file",
				want.field, want.path)
			continue
		}
		// A ConfigMap here would mean the credential is in a manifest rather
		// than a Secret, which is a different defect wearing the same shape.
		if secret, ok := volumes[volume]; !ok || secret == "" {
			t.Errorf("%s is mounted from volume %q, which is not backed by a Secret", want.field, volume)
		}
	}

	// The audit sink names files rather than directories, so what has to be
	// mounted is the directory each one sits in. Without them the manager
	// cannot serve the sink, and every component that has no ledger
	// credentials of its own -- which ADR-0003 makes all of them -- loses the
	// only way it has to record what it did.
	for _, want := range []struct {
		field string
		path  string
	}{
		{"auditSink.certFile", cfg.AuditSink.CertFile},
		{"auditSink.keyFile", cfg.AuditSink.KeyFile},
		{"auditSink.caFile", cfg.AuditSink.CAFile},
	} {
		dir := filepath.Dir(want.path)
		volume, ok := mounts[dir]
		if !ok {
			t.Errorf("%s is %s, but the manager mounts nothing at %s; the listener would not start",
				want.field, want.path, dir)
			continue
		}
		if secret, ok := volumes[volume]; !ok || secret == "" {
			t.Errorf("%s is mounted from volume %q, which is not backed by a Secret", want.field, volume)
		}
	}
}

// managerCredentialSurface returns the manager container's read-only mount
// paths mapped to their volume names, and the volume names that are Secrets
// mapped to the secret they name.
func managerCredentialSurface(t *testing.T) (map[string]string, map[string]string) {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("..", "..", "config", "manager", "manager.yaml"))
	if err != nil {
		t.Skipf("manager manifest absent: %v", err)
	}

	type manifest struct {
		Kind string `json:"kind"`
		Spec struct {
			Template struct {
				Spec struct {
					Containers []struct {
						Name         string `json:"name"`
						VolumeMounts []struct {
							Name      string `json:"name"`
							MountPath string `json:"mountPath"`
							ReadOnly  bool   `json:"readOnly"`
						} `json:"volumeMounts"`
					} `json:"containers"`
					Volumes []struct {
						Name   string `json:"name"`
						Secret *struct {
							SecretName string `json:"secretName"`
						} `json:"secret"`
					} `json:"volumes"`
				} `json:"spec"`
			} `json:"template"`
		} `json:"spec"`
	}

	mounts := map[string]string{}
	volumes := map[string]string{}
	found := false

	for doc := range strings.SplitSeq(string(raw), "\n---") {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		var m manifest
		if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
			t.Fatalf("the manager manifest is not valid YAML: %v", err)
		}
		if m.Kind != "Deployment" {
			continue
		}
		found = true
		for _, c := range m.Spec.Template.Spec.Containers {
			for _, vm := range c.VolumeMounts {
				// A writable credential mount would let the process that reads
				// the key also replace it.
				if !vm.ReadOnly {
					continue
				}
				mounts[vm.MountPath] = vm.Name
			}
		}
		for _, v := range m.Spec.Template.Spec.Volumes {
			if v.Secret != nil {
				volumes[v.Name] = v.Secret.SecretName
			}
		}
	}
	if !found {
		t.Fatal("the manager manifest contains no Deployment")
	}
	return mounts, volumes
}
