package config

import (
	"os"
	"path/filepath"
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
