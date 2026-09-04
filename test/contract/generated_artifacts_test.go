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

// Package contract holds tests that assert Trawl's checked-in artifacts agree
// with the contracts they claim to implement.
//
// Constitution gate 6: generated manifests, schemas, examples, dashboards, and
// documentation must agree with the implemented contract, and drift blocks
// merge. These failures are all silent ones — nothing breaks at install time
// when a CRD is stale or a dashboard queries a label that is no longer indexed;
// it breaks later, in a cluster, during an investigation.
package contract

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"trawl.cloud/trawl/internal/observation"
	"trawl.cloud/trawl/internal/telemetry"
)

// repoRoot resolves paths relative to the module root rather than the test's
// working directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Join(wd, "..", "..")
}

func TestTelemetryContractListsEveryRegisteredMetric(t *testing.T) {
	// The telemetry contract is the document dashboards and alerts are written
	// against. A metric that exists in code but not in the document is one
	// nobody knows to graph; one in the document but not in code is a dashboard
	// panel that renders empty forever.
	root := repoRoot(t)
	doc, err := os.ReadFile(filepath.Join(root, "specs", "001-cloud-native-nsm", "contracts", "telemetry.md"))
	if err != nil {
		t.Skipf("telemetry contract not present: %v", err)
	}

	m := telemetry.NewMetrics()
	reg := newRegistry(t, m)
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	for _, f := range families {
		name := f.GetName()
		if !strings.Contains(string(doc), name) {
			t.Errorf("metric %q is registered but absent from contracts/telemetry.md", name)
		}
	}
}

func TestAuditActionsAppearInTelemetryContract(t *testing.T) {
	root := repoRoot(t)
	doc, err := os.ReadFile(filepath.Join(root, "specs", "001-cloud-native-nsm", "contracts", "telemetry.md"))
	if err != nil {
		t.Skipf("telemetry contract not present: %v", err)
	}
	for _, action := range auditActions() {
		if !strings.Contains(string(doc), action) {
			t.Errorf("audit action %q is implemented but absent from contracts/telemetry.md", action)
		}
	}
}

func TestConditionTypesMatchTelemetryContract(t *testing.T) {
	root := repoRoot(t)
	doc, err := os.ReadFile(filepath.Join(root, "specs", "001-cloud-native-nsm", "contracts", "telemetry.md"))
	if err != nil {
		t.Skipf("telemetry contract not present: %v", err)
	}
	for _, condType := range conditionTypes() {
		if !strings.Contains(string(doc), condType) {
			t.Errorf("condition type %q is implemented but absent from contracts/telemetry.md", condType)
		}
	}
}

func TestManifestsUseNoFloatingImageTags(t *testing.T) {
	// Duplicated from hack/verify-manifests.sh on purpose. The shell check runs
	// in CI; this one runs in `go test`, so a developer sees the failure before
	// pushing.
	floating := regexp.MustCompile(`image:\s*\S+:(latest|main|master|edge|dev)\s*$`)

	forEachManifest(t, func(path string, content []byte) {
		for i, line := range strings.Split(string(content), "\n") {
			if floating.MatchString(line) {
				t.Errorf("%s:%d uses a floating image tag: %s", path, i+1, strings.TrimSpace(line))
			}
		}
	})
}

func TestManifestsDeclareNoWildcardRBAC(t *testing.T) {
	forEachManifest(t, func(path string, content []byte) {
		if !strings.Contains(path, "rbac") {
			return
		}
		var doc map[string]any
		for _, part := range splitYAML(string(content)) {
			if err := yaml.Unmarshal([]byte(part), &doc); err != nil {
				continue
			}
			kind, _ := doc["kind"].(string)
			if kind != "Role" && kind != "ClusterRole" {
				continue
			}
			rules, _ := doc["rules"].([]any)
			for _, r := range rules {
				rule, ok := r.(map[string]any)
				if !ok {
					continue
				}
				for _, field := range []string{"verbs", "resources", "apiGroups"} {
					values, _ := rule[field].([]any)
					for _, v := range values {
						if s, ok := v.(string); ok && s == "*" {
							t.Errorf("%s: %s grants %s: \"*\"", path, kind, field)
						}
					}
				}
			}
		}
	})
}

func TestManifestsRequestNoHostAccess(t *testing.T) {
	// Nothing shipped under config/ is a data-plane workload. Analyzer and
	// capture pods are rendered by the operator with an explicit, reviewed
	// exception; a host namespace in a checked-in manifest is a mistake.
	banned := []string{"hostPath", "hostNetwork: true", "hostPID: true", "hostIPC: true", "privileged: true"}

	forEachManifest(t, func(path string, content []byte) {
		for _, b := range banned {
			if strings.Contains(string(content), b) {
				t.Errorf("%s contains %q", path, b)
			}
		}
	})
}

func TestSystemNamespaceEnforcesRestrictedPodSecurity(t *testing.T) {
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "config", "namespace", "namespace.yaml"))
	if err != nil {
		t.Fatalf("reading namespace manifest: %v", err)
	}
	var ns struct {
		Metadata struct {
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
	}
	if err := yaml.Unmarshal(data, &ns); err != nil {
		t.Fatalf("parsing namespace manifest: %v", err)
	}
	// Enforcement is privileged because analyzer and capture pods need
	// hostNetwork and CAP_NET_RAW, and PSA has no per-workload exemption. The
	// compensating controls are asserted separately: audit and warn must stay
	// at restricted so any pod exceeding it is still reported, and
	// TestManifestsRequestNoHostAccess proves nothing shipped under config/
	// actually uses the latitude the namespace grants.
	if got := ns.Metadata.Labels["pod-security.kubernetes.io/enforce"]; got != "privileged" {
		t.Errorf("pod-security enforce = %q, want %q", got, "privileged")
	}
	for _, mode := range []string{"audit", "warn"} {
		key := "pod-security.kubernetes.io/" + mode
		if got := ns.Metadata.Labels[key]; got != "restricted" {
			t.Errorf("%s = %q, want restricted so over-privileged pods stay visible", key, got)
		}
	}
}

func TestDefaultDenyNetworkPolicyExists(t *testing.T) {
	// Without a default-deny, the allowlist policies grant nothing extra and
	// every pod in the namespace stays fully reachable.
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "config", "networkpolicy", "control-plane.yaml"))
	if err != nil {
		t.Fatalf("reading network policy: %v", err)
	}
	found := false
	for _, part := range splitYAML(string(data)) {
		var np struct {
			Kind string `json:"kind"`
			Spec struct {
				PodSelector map[string]any `json:"podSelector"`
				PolicyTypes []string       `json:"policyTypes"`
			} `json:"spec"`
		}
		if err := yaml.Unmarshal([]byte(part), &np); err != nil {
			continue
		}
		if np.Kind == "NetworkPolicy" && len(np.Spec.PodSelector) == 0 &&
			slices.Contains(np.Spec.PolicyTypes, "Ingress") &&
			slices.Contains(np.Spec.PolicyTypes, "Egress") {
			found = true
		}
	}
	if !found {
		t.Error("no default-deny NetworkPolicy (empty podSelector, Ingress+Egress) found")
	}
}

func TestADRsExistForIrreversibleDecisions(t *testing.T) {
	// plan.md commits to recording these before implementation. An ADR written
	// after the fact documents what was done, not what was decided.
	root := repoRoot(t)
	adrDir := filepath.Join(root, "docs", "src", "content", "docs", "adr")

	required := []string{
		"0001-normalized-observation-envelope.md",
		"0002-trigger-replay-and-deduplication.md",
		"0003-artifact-storage-and-gateway.md",
		"0004-capability-minimized-capture.md",
		"0005-analyzer-content-management.md",
	}
	for _, name := range required {
		path := filepath.Join(adrDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("required ADR %s is missing: %v", name, err)
			continue
		}
		// Starlight needs frontmatter; a missing title breaks the docs build.
		if !strings.HasPrefix(string(data), "---\ntitle:") {
			t.Errorf("ADR %s has no Starlight frontmatter title", name)
		}
		for _, section := range []string{"## Context", "## Decision", "## Consequences"} {
			if !strings.Contains(string(data), section) {
				t.Errorf("ADR %s is missing %q", name, section)
			}
		}
	}
}

// forEachManifest walks every YAML file under config/.
func forEachManifest(t *testing.T, fn func(path string, content []byte)) {
	t.Helper()
	root := filepath.Join(repoRoot(t), "config")

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		rel, _ := filepath.Rel(repoRoot(t), path)
		fn(rel, content)
		return nil
	})
	if err != nil {
		t.Fatalf("walking config/: %v", err)
	}
}

func splitYAML(s string) []string {
	return strings.Split(s, "\n---\n")
}

func TestEmbeddedObservationSchemaMatchesContract(t *testing.T) {
	// The sensor validates against a schema compiled into its binary, because a
	// pod has no access to the repository and a schema loaded from a ConfigMap
	// could drift from the code producing the records. That embedding is only
	// safe if it cannot silently diverge from the published contract.
	root := repoRoot(t)

	contractPath := filepath.Join(root, "specs", "001-cloud-native-nsm",
		"contracts", "observation.schema.json")
	published, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatalf("reading published schema: %v", err)
	}

	var publishedDoc, embeddedDoc any
	if err := json.Unmarshal(published, &publishedDoc); err != nil {
		t.Fatalf("parsing published schema: %v", err)
	}
	if err := json.Unmarshal(observation.SchemaJSON(), &embeddedDoc); err != nil {
		t.Fatalf("parsing embedded schema: %v", err)
	}

	// Compared as parsed documents rather than bytes, so reformatting the
	// contract file does not fail the build while a semantic change does.
	if !reflect.DeepEqual(publishedDoc, embeddedDoc) {
		t.Error("the embedded observation schema differs from contracts/observation.schema.json; " +
			"copy the contract into internal/observation/observation.schema.json")
	}
}

func TestObservationSchemaCompiles(t *testing.T) {
	// A schema that fails to compile would make every record unvalidatable at
	// runtime, and the failure would surface in a sensor pod rather than here.
	if _, err := observation.Schema(); err != nil {
		t.Fatalf("embedded observation schema does not compile: %v", err)
	}
}

func TestNamedServiceTargetPortsAreDeclaredByAWorkload(t *testing.T) {
	// A Service whose targetPort names a container port nothing declares gets
	// no endpoints, and nothing anywhere says so: the Service exists, the
	// Deployment is healthy, and clients simply cannot connect.
	//
	// config/audit/service.yaml forwarded to a port named "audit" that the
	// manager did not declare. Since ADR-0003 gives ledger credentials to the
	// manager alone, every other component commits audit records through that
	// Service -- so the whole of FR-036 rested on a name that resolved to
	// nothing.
	declared := map[string]string{}
	named := map[string][]string{}

	forEachManifest(t, func(path string, content []byte) {
		for _, part := range splitYAML(string(content)) {
			var doc struct {
				Kind string `json:"kind"`
				Spec struct {
					Template struct {
						Spec struct {
							Containers []struct {
								Ports []struct {
									Name string `json:"name"`
								} `json:"ports"`
							} `json:"containers"`
						} `json:"spec"`
					} `json:"template"`
					Ports []struct {
						TargetPort any `json:"targetPort"`
					} `json:"ports"`
				} `json:"spec"`
			}
			if err := yaml.Unmarshal([]byte(part), &doc); err != nil {
				continue
			}
			switch doc.Kind {
			case "Deployment", "DaemonSet", "StatefulSet":
				for _, c := range doc.Spec.Template.Spec.Containers {
					for _, p := range c.Ports {
						if p.Name != "" {
							declared[p.Name] = path
						}
					}
				}
			case "Service":
				for _, p := range doc.Spec.Ports {
					// A numeric targetPort needs no declaration; only a name
					// can dangle.
					if name, ok := p.TargetPort.(string); ok && name != "" {
						named[name] = append(named[name], path)
					}
				}
			}
		}
	})

	for name, services := range named {
		if _, ok := declared[name]; !ok {
			t.Errorf("%s target a container port named %q, which no workload in config/ declares; "+
				"the Service will have no endpoints", strings.Join(services, ", "), name)
		}
	}
}

func TestNetworkPolicyIngressPortsAreDeclaredContainerPorts(t *testing.T) {
	// A NetworkPolicy port is a port on the receiving pod, not the port its
	// Service publishes. The audit sink's rule opened 8443 -- the Service's
	// port -- while the manager serves the sink on 9444, so the rule actually
	// opened the metrics port and left the sink closed to every component that
	// has no other way to record what it did.
	//
	// Nothing catches that at apply time: both numbers are valid, the policy is
	// accepted, and the only symptom is a connection that times out. The
	// adjacent Service check above cannot see it either, because a
	// NetworkPolicy names no Service.
	//
	// Be clear about the limit: this would NOT have caught that particular
	// defect, because 8443 was also the manager's real metrics port, so the
	// rule opened something. What it catches is the same mistake whenever the
	// Service port is not independently a port of that pod - the common case,
	// and the one the gateway's own 443-versus-8443 pair would have hit. It is
	// a floor, not a proof.
	declared := map[string]map[int]bool{} // component -> container ports
	policies := map[string][]int{}        // component -> ingress ports

	const componentLabel = "app.kubernetes.io/component"

	// Rendered rather than read from config/, because kustomize patches add
	// both ports and the arguments that open them: the manager's webhook port
	// exists only after config/default is built, so a check against the source
	// files would be judging a workload that is not the one deployed.
	{
		for _, part := range splitYAML(renderDefault(t)) {
			var doc struct {
				Kind string `json:"kind"`
				Spec struct {
					Template struct {
						Metadata struct {
							Labels map[string]string `json:"labels"`
						} `json:"metadata"`
						Spec struct {
							Containers []struct {
								Ports []struct {
									ContainerPort int `json:"containerPort"`
								} `json:"ports"`
							} `json:"containers"`
						} `json:"spec"`
					} `json:"template"`
					PodSelector struct {
						MatchLabels map[string]string `json:"matchLabels"`
					} `json:"podSelector"`
					Ingress []struct {
						Ports []struct {
							Port     any    `json:"port"`
							Protocol string `json:"protocol"`
						} `json:"ports"`
					} `json:"ingress"`
				} `json:"spec"`
			}
			if err := yaml.Unmarshal([]byte(part), &doc); err != nil {
				continue
			}

			switch doc.Kind {
			case "Deployment", "DaemonSet", "StatefulSet":
				component := doc.Spec.Template.Metadata.Labels[componentLabel]
				if component == "" {
					continue
				}
				if declared[component] == nil {
					declared[component] = map[int]bool{}
				}
				for _, c := range doc.Spec.Template.Spec.Containers {
					for _, p := range c.Ports {
						declared[component][p.ContainerPort] = true
					}
				}
			case "NetworkPolicy":
				// Only policies that single out one workload can be checked
				// this way. A namespace-wide default-deny selects everything
				// and its ports belong to no one container.
				component := doc.Spec.PodSelector.MatchLabels[componentLabel]
				if component == "" {
					continue
				}
				for _, rule := range doc.Spec.Ingress {
					for _, p := range rule.Ports {
						// A named port in a NetworkPolicy resolves against the
						// pod too, but only numbers can be silently wrong in
						// the way that matters here.
						if n, ok := p.Port.(float64); ok {
							policies[component] = append(policies[component], int(n))
						}
					}
				}
			}
		}
	}

	if len(policies) == 0 {
		t.Fatal("no per-workload NetworkPolicy found; this check would pass vacuously")
	}

	for component, ports := range policies {
		containerPorts, ok := declared[component]
		if !ok {
			t.Errorf("a NetworkPolicy selects component %q, which no rendered workload declares", component)
			continue
		}
		for _, port := range ports {
			if !containerPorts[port] {
				t.Errorf("a NetworkPolicy allows ingress to port %d on component %q, which declares no such "+
					"container port; a NetworkPolicy port is the pod's port, not its Service's",
					port, component)
			}
		}
	}
}

// renderDefault builds config/default the way a deploy does.
//
// Several properties worth asserting only exist after kustomization: patches
// add container ports and the flags that open them, and namePrefix decides the
// names objects actually reference each other by. Checking the source files
// instead would be checking a workload nobody runs.
func renderDefault(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	kustomize := filepath.Join(root, "bin", "kustomize")
	if _, err := os.Stat(kustomize); err != nil {
		t.Skipf("bin/kustomize absent, run `make kustomize`: %v", err)
	}

	//nolint:gosec // G204: both the binary and the path are derived from the
	// repository root this test located itself; there is no caller input.
	cmd := exec.CommandContext(t.Context(), kustomize, "build", filepath.Join(root, "config", "default"))
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("kustomize build config/default: %v: %s", err, exitErr.Stderr)
		}
		t.Fatalf("kustomize build config/default: %v", err)
	}
	return string(out)
}
