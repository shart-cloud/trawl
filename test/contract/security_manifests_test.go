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

// T121's static security gates, over the manifests a deploy actually applies.
//
// Most of T121's list was already asserted before this file existed, and is
// deliberately not repeated here - a second copy of a check is a second thing
// to keep true, and the first copy is where a reader will look:
//
//   - wildcard RBAC              TestManifestsDeclareNoWildcardRBAC
//   - floating image tags        TestManifestsUseNoFloatingImageTags
//   - hostPath, host namespaces,
//     privileged: true           TestManifestsRequestNoHostAccess
//   - restricted Pod Security    TestSystemNamespaceEnforcesRestrictedPodSecurity
//   - default-deny networking    TestDefaultDenyNetworkPolicyExists
//   - browser download links     TestDashboardsCarryNoSecretsOrDownloadLinks
//   - secret-bearing telemetry   TestNormalizedRecordsCarryNoSensitiveFieldNames,
//     TestStoredRecordsNeverCarryAQueryStringToken
//
// What remained were three properties nothing asserted: that admission can see
// an off-namespace resource at all, that a workload with no reason to hold an
// API credential is not handed one, and that nothing publishes the evidence
// bucket. Each is silent when it breaks, which is the whole reason for a static
// gate.
//
// These render config/default rather than reading config/. T119 is the reason:
// a check that reads the pre-kustomize files is checking a workload nobody
// runs, and that is exactly how the event worker shipped naming a service
// account that does not exist.
package contract

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"
)

// manifestDocs splits a rendered stream into its documents, skipping blanks.
func manifestDocs(rendered string) []string {
	var out []string
	for doc := range strings.SplitSeq(rendered, "\n---\n") {
		if strings.TrimSpace(doc) != "" {
			out = append(out, doc)
		}
	}
	return out
}

// docKind reports a document's kind without fully decoding it.
func docKind(doc string) string {
	var head struct {
		Kind string `json:"kind"`
	}
	if err := yaml.Unmarshal([]byte(doc), &head); err != nil {
		return ""
	}
	return head.Kind
}

func TestTrawlWebhooksInterceptEveryNamespace(t *testing.T) {
	// admission.Gate refuses a Trawl resource created outside the system
	// namespace. That refusal is only reachable if the API server routes the
	// request to the webhook in the first place - and a namespaceSelector or
	// an objectSelector on the webhook configuration is exactly what would
	// stop it, silently. A CaptureJob created in `default` would then be
	// admitted unvalidated rather than rejected: no error, no audit record,
	// and a privileged capture request living somewhere nothing watches.
	//
	// failurePolicy is asserted with them for the same reason. Ignore would
	// turn an unreachable webhook into blanket admission, which is the failure
	// mode a fail-closed design exists to refuse.
	rendered := renderDefault(t)

	seen := 0
	for _, doc := range manifestDocs(rendered) {
		kind := docKind(doc)
		if kind != "ValidatingWebhookConfiguration" && kind != "MutatingWebhookConfiguration" {
			continue
		}

		type webhook struct {
			Name              string                         `json:"name"`
			NamespaceSelector *map[string]any                `json:"namespaceSelector"`
			ObjectSelector    *map[string]any                `json:"objectSelector"`
			FailurePolicy     *admissionv1.FailurePolicyType `json:"failurePolicy"`
		}
		var cfg struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Webhooks []webhook `json:"webhooks"`
		}
		if err := yaml.Unmarshal([]byte(doc), &cfg); err != nil {
			t.Fatalf("decoding %s: %v", kind, err)
		}
		if len(cfg.Webhooks) == 0 {
			t.Errorf("%s %s registers no webhooks", kind, cfg.Metadata.Name)
		}

		for _, w := range cfg.Webhooks {
			seen++
			if w.NamespaceSelector != nil && len(*w.NamespaceSelector) > 0 {
				t.Errorf("%s: webhook %q carries a namespaceSelector, so a Trawl resource created "+
					"outside the selected namespaces bypasses admission entirely rather than being rejected by it",
					cfg.Metadata.Name, w.Name)
			}
			if w.ObjectSelector != nil && len(*w.ObjectSelector) > 0 {
				t.Errorf("%s: webhook %q carries an objectSelector, so a Trawl resource whose labels "+
					"do not match is admitted unvalidated", cfg.Metadata.Name, w.Name)
			}
			if w.FailurePolicy == nil || *w.FailurePolicy != admissionv1.Fail {
				t.Errorf("%s: webhook %q has failurePolicy %v, want Fail; an unreachable webhook must "+
					"refuse mutations rather than wave them through", cfg.Metadata.Name, w.Name, w.FailurePolicy)
			}
		}
	}

	// Without this the loop above passes on a render that registers no
	// webhooks at all, which is the strongest form of the defect it is
	// looking for.
	if seen == 0 {
		t.Fatal("the rendered install registers no admission webhooks, so nothing enforces the system namespace")
	}
}

func TestEveryServiceAccountWithoutABindingRefusesATokenMount(t *testing.T) {
	// A service-account token in a pod that has no API permissions is not
	// harmless: it is a cluster-authenticated credential sitting on a
	// filesystem, and it names an identity an attacker can then look for
	// bindings on. The operator-rendered workloads already get this right -
	// the sensor and the capture runner set automountServiceAccountToken
	// false and project a narrow token where one is genuinely needed
	// (capturejob_workload_test.go, networktap_workload_test.go). Nothing
	// asserted it for the workloads shipped as static manifests.
	//
	// The rule is the honest one rather than a blanket ban: an account that
	// is bound to a Role or ClusterRole needs its token, and all three of
	// Trawl's control-plane accounts are. An account with no binding has
	// nothing to use a token for, so it must refuse one.
	rendered := renderDefault(t)

	accounts := map[string]*corev1.ServiceAccount{}
	bound := map[string]bool{}

	for _, doc := range manifestDocs(rendered) {
		switch docKind(doc) {
		case "ServiceAccount":
			var sa corev1.ServiceAccount
			if err := yaml.Unmarshal([]byte(doc), &sa); err != nil {
				t.Fatalf("decoding ServiceAccount: %v", err)
			}
			accounts[sa.Name] = &sa
		case "RoleBinding":
			var rb rbacv1.RoleBinding
			if err := yaml.Unmarshal([]byte(doc), &rb); err != nil {
				t.Fatalf("decoding RoleBinding: %v", err)
			}
			for _, s := range rb.Subjects {
				if s.Kind == "ServiceAccount" {
					bound[s.Name] = true
				}
			}
		case "ClusterRoleBinding":
			var crb rbacv1.ClusterRoleBinding
			if err := yaml.Unmarshal([]byte(doc), &crb); err != nil {
				t.Fatalf("decoding ClusterRoleBinding: %v", err)
			}
			for _, s := range crb.Subjects {
				if s.Kind == "ServiceAccount" {
					bound[s.Name] = true
				}
			}
		}
	}

	if len(accounts) == 0 {
		t.Fatal("the rendered install declares no ServiceAccounts, so this check asserts nothing")
	}

	for name, sa := range accounts {
		if bound[name] {
			continue
		}
		if sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken {
			t.Errorf("ServiceAccount %q is bound to no Role or ClusterRole but still automounts a "+
				"token; set automountServiceAccountToken: false, or bind it and say what it needs",
				name)
		}
	}
}

func TestNoContainerAddsALinuxCapability(t *testing.T) {
	// CAP_NET_RAW and CAP_NET_ADMIN belong to the sensor and the capture
	// runner, which the operator renders with a reviewed exception (ADR-0004).
	// Nothing under config/ is a data-plane workload, so nothing here should
	// add a capability at all. TestManifestsRequestNoHostAccess catches
	// `privileged: true`, which is the loud version of this; a single added
	// capability is the quiet one.
	rendered := renderDefault(t)

	checked := 0
	for _, doc := range manifestDocs(rendered) {
		kind := docKind(doc)
		if kind != "Deployment" && kind != "DaemonSet" && kind != "StatefulSet" {
			continue
		}
		var wl struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Spec struct {
				Template corev1.PodTemplateSpec `json:"template"`
			} `json:"spec"`
		}
		if err := yaml.Unmarshal([]byte(doc), &wl); err != nil {
			t.Fatalf("decoding %s: %v", kind, err)
		}

		containers := append([]corev1.Container{}, wl.Spec.Template.Spec.InitContainers...)
		containers = append(containers, wl.Spec.Template.Spec.Containers...)
		for _, c := range containers {
			checked++
			sc := c.SecurityContext
			if sc == nil || sc.Capabilities == nil {
				t.Errorf("%s %s container %q declares no capability policy; it should drop ALL",
					kind, wl.Metadata.Name, c.Name)
				continue
			}
			if len(sc.Capabilities.Add) > 0 {
				t.Errorf("%s %s container %q adds capabilities %v; only the operator-rendered sensor "+
					"and capture runner may, and they do it with a reviewed exception",
					kind, wl.Metadata.Name, c.Name, sc.Capabilities.Add)
			}
			dropsAll := false
			for _, d := range sc.Capabilities.Drop {
				if d == "ALL" {
					dropsAll = true
				}
			}
			if !dropsAll {
				t.Errorf("%s %s container %q drops %v, not ALL",
					kind, wl.Metadata.Name, c.Name, sc.Capabilities.Drop)
			}
		}
	}

	if checked == 0 {
		t.Fatal("the rendered install declares no containers, so this check asserts nothing")
	}
}

func TestNothingPublishesTheArtifactBucket(t *testing.T) {
	// Captures are evidence. The artifact gateway exists so that reading one
	// is an authorized, audited act (US3), and every one of those properties
	// is void if the bucket itself answers anonymous requests. Trawl never
	// creates a bucket, so what this guards is the configuration and the
	// documentation an operator copies: a public-read ACL or an anonymous
	// bucket policy pasted into either is a silent, total bypass of the
	// download authorization path.
	root := repoRoot(t)

	// Written as separate patterns rather than one alternation so a failure
	// names the specific grant that was found.
	grants := []struct {
		pattern *regexp.Regexp
		what    string
	}{
		{regexp.MustCompile(`(?i)public-read`), "a public-read ACL"},
		{regexp.MustCompile(`(?i)PublicReadGetObject`), "the canonical anonymous bucket-policy statement"},
		{regexp.MustCompile(`"Principal"\s*:\s*(\{\s*"AWS"\s*:\s*)?"\*"`), `a bucket policy with Principal "*"`},
		{regexp.MustCompile(`(?i)AuthenticatedRead|BucketOwnerRead`), "a canned ACL wider than private"},
		{regexp.MustCompile(`(?i)mc\s+anonymous\s+set\s+(public|download)`), "an mc anonymous grant"},
		{regexp.MustCompile(`(?i)policy\s+set\s+(public|download)`), "an mc policy grant"},
	}

	roots := []string{
		filepath.Join(root, "config"),
		filepath.Join(root, "docs"),
		filepath.Join(root, "specs"),
	}

	scanned := 0
	for _, dir := range roots {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		walkFiles(t, dir, func(path string, content []byte) {
			scanned++
			for _, g := range grants {
				if loc := g.pattern.FindIndex(content); loc != nil {
					rel, _ := filepath.Rel(root, path)
					t.Errorf("%s declares %s near byte %d; the artifact gateway is the only "+
						"authorized read path for evidence, and an anonymous grant bypasses it "+
						"together with every audit record it would have written",
						rel, g.what, loc[0])
				}
			}
		})
	}

	if scanned == 0 {
		t.Fatal("no configuration or documentation was scanned, so this check asserts nothing")
	}
}

// walkFiles calls fn for every regular text file under dir.
func walkFiles(t *testing.T, dir string, fn func(path string, content []byte)) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// node_modules and build output are neither reviewed nor shipped,
			// and walking them turns a fast check into a slow one.
			switch d.Name() {
			case "node_modules", ".astro", "dist", ".git":
				return filepath.SkipDir
			}
			return nil
		}
		switch filepath.Ext(path) {
		case ".yaml", ".yml", ".json", ".md", ".sh", ".hcl", ".alloy", ".mdx":
		default:
			return nil
		}
		content, readErr := os.ReadFile(path) //nolint:gosec // G304: path comes from the walk of a repository directory.
		if readErr != nil {
			return readErr
		}
		fn(path, content)
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", dir, err)
	}
}
