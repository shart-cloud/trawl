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

// T128: the supply-chain manifest says everything it is required to say.
package contract

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

func TestImagesWorkflowRunsTheCompletenessGateAgainstItsManifest(t *testing.T) {
	root := repoRoot(t)
	workflowPath := filepath.Join(root, ".github", "workflows", "images.yml")
	raw, err := os.ReadFile(workflowPath) //nolint:gosec // Repository fixture.
	if err != nil {
		t.Fatalf("reading Images workflow: %v", err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct {
				Name string `json:"name"`
				Run  string `json:"run"`
			} `json:"steps"`
		} `json:"jobs"`
	}
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		t.Fatalf("decoding Images workflow: %v", err)
	}
	var gate string
	for _, step := range workflow.Jobs["supply-chain"].Steps {
		if step.Name == "Refuse an incomplete supply-chain record" {
			gate = step.Run
			break
		}
	}
	if gate == "" {
		t.Fatal("Images workflow has no supply-chain completeness gate")
	}

	manifestPath := filepath.Join(t.TempDir(), "manifest.json")
	writeManifest := func(sbomStatus string) {
		t.Helper()
		manifest := map[string]any{
			"build":             map[string]any{"cleanTree": true},
			"imageDigests":      map[string]any{"status": "present"},
			"goVulnerabilities": map[string]any{"status": "present"},
			"sbom":              map[string]any{"status": sbomStatus},
			"provenance":        map[string]any{"status": "present"},
		}
		encoded, err := json.Marshal(manifest)
		if err != nil {
			t.Fatalf("encoding manifest fixture: %v", err)
		}
		if err := os.WriteFile(manifestPath, encoded, 0o600); err != nil {
			t.Fatalf("writing manifest fixture: %v", err)
		}
	}
	runGate := func() ([]byte, error) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "bash", "-e", "-c", gate) //nolint:gosec // Workflow script from this repository.
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "MANIFEST="+manifestPath)
		return cmd.CombinedOutput()
	}

	writeManifest("present")
	if output, err := runGate(); err != nil {
		t.Fatalf("a complete manifest was rejected: %v\n%s", err, output)
	}
	writeManifest("unavailable")
	if output, err := runGate(); err == nil {
		t.Errorf("an incomplete manifest passed the workflow gate:\n%s", output)
	}
}

func TestTheSupplyChainManifestDeclaresEverySection(t *testing.T) {
	// The manifest's one rule is that a section which could not be produced is
	// recorded as absent with a reason, never omitted - a manifest missing its
	// SBOM section looks exactly like one whose SBOMs were never generated, and
	// the second is the case somebody needs to know about.
	//
	// That rule is only worth anything if something checks it, because the
	// failure mode is a section quietly disappearing from the generator. So
	// this runs the real generator and asserts every required key is present,
	// with either content or a stated reason.
	root := repoRoot(t)
	script := filepath.Join(root, "hack", "supply-chain-manifest.sh")
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("%s is missing, so releases have no provenance document: %v", script, err)
	}

	out := t.TempDir()
	//nolint:gosec // G204: the path comes from the repository root this test located.
	cmd := exec.CommandContext(t.Context(), script)
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"OUT_DIR="+out,
		// The vulnerability scan is covered by `make security` and takes long
		// enough to make this test a poor place for it. Its *section* is still
		// asserted below, which is what this test is about.
		"SUPPLY_CHAIN_SKIP_VULN=1",
	)
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generating the supply-chain manifest: %v\n%s", err, combined)
	}

	raw, err := os.ReadFile(filepath.Join(out, "manifest.json")) //nolint:gosec // G304: a temp dir this test created.
	if err != nil {
		t.Fatalf("reading the generated manifest: %v", err)
	}
	var manifest map[string]json.RawMessage
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("the generated manifest is not valid JSON: %v", err)
	}

	// Every clause of T128, by the name the manifest gives it.
	required := []string{
		"upstreamSources",  // verified upstream sources
		"detectionContent", // rule and script hashes
		"imageDigests",     // immutable image digests
		"goVulnerabilities",
		"sbom",
		"provenance",
	}

	for _, section := range required {
		body, ok := manifest[section]
		if !ok {
			t.Errorf("the manifest has no %q section. A missing section is indistinguishable from one "+
				"that was never generated, which is the exact ambiguity this document exists to remove.",
				section)
			continue
		}
		var s struct {
			Status string `json:"status"`
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal(body, &s); err != nil {
			t.Errorf("%s is not an object with a status: %v", section, err)
			continue
		}
		switch s.Status {
		case "present":
		case "unavailable":
			if s.Reason == "" {
				t.Errorf("%s is unavailable and says why not; a section that cannot explain its own "+
					"absence cannot be acted on", section)
			}
		default:
			t.Errorf("%s has status %q, want present or unavailable", section, s.Status)
		}
	}

	// Build identity is not optional: a provenance document that cannot say
	// which commit it describes documents nothing.
	var build struct {
		Commit    string `json:"commit"`
		CleanTree *bool  `json:"cleanTree"`
	}
	if body, ok := manifest["build"]; !ok {
		t.Error("the manifest records no build identity")
	} else if err := json.Unmarshal(body, &build); err != nil {
		t.Errorf("build is not an object: %v", err)
	} else {
		if build.Commit == "" {
			t.Error("the manifest records no commit, so nothing ties it to a revision")
		}
		// Recorded rather than required to be true: this test runs from a
		// working tree that is usually dirty. What matters is that the manifest
		// states it, so a release artifact cannot imply a reproducibility it
		// does not have.
		if build.CleanTree == nil {
			t.Error("the manifest does not say whether it was generated from a clean tree")
		}
	}
}

func TestEveryUpstreamSourceIsPinnedByChecksumOrNamedAsNot(t *testing.T) {
	// The supply chain's actual content, rather than the manifest's shape.
	//
	// Trawl compiles Zeek and Suricata from upstream source and takes dumpcap
	// from Debian packages. A version alone can be re-cut upstream; the
	// checksum is what makes a pin mean anything. This does not demand that
	// every source carry one - cbindgen comes from crates.io, where a published
	// version is immutable - but it does demand that anything without one is
	// visible in the manifest's warning rather than sitting quietly in a list
	// of things that look equally pinned.
	root := repoRoot(t)
	out := t.TempDir()

	//nolint:gosec // G204: the path comes from the repository root this test located.
	cmd := exec.CommandContext(t.Context(), filepath.Join(root, "hack", "supply-chain-manifest.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "OUT_DIR="+out, "SUPPLY_CHAIN_SKIP_VULN=1")
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generating the supply-chain manifest: %v\n%s", err, combined)
	}

	raw, err := os.ReadFile(filepath.Join(out, "manifest.json")) //nolint:gosec // G304: a temp dir this test created.
	if err != nil {
		t.Fatalf("reading the generated manifest: %v", err)
	}
	var manifest struct {
		UpstreamSources struct {
			Entries []struct {
				Image        string `json:"image"`
				Component    string `json:"component"`
				Verification string `json:"verification"`
			} `json:"entries"`
			Warning string `json:"warning"`
		} `json:"upstreamSources"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("decoding the manifest: %v", err)
	}

	entries := manifest.UpstreamSources.Entries
	if len(entries) == 0 {
		t.Fatal("the manifest lists no upstream sources, so this check asserts nothing")
	}

	var weak []string
	for _, e := range entries {
		switch e.Verification {
		case "checksum and detached signature", "checksum only":
		case "version only":
			weak = append(weak, e.Image+"/"+e.Component)
		default:
			t.Errorf("%s/%s reports verification %q, which this check does not recognise",
				e.Image, e.Component, e.Verification)
		}
	}

	// The two analyzers compiled from source are the ones where a signature,
	// not merely a checksum, is the bar: they are the code that reads attacker
	// -controlled bytes off the wire.
	signed := map[string]bool{}
	for _, e := range entries {
		if e.Verification == "checksum and detached signature" {
			signed[e.Component] = true
		}
	}
	for _, component := range []string{"zeek", "suricata"} {
		if !signed[component] {
			t.Errorf("%s is not pinned by a detached signature. It is compiled from upstream source "+
				"and parses hostile input; a checksum alone records that the bytes did not change, "+
				"not who published them.", component)
		}
	}

	if len(weak) > 0 && manifest.UpstreamSources.Warning == "" {
		t.Errorf("%v are pinned by version with no checksum and the manifest carries no warning "+
			"about it; they sit in the list looking as pinned as everything else", weak)
	}
}

func TestEveryPublishedBinaryIsIncludedInTheDigestRecord(t *testing.T) {
	root := repoRoot(t)
	workflowPath := filepath.Join(root, ".github", "workflows", "images.yml")
	raw, err := os.ReadFile(workflowPath) //nolint:gosec // Repository fixture.
	if err != nil {
		t.Fatalf("reading Images workflow: %v", err)
	}
	workflow := string(raw)
	start := strings.Index(workflow, "      - name: Resolve digests")
	if start < 0 {
		t.Fatal("Images workflow has no digest-resolution step")
	}
	end := strings.Index(workflow[start:], "      - uses: actions/upload-artifact@")
	if end < 0 {
		t.Fatal("Images workflow does not upload its digest record")
	}
	resolver := workflow[start : start+end]

	// These are every image published by the workflow. The gateway was once in
	// the build matrix but absent here, so a green workflow published it without
	// putting its immutable reference in the provenance document.
	for _, image := range []string{
		"controller-manager", "sensor-agent", "event-worker", "capture-runner",
		"capture-reporter", "artifact-gateway", "content-init", "zeek", "suricata",
	} {
		if !strings.Contains(resolver, image) {
			t.Errorf("the digest record omits %s", image)
		}
	}
}

func TestTheSBOMGeneratorScansEveryBuiltDigest(t *testing.T) {
	root := repoRoot(t)
	temp := t.TempDir()
	out := filepath.Join(temp, "out")
	digests := filepath.Join(temp, "digests.txt")
	if err := os.WriteFile(digests, []byte(strings.Join([]string{
		"controller-manager=ghcr.io/example/controller-manager@sha256:" + strings.Repeat("a", 64),
		"artifact-gateway=ghcr.io/example/artifact-gateway@sha256:" + strings.Repeat("b", 64),
		"zeek=<not built in this run>",
	}, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("writing digest fixture: %v", err)
	}

	log := filepath.Join(temp, "syft.log")
	fakeSyft := filepath.Join(temp, "syft")
	fake := `#!/bin/sh
set -eu
printf '%s\n' "$1" >> "$SYFT_LOG"
output=${3#spdx-json=}
printf '{"spdxVersion":"SPDX-2.3"}\n' > "$output"
`
	if err := os.WriteFile(fakeSyft, []byte(fake), 0o600); err != nil {
		t.Fatalf("writing fake syft: %v", err)
	}
	if err := os.Chmod(fakeSyft, 0o700); err != nil { //nolint:gosec // Test helper must be executable.
		t.Fatalf("making fake syft executable: %v", err)
	}

	generator := filepath.Join(root, "hack", "generate-sboms.sh")
	cmd := exec.CommandContext(t.Context(), generator) //nolint:gosec // Repository script.
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"SYFT="+fakeSyft,
		"SYFT_LOG="+log,
		"DIGESTS_FILE="+digests,
		"OUT_DIR="+out,
		"SOURCE_DIR="+root,
	)
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generating SBOM fixtures: %v\n%s", err, combined)
	}

	for _, name := range []string{"source", "controller-manager", "artifact-gateway"} {
		if _, err := os.Stat(filepath.Join(out, name+".spdx.json")); err != nil {
			t.Errorf("%s SBOM was not generated: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "zeek.spdx.json")); !os.IsNotExist(err) {
		t.Errorf("an image explicitly absent from this run acquired an SBOM: %v", err)
	}

	logged, err := os.ReadFile(log) //nolint:gosec // Test-owned temporary file.
	if err != nil {
		t.Fatalf("reading fake syft log: %v", err)
	}
	for _, reference := range []string{"dir:" + root, "controller-manager@sha256:", "artifact-gateway@sha256:"} {
		if !strings.Contains(string(logged), reference) {
			t.Errorf("syft was not invoked for %q; calls were:\n%s", reference, logged)
		}
	}

	manifestGenerator := filepath.Join(root, "hack", "supply-chain-manifest.sh")
	manifestCmd := exec.CommandContext(t.Context(), manifestGenerator) //nolint:gosec // Repository script.
	manifestCmd.Dir = root
	manifestCmd.Env = append(os.Environ(),
		"DIGESTS_FILE="+digests,
		"OUT_DIR="+out,
		"SUPPLY_CHAIN_SKIP_VULN=1",
	)
	if combined, err := manifestCmd.CombinedOutput(); err != nil {
		t.Fatalf("assembling manifest from the generated SBOMs: %v\n%s", err, combined)
	}
	manifestRaw, err := os.ReadFile(filepath.Join(out, "manifest.json")) //nolint:gosec // Test-owned temporary file.
	if err != nil {
		t.Fatalf("reading generated manifest: %v", err)
	}
	var manifest struct {
		SBOM struct {
			Status  string `json:"status"`
			Entries []struct {
				Subject string `json:"subject"`
			} `json:"entries"`
		} `json:"sbom"`
	}
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatalf("decoding generated manifest: %v", err)
	}
	if manifest.SBOM.Status != "present" {
		t.Errorf("complete generated SBOM set has status %q, want present", manifest.SBOM.Status)
	}
	if len(manifest.SBOM.Entries) != 3 {
		t.Errorf("manifest records %d SBOMs, want source and two built images", len(manifest.SBOM.Entries))
	}
}

func TestTheManifestCannotClaimAnSBOMThatDoesNotExist(t *testing.T) {
	root := repoRoot(t)
	out := t.TempDir()

	manifestGenerator := filepath.Join(root, "hack", "supply-chain-manifest.sh")
	cmd := exec.CommandContext(t.Context(), manifestGenerator) //nolint:gosec // Repository script.
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "OUT_DIR="+out, "SUPPLY_CHAIN_SKIP_VULN=1")
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generating supply-chain manifest: %v\n%s", err, combined)
	}

	raw, err := os.ReadFile(filepath.Join(out, "manifest.json")) //nolint:gosec // Test-owned temporary file.
	if err != nil {
		t.Fatalf("reading generated manifest: %v", err)
	}
	var manifest struct {
		SBOM struct {
			Status string `json:"status"`
			Reason string `json:"reason"`
		} `json:"sbom"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("decoding generated manifest: %v", err)
	}
	if manifest.SBOM.Status != "unavailable" {
		t.Errorf("SBOM status = %q without an SBOM file, want unavailable", manifest.SBOM.Status)
	}
	if !strings.Contains(manifest.SBOM.Reason, "source") {
		t.Errorf("missing source SBOM reason = %q, want the absent subject named", manifest.SBOM.Reason)
	}
}

func TestTheInstallerUsesTheImagesBuiltForItsReleaseTag(t *testing.T) {
	root := repoRoot(t)
	temp := t.TempDir()
	install := filepath.Join(temp, "install.yaml")
	digests := filepath.Join(temp, "digests.txt")
	oldDigest := strings.Repeat("0", 64)
	managerDigest := strings.Repeat("a", 64)
	gatewayDigest := strings.Repeat("b", 64)
	fixture := strings.Join([]string{
		"containers:",
		"  image: ghcr.io/shart-cloud/trawl/controller-manager@sha256:" + oldDigest,
		"  image: ghcr.io/shart-cloud/trawl/artifact-gateway@sha256:" + oldDigest,
		"  image: quay.io/minio/minio:RELEASE.2025-04-22T22-12-26Z",
	}, "\n") + "\n"
	if err := os.WriteFile(install, []byte(fixture), 0o600); err != nil {
		t.Fatalf("writing installer fixture: %v", err)
	}
	digestFixture := strings.Join([]string{
		"controller-manager=ghcr.io/shart-cloud/trawl/controller-manager@sha256:" + managerDigest,
		"artifact-gateway=ghcr.io/shart-cloud/trawl/artifact-gateway@sha256:" + gatewayDigest,
		"zeek=<not built in this run>",
	}, "\n") + "\n"
	if err := os.WriteFile(digests, []byte(digestFixture), 0o600); err != nil {
		t.Fatalf("writing digest fixture: %v", err)
	}

	pinner := filepath.Join(root, "hack", "pin-installer-images.sh")
	cmd := exec.CommandContext(t.Context(), pinner, install, digests) //nolint:gosec // Repository script.
	cmd.Dir = root
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("pinning installer fixture: %v\n%s", err, combined)
	}

	updated, err := os.ReadFile(install) //nolint:gosec // Test-owned temporary file.
	if err != nil {
		t.Fatalf("reading pinned installer: %v", err)
	}
	text := string(updated)
	for _, digest := range []string{managerDigest, gatewayDigest} {
		if !strings.Contains(text, "sha256:"+digest) {
			t.Errorf("installer does not contain tag-build digest %s", digest)
		}
	}
	if strings.Contains(text, "sha256:"+oldDigest) {
		t.Error("installer retained a pre-tag candidate digest")
	}
	if !strings.Contains(text, "quay.io/minio/minio:RELEASE.2025-04-22T22-12-26Z") {
		t.Error("pinning Trawl images changed an unrelated image")
	}
}

func TestReleaseWaitsForAndConsumesTheTagImageBuild(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, ".github", "workflows", "release.yml")
	raw, err := os.ReadFile(path) //nolint:gosec // Repository fixture.
	if err != nil {
		t.Fatalf("reading Release workflow: %v", err)
	}
	workflow := string(raw)
	for _, required := range []string{
		"workflow_run:",
		`workflows: ["Images"]`,
		"run-id: ${{ steps.release.outputs.run_id }}",
		"name: image-digests",
		"name: supply-chain-manifest",
		"hack/pin-installer-images.sh",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("Release workflow does not contain %q", required)
		}
	}
	if strings.Contains(workflow, "tags: [\"v*\"]") {
		t.Error("Release still starts concurrently on a tag instead of waiting for Images")
	}
}
