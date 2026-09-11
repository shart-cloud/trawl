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
	"testing"
)

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
