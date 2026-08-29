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

package content

import (
	"strings"
	"testing"
)

// ADR-0005: analyzer content is two layers, upstream and an optional
// site-specific OCI overlay. These tests pin the reference and merge rules that
// the init containers in T047a depend on.

func TestParseReferenceRequiresDigest(t *testing.T) {
	// FR-042: custom content is versioned by digest. A tag can be repointed
	// after the rule review that approved it.
	valid := "registry.example.com/trawl/custom@sha256:" + strings.Repeat("a", 64)

	ref, err := ParseReference(valid)
	if err != nil {
		t.Fatalf("ParseReference rejected a digest reference: %v", err)
	}
	if ref.Repository != "registry.example.com/trawl/custom" {
		t.Errorf("Repository = %q", ref.Repository)
	}
	if ref.Digest != "sha256:"+strings.Repeat("a", 64) {
		t.Errorf("Digest = %q", ref.Digest)
	}

	for name, in := range map[string]string{
		"tag":              "registry.example.com/trawl/custom:v1",
		"latest":           "registry.example.com/trawl/custom:latest",
		"bare repository":  "registry.example.com/trawl/custom",
		"empty":            "",
		"short digest":     "registry.example.com/c@sha256:abc",
		"wrong algorithm":  "registry.example.com/c@md5:" + strings.Repeat("a", 32),
		"uppercase digest": "registry.example.com/c@sha256:" + strings.Repeat("A", 64),
		"no repository":    "@sha256:" + strings.Repeat("a", 64),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseReference(in); err == nil {
				t.Errorf("ParseReference accepted %q", in)
			}
		})
	}
}

func TestReferenceStringRoundTrips(t *testing.T) {
	in := "reg.example/c@sha256:" + strings.Repeat("b", 64)
	ref, err := ParseReference(in)
	if err != nil {
		t.Fatalf("ParseReference: %v", err)
	}
	if got := ref.String(); got != in {
		t.Errorf("String() = %q, want %q", got, in)
	}
}

func TestValidateFeedURLRejectsUnsafeSchemes(t *testing.T) {
	// The init container fetches this URL. A file:// or plain-http feed would
	// let anyone who can edit installation config replace detection content.
	for _, ok := range []string{
		"https://rules.emergingthreats.net/open/suricata-8.0/emerging.rules.tar.gz",
		"https://github.com/zeek/packages",
	} {
		if err := ValidateFeedURL(ok); err != nil {
			t.Errorf("ValidateFeedURL(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{
		"http://rules.example/emerging.rules.tar.gz",
		"file:///etc/passwd",
		"ftp://rules.example/x.tar.gz",
		"rules.example/x.tar.gz",
		"",
		"https://",
	} {
		if err := ValidateFeedURL(bad); err == nil {
			t.Errorf("ValidateFeedURL(%q) accepted an unsafe feed URL", bad)
		}
	}
}

func TestMergeOrderPutsCustomOverUpstream(t *testing.T) {
	// ADR-0005: custom overlays upstream, never the reverse. If it were the
	// other way, a site rule could never override a noisy upstream rule.
	upstream := Layer{
		Name:  LayerUpstream,
		Files: map[string][]byte{"rules/emerging.rules": []byte("upstream"), "rules/only-upstream.rules": []byte("u")},
	}
	custom := Layer{
		Name:  LayerCustom,
		Files: map[string][]byte{"rules/emerging.rules": []byte("custom"), "rules/only-custom.rules": []byte("c")},
	}

	merged, err := Merge(upstream, &custom)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if got := string(merged.Files["rules/emerging.rules"]); got != "custom" {
		t.Errorf("custom layer did not win: %q", got)
	}
	if _, ok := merged.Files["rules/only-upstream.rules"]; !ok {
		t.Error("upstream-only file was dropped")
	}
	if _, ok := merged.Files["rules/only-custom.rules"]; !ok {
		t.Error("custom-only file was dropped")
	}
	if merged.CustomApplied != true {
		t.Error("merged result does not record that custom content was applied")
	}
}

func TestMergeFallsBackToUpstreamWhenCustomAbsent(t *testing.T) {
	// FR-043: a missing custom artifact must not stop the analyzer. A
	// detection gap is bad; a monitoring outage is worse.
	upstream := Layer{Name: LayerUpstream, Files: map[string][]byte{"rules/a.rules": []byte("u")}}

	merged, err := Merge(upstream, nil)
	if err != nil {
		t.Fatalf("Merge with no custom layer failed: %v", err)
	}
	if merged.CustomApplied {
		t.Error("CustomApplied is true with no custom layer")
	}
	if len(merged.Files) != 1 {
		t.Errorf("got %d files, want 1", len(merged.Files))
	}
}

func TestMergeRejectsPathTraversalInCustomLayer(t *testing.T) {
	// Custom content is an OCI artifact from a registry. A path that escapes
	// the content directory would let it overwrite analyzer binaries or
	// configuration outside the shared volume.
	upstream := Layer{Name: LayerUpstream, Files: map[string][]byte{"rules/a.rules": []byte("u")}}

	for _, bad := range []string{
		"../../etc/passwd",
		"rules/../../escape",
		"/absolute/path",
		"rules/./../../x",
	} {
		t.Run(bad, func(t *testing.T) {
			custom := Layer{Name: LayerCustom, Files: map[string][]byte{bad: []byte("x")}}
			if _, err := Merge(upstream, &custom); err == nil {
				t.Errorf("Merge accepted traversal path %q", bad)
			}
		})
	}
}

func TestMergeRequiresNonEmptyUpstream(t *testing.T) {
	// An empty upstream layer means the fetch silently produced nothing.
	// Starting Suricata with no rules at all is worse than failing loudly,
	// because it looks healthy while detecting nothing.
	if _, err := Merge(Layer{Name: LayerUpstream}, nil); err == nil {
		t.Error("Merge accepted an empty upstream layer")
	}
}

func TestStatusReportsFeedTimestampAndDigest(t *testing.T) {
	// FR-045: operators verify content currency from status, without exec'ing
	// into a pod.
	upstream := Layer{
		Name:      LayerUpstream,
		Files:     map[string][]byte{"rules/a.rules": []byte("u")},
		FetchedAt: mustTime("2026-08-29T06:00:00Z"),
	}
	digest := "sha256:" + strings.Repeat("c", 64)
	custom := Layer{
		Name:   LayerCustom,
		Files:  map[string][]byte{"rules/b.rules": []byte("c")},
		Digest: digest,
	}

	merged, err := Merge(upstream, &custom)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	st := merged.Status()

	if st.UpstreamFetchedAt.IsZero() {
		t.Error("status does not report the upstream feed timestamp")
	}
	if st.CustomDigest != digest {
		t.Errorf("CustomDigest = %q, want %q", st.CustomDigest, digest)
	}
	if !st.CustomApplied {
		t.Error("status does not record that custom content was applied")
	}
}

func TestStatusOmitsCustomDigestWhenAbsent(t *testing.T) {
	upstream := Layer{
		Name:      LayerUpstream,
		Files:     map[string][]byte{"rules/a.rules": []byte("u")},
		FetchedAt: mustTime("2026-08-29T06:00:00Z"),
	}
	merged, err := Merge(upstream, nil)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if got := merged.Status().CustomDigest; got != "" {
		t.Errorf("CustomDigest = %q with no custom layer, want empty", got)
	}
}
