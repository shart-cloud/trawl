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
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type stubFetcher struct {
	layer Layer
	err   error
}

func (s *stubFetcher) Fetch(_ context.Context, _ string) (Layer, error) {
	return s.layer, s.err
}

func upstreamLayer() Layer {
	return Layer{
		Name:      LayerUpstream,
		Files:     map[string][]byte{"rules/emerging.rules": []byte("upstream rule")},
		FetchedAt: time.Date(2026, 8, 29, 6, 0, 0, 0, time.UTC),
	}
}

func TestResolveUpstreamOnly(t *testing.T) {
	r := &Resolver{Upstream: &stubFetcher{layer: upstreamLayer()}}

	merged, err := r.Resolve(t.Context(), t.TempDir())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if merged.CustomApplied {
		t.Error("custom content reported applied with no custom fetcher")
	}
	if merged.UpstreamFetchedAt.IsZero() {
		t.Error("no upstream feed timestamp recorded")
	}
}

func TestUpstreamFailureIsFatal(t *testing.T) {
	// An analyzer with no rules looks healthy while detecting nothing, which is
	// the worse failure mode. Better to fail the pod loudly.
	r := &Resolver{Upstream: &stubFetcher{err: errors.New("feed unreachable")}}

	if _, err := r.Resolve(t.Context(), t.TempDir()); err == nil {
		t.Fatal("Resolve succeeded despite an upstream fetch failure")
	}
}

func TestCustomFailureDegradesToUpstreamOnly(t *testing.T) {
	// FR-043: a missing or corrupt custom artifact must not stop the analyzer.
	// A detection gap is bad; a monitoring outage is worse.
	var reported error
	r := &Resolver{
		Upstream:        &stubFetcher{layer: upstreamLayer()},
		Custom:          &stubFetcher{err: errors.New("registry unreachable")},
		OnCustomFailure: func(err error) { reported = err },
	}

	merged, err := r.Resolve(t.Context(), t.TempDir())
	if err != nil {
		t.Fatalf("Resolve failed instead of degrading: %v", err)
	}
	if merged.CustomApplied {
		t.Error("custom content reported applied after a failed pull")
	}
	if len(merged.Files) != 1 {
		t.Errorf("got %d files, want the upstream layer intact", len(merged.Files))
	}
	if reported == nil {
		t.Error("the custom failure was absorbed silently instead of being reported")
	}
}

func TestCorruptCustomLayerDegradesRatherThanFailing(t *testing.T) {
	// A traversal path in an overlay pulled from a registry is treated the same
	// as a failed pull: refuse the overlay, keep monitoring.
	var reported error
	r := &Resolver{
		Upstream: &stubFetcher{layer: upstreamLayer()},
		Custom: &stubFetcher{layer: Layer{
			Name:  LayerCustom,
			Files: map[string][]byte{"../../escape": []byte("x")},
		}},
		OnCustomFailure: func(err error) { reported = err },
	}

	merged, err := r.Resolve(t.Context(), t.TempDir())
	if err != nil {
		t.Fatalf("Resolve failed instead of degrading: %v", err)
	}
	if merged.CustomApplied {
		t.Error("a traversal-bearing overlay was applied")
	}
	if reported == nil {
		t.Error("the corrupt overlay was not reported")
	}
}

func TestCustomOverlayApplies(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	r := &Resolver{
		Upstream: &stubFetcher{layer: upstreamLayer()},
		Custom: &stubFetcher{layer: Layer{
			Name:   LayerCustom,
			Files:  map[string][]byte{"rules/local.rules": []byte("site rule")},
			Digest: digest,
		}},
	}

	merged, err := r.Resolve(t.Context(), t.TempDir())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !merged.CustomApplied {
		t.Error("custom content was not applied")
	}
	if merged.CustomDigest != digest {
		t.Errorf("custom digest = %q, want %q", merged.CustomDigest, digest)
	}
	if len(merged.Files) != 2 {
		t.Errorf("got %d files, want 2", len(merged.Files))
	}
}

func TestWriteInstallsContentAtomically(t *testing.T) {
	// An analyzer starting concurrently must never observe a half-written
	// ruleset, so files are staged and moved into place.
	dir := filepath.Join(t.TempDir(), "content")
	merged := Merged{Files: map[string][]byte{
		"rules/a.rules":       []byte("one"),
		"scripts/site/b.zeek": []byte("two"),
	}}

	if err := Write(merged, dir); err != nil {
		t.Fatalf("Write: %v", err)
	}

	for name, want := range merged.Files {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("reading %s: %v", name, err)
			continue
		}
		if string(got) != string(want) {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if _, err := os.Stat(dir + ".staging"); !os.IsNotExist(err) {
		t.Error("the staging directory was left behind")
	}
}

func TestWriteReplacesPreviousContent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "content")

	if err := Write(Merged{Files: map[string][]byte{"rules/old.rules": []byte("old")}}, dir); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	if err := Write(Merged{Files: map[string][]byte{"rules/new.rules": []byte("new")}}, dir); err != nil {
		t.Fatalf("second Write: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "rules/old.rules")); !os.IsNotExist(err) {
		t.Error("content from the previous fetch survived a refresh")
	}
	if _, err := os.Stat(filepath.Join(dir, "rules/new.rules")); err != nil {
		t.Errorf("new content is missing: %v", err)
	}
}

func TestWriteRejectsTraversalPaths(t *testing.T) {
	// The last check before bytes reach the filesystem. The cost of being wrong
	// here is writing outside the content directory entirely.
	dir := filepath.Join(t.TempDir(), "content")
	merged := Merged{Files: map[string][]byte{"../escape.rules": []byte("x")}}

	if err := Write(merged, dir); err == nil {
		t.Fatal("Write accepted a traversal path")
	}
}

func TestReadRoundTripsWrittenContent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "content")
	merged := Merged{Files: map[string][]byte{
		"rules/a.rules":  []byte("one"),
		"scripts/b.zeek": []byte("two"),
	}}
	if err := Write(merged, dir); err != nil {
		t.Fatalf("Write: %v", err)
	}

	files, err := Read(dir)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(files) != 2 {
		t.Errorf("read %d files, want 2", len(files))
	}
	if string(files["rules/a.rules"]) != "one" {
		t.Errorf("rules/a.rules = %q", files["rules/a.rules"])
	}
}

func TestStatusRoundTripsThroughTheContentVolume(t *testing.T) {
	// The init container records what it resolved; the sensor reads it to
	// report content currency without re-walking the tree (FR-045).
	dir := t.TempDir()
	want := Status{
		UpstreamFetchedAt: time.Date(2026, 8, 29, 6, 0, 0, 0, time.UTC),
		CustomDigest:      "sha256:" + strings.Repeat("b", 64),
		CustomApplied:     true,
	}

	if err := WriteStatus(dir, want); err != nil {
		t.Fatalf("WriteStatus: %v", err)
	}
	got, err := ReadStatus(dir)
	if err != nil {
		t.Fatalf("ReadStatus: %v", err)
	}
	if !got.UpstreamFetchedAt.Equal(want.UpstreamFetchedAt) {
		t.Errorf("upstream fetched at = %v, want %v", got.UpstreamFetchedAt, want.UpstreamFetchedAt)
	}
	if got.CustomDigest != want.CustomDigest || got.CustomApplied != want.CustomApplied {
		t.Errorf("status = %+v, want %+v", got, want)
	}
}

func TestResolveRequiresAnUpstreamFetcher(t *testing.T) {
	r := &Resolver{}
	if _, err := r.Resolve(t.Context(), t.TempDir()); err == nil {
		t.Fatal("Resolve succeeded with no upstream fetcher configured")
	}
}

// The analyzers read this content as root with every capability dropped, so
// they have no CAP_DAC_OVERRIDE and the permission bits are enforced against
// them. Written at 0750/0600 by UID 65532, the tree was unreadable to them:
// Suricata started and reported "no rules were loaded", which is the detection
// half of the product silently doing nothing.
func TestFetchedContentIsReadableByTheAnalyzers(t *testing.T) {
	if DirMode&0o005 != 0o005 {
		t.Errorf("directory mode %#o does not allow other read+execute; the analyzers cannot traverse the content tree", DirMode)
	}
	if FileMode&0o004 != 0o004 {
		t.Errorf("file mode %#o does not allow other read; the analyzers cannot open the rules", FileMode)
	}
	// Nothing here should be writable by anyone but the fetcher.
	if DirMode&0o022 != 0 || FileMode&0o022 != 0 {
		t.Errorf("content is group- or world-writable (dir %#o, file %#o); only the fetcher should write it", DirMode, FileMode)
	}
}
