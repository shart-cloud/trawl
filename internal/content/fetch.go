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
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"trawl.cloud/trawl/internal/sanitize"
)

// Content is public upstream detection rules, not a secret, and the analyzers
// that must read it run as root with every capability dropped - so they have
// no CAP_DAC_OVERRIDE and the permission bits are enforced against them like
// anyone else. Written by UID 65532 at 0750/0600, the directories were
// unreadable to the analyzers: Suricata reported "no rules were loaded" and
// the fetched Zeek packages could not be opened either. The content is
// world-readable so the readers can actually read it; nothing here is
// sensitive, and the write side stays owned by the fetcher.
const (
	DirMode  = 0o755
	FileMode = 0o644
)

// Fetcher retrieves one content layer.
//
// Upstream feeds and OCI artifacts are fetched by external tooling
// (suricata-update, git, oras) inside the content-init image, so this interface
// is what the init command drives and what tests substitute.
type Fetcher interface {
	// Fetch retrieves a layer into dir, returning what was resolved.
	Fetch(ctx context.Context, dir string) (Layer, error)
}

// Resolver produces the merged content an analyzer will read.
//
// The asymmetry between the two layers is the whole point (FR-043): an upstream
// failure is fatal, because an analyzer with no rules looks healthy while
// detecting nothing, whereas a custom failure degrades to upstream-only,
// because a detection gap is bad but a monitoring outage is worse.
type Resolver struct {
	// Upstream fetches vendor rules and scripts. Required.
	Upstream Fetcher

	// Custom fetches the optional site-specific overlay. Nil means
	// upstream-only, which is the normal case.
	Custom Fetcher

	// OnCustomFailure is called when the custom layer could not be applied, so
	// the degradation is reported rather than silently absorbed.
	OnCustomFailure func(err error)
}

// Resolve fetches both layers and merges them.
func (r *Resolver) Resolve(ctx context.Context, dir string) (Merged, error) {
	if r.Upstream == nil {
		return Merged{}, errors.New("no upstream content fetcher configured")
	}

	upstream, err := r.Upstream.Fetch(ctx, dir)
	if err != nil {
		// Fatal. Starting an analyzer with no rules is the worse failure: it
		// looks healthy while detecting nothing.
		return Merged{}, sanitize.Errorf("fetching upstream content: %v", err)
	}
	if upstream.FetchedAt.IsZero() {
		upstream.FetchedAt = time.Now().UTC()
	}

	if r.Custom == nil {
		return Merge(upstream, nil)
	}

	custom, err := r.Custom.Fetch(ctx, dir)
	if err != nil {
		// Degraded, not fatal. The analyzer starts on upstream content and the
		// failure surfaces through status.
		r.reportCustomFailure(sanitize.Errorf("fetching custom content: %v", err))
		return Merge(upstream, nil)
	}

	merged, err := Merge(upstream, &custom)
	if err != nil {
		// A corrupt overlay - bad paths, empty payload - is treated the same
		// way as a failed pull, for the same reason.
		r.reportCustomFailure(sanitize.Errorf("merging custom content: %v", err))
		return Merge(upstream, nil)
	}
	return merged, nil
}

func (r *Resolver) reportCustomFailure(err error) {
	if r.OnCustomFailure != nil {
		r.OnCustomFailure(err)
	}
}

// Write materializes merged content into dir.
//
// Files are written to a staging directory and moved into place, so an analyzer
// starting concurrently never observes a half-written ruleset. Content is only
// read at startup, so there is no live-reload path that could see the swap.
func Write(merged Merged, dir string) error {
	staging := dir + ".staging"
	if err := os.RemoveAll(staging); err != nil {
		return sanitize.Errorf("clearing content staging directory: %v", err)
	}
	//nolint:gosec // G301: see DirMode below.
	if err := os.MkdirAll(staging, DirMode); err != nil {
		return sanitize.Errorf("creating content staging directory: %v", err)
	}

	for name, body := range merged.Files {
		// Re-checked here as well as in Merge: this is the last point before
		// bytes hit the filesystem, and the cost of being wrong is writing
		// outside the content directory.
		if err := validateContentPath(name); err != nil {
			return err
		}
		target := filepath.Join(staging, name)
		//nolint:gosec // G301: see DirMode.
		if err := os.MkdirAll(filepath.Dir(target), DirMode); err != nil {
			return sanitize.Errorf("creating content directory: %v", err)
		}
		// 0600: the init container writes as uid 65532 and the analyzer reads
		// as uid 0, which is unaffected by the mode. Nothing else in the pod
		// needs these bytes, so no group or world access is granted.
		//nolint:gosec // G306: see FileMode.
		if err := os.WriteFile(target, body, FileMode); err != nil {
			return sanitize.Errorf("writing content file: %v", err)
		}
	}

	previous := dir + ".previous"
	_ = os.RemoveAll(previous)
	if err := os.Rename(dir, previous); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return sanitize.Errorf("rotating previous content: %v", err)
	}
	if err := os.Rename(staging, dir); err != nil {
		// Put the previous content back rather than leaving the analyzer with
		// nothing at all.
		_ = os.Rename(previous, dir)
		return sanitize.Errorf("installing content: %v", err)
	}
	_ = os.RemoveAll(previous)
	return nil
}

// Read loads a content layer from a directory.
func Read(dir string) (map[string][]byte, error) {
	files := make(map[string][]byte)

	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(dir, p)
		if relErr != nil {
			return relErr
		}
		if err := validateContentPath(rel); err != nil {
			return err
		}
		//nolint:gosec // p comes from WalkDir over the operator-configured dir
		body, readErr := os.ReadFile(p)
		if readErr != nil {
			return readErr
		}
		files[rel] = body
		return nil
	})
	if err != nil {
		return nil, sanitize.Errorf("reading content directory: %v", err)
	}
	return files, nil
}

// StatusFile is where the init container records what it resolved, so the
// sensor can report content currency without re-reading the whole tree.
const StatusFile = ".trawl-content-status.json"

// WriteStatus records the resolved content status beside the content.
func WriteStatus(dir string, st Status) error {
	data, err := marshalStatus(st)
	if err != nil {
		return err
	}
	//nolint:gosec // G306: see FileMode.
	if err := os.WriteFile(filepath.Join(dir, StatusFile), data, FileMode); err != nil {
		return sanitize.Errorf("writing content status: %v", err)
	}
	return nil
}

// ReadStatus loads the status the init container recorded.
func ReadStatus(dir string) (Status, error) {
	//nolint:gosec // dir is the operator-configured content mount
	data, err := os.ReadFile(filepath.Join(dir, StatusFile))
	if err != nil {
		return Status{}, sanitize.Errorf("reading content status: %v", err)
	}
	return unmarshalStatus(data)
}

func marshalStatus(st Status) ([]byte, error) {
	data, err := json.Marshal(st)
	if err != nil {
		return nil, sanitize.Errorf("encoding content status: %v", err)
	}
	return data, nil
}

func unmarshalStatus(data []byte) (Status, error) {
	var st Status
	if err := json.Unmarshal(data, &st); err != nil {
		return Status{}, sanitize.Errorf("decoding content status: %v", err)
	}
	return st, nil
}
