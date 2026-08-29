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
	"errors"
	"fmt"
	"maps"
	"path"
	"strings"
	"time"
)

// Layer is one resolved content layer.
type Layer struct {
	// Name is LayerUpstream or LayerCustom.
	Name string

	// Files maps content-relative paths to bytes.
	Files map[string][]byte

	// FetchedAt is when an upstream layer was retrieved, reported in status so
	// operators can see content currency (FR-045).
	FetchedAt time.Time

	// Digest is the OCI digest of a custom layer.
	Digest string
}

// Merged is the result of overlaying custom content onto upstream.
type Merged struct {
	Files             map[string][]byte
	UpstreamFetchedAt time.Time
	CustomDigest      string
	CustomApplied     bool
}

// Status is the content summary surfaced through NetworkTap target health.
type Status struct {
	UpstreamFetchedAt time.Time `json:"upstreamFetchedAt,omitempty"`
	CustomDigest      string    `json:"customDigest,omitempty"`
	CustomApplied     bool      `json:"customApplied"`
}

// Status returns the reportable content summary.
func (m Merged) Status() Status {
	return Status{
		UpstreamFetchedAt: m.UpstreamFetchedAt,
		CustomDigest:      m.CustomDigest,
		CustomApplied:     m.CustomApplied,
	}
}

// Merge overlays an optional custom layer onto upstream.
//
// A nil custom layer is the normal FR-043 fallback path, not an error: the
// analyzer starts with upstream-only content and status records that custom
// content was not applied.
func Merge(upstream Layer, custom *Layer) (Merged, error) {
	if len(upstream.Files) == 0 {
		// An empty upstream layer means the fetch produced nothing. Starting an
		// analyzer with no rules looks healthy while detecting nothing, so this
		// fails rather than degrades.
		return Merged{}, errors.New("upstream content layer is empty")
	}
	for name := range upstream.Files {
		if err := validateContentPath(name); err != nil {
			return Merged{}, fmt.Errorf("upstream layer: %w", err)
		}
	}

	files := make(map[string][]byte, len(upstream.Files))
	maps.Copy(files, upstream.Files)

	merged := Merged{Files: files, UpstreamFetchedAt: upstream.FetchedAt}
	if custom == nil || len(custom.Files) == 0 {
		return merged, nil
	}

	// Custom content arrives from a registry, so its paths are untrusted. A
	// path that escapes the content directory could overwrite analyzer
	// binaries or configuration on the shared volume.
	for name := range custom.Files {
		if err := validateContentPath(name); err != nil {
			return Merged{}, fmt.Errorf("custom layer: %w", err)
		}
	}
	maps.Copy(files, custom.Files)

	merged.CustomDigest = custom.Digest
	merged.CustomApplied = true
	return merged, nil
}

// validateContentPath rejects absolute paths and any traversal outside the
// content root.
func validateContentPath(name string) error {
	if name == "" {
		return errors.New("content path is empty")
	}
	if path.IsAbs(name) || strings.HasPrefix(name, "/") {
		return fmt.Errorf("content path %q is absolute", name)
	}
	cleaned := path.Clean(name)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return fmt.Errorf("content path %q escapes the content directory", name)
	}
	return nil
}
