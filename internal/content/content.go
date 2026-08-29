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

// Package content models Trawl's two-layer analyzer content (ADR-0005):
// upstream detection rules and scripts fetched at pod startup, optionally
// overlaid with site-specific content pulled from a versioned OCI artifact.
//
// This package holds the reference parsing, merge ordering, and status
// reporting that both init containers and the NetworkTap controller depend on.
// The fetch and OCI pull themselves land with the init container implementation.
//
// Two rules here are load-bearing:
//
//   - Custom content overlays upstream, never the reverse. If upstream won, a
//     site could never suppress a noisy upstream rule.
//   - A missing or corrupt custom layer degrades to upstream-only rather than
//     failing the pod. A detection gap is bad; a monitoring outage is worse
//     (FR-043).
package content

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Layer names.
const (
	LayerUpstream = "upstream"
	LayerCustom   = "custom"
)

// digestRE matches an OCI content digest. Lowercase hex only: a digest is
// compared byte-wise, and accepting mixed case would let two spellings of one
// digest look like different versions.
var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Reference is a digest-pinned OCI artifact reference.
type Reference struct {
	Repository string
	Digest     string
}

// String renders the canonical repository@digest form.
func (r Reference) String() string { return r.Repository + "@" + r.Digest }

// ParseReference parses a digest-pinned OCI reference.
//
// Tags are rejected outright (FR-042). A tag can be repointed after the rule
// review that approved its content, so it cannot identify what a sensor is
// actually running.
func ParseReference(s string) (Reference, error) {
	if s == "" {
		return Reference{}, errors.New("content reference is empty")
	}
	repo, digest, found := strings.Cut(s, "@")
	if !found {
		return Reference{}, fmt.Errorf("content reference %q must be digest-pinned (repository@sha256:...)", s)
	}
	if repo == "" {
		return Reference{}, errors.New("content reference has no repository")
	}
	if !digestRE.MatchString(digest) {
		return Reference{}, fmt.Errorf("content reference %q does not carry a valid sha256 digest", s)
	}
	return Reference{Repository: repo, Digest: digest}, nil
}

// ValidateFeedURL checks an upstream feed URL.
//
// HTTPS only. The init container executes what it downloads as detection logic,
// so an unauthenticated transport would let a network position replace it.
func ValidateFeedURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return errors.New("feed URL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("feed URL is not a valid URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("feed URL scheme %q is not https", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("feed URL has no host")
	}
	return nil
}
