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

package observation

import "testing"

func TestAVersionSourceNeverResolvesToAnEmptyString(t *testing.T) {
	// The envelope requires source.version with minLength 1. A normalizer built
	// without a version, or one whose analyzer has not published its version
	// yet, must still produce a valid record rather than one the tailer counts
	// as malformed.
	var absent VersionSource
	if got := absent.Resolve(); got != UnknownVersion {
		t.Errorf("an absent version source resolved to %q, want %q", got, UnknownVersion)
	}
	if got := StaticVersion("").Resolve(); got != UnknownVersion {
		t.Errorf("an empty version resolved to %q, want %q", got, UnknownVersion)
	}
	if got := StaticVersion("8.0.6").Resolve(); got != "8.0.6" {
		t.Errorf("a known version resolved to %q, want it unchanged", got)
	}
}

func TestAVersionSourceIsReadPerRecord(t *testing.T) {
	// The point of the function type: a normalizer built before the analyzer
	// published its version must pick it up, not latch the value it saw first.
	current := ""
	src := VersionSource(func() string { return current })

	if got := src.Resolve(); got != UnknownVersion {
		t.Errorf("version = %q before the analyzer published one, want %q", got, UnknownVersion)
	}
	current = "zeek version 8.0.10"
	if got := src.Resolve(); got != current {
		t.Errorf("version = %q after the analyzer published one, want %q", got, current)
	}
}
