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

// UnknownVersion is what a record reports when the analyzer's version could not
// be established.
//
// The envelope requires source.version with minLength 1, so an empty string is
// not an option: it fails validation and the record is counted malformed -
// discarded for want of a label about the reader rather than anything wrong
// with what was read. The Hubble path records the same word when the relay
// supplies no version.
const UnknownVersion = "unknown"

// VersionSource reports the analyzer version to stamp on each record.
//
// It is a function rather than a string because the version is not known when
// the normalizer is built. The analyzer writes it from its own entrypoint in a
// container that starts concurrently with the sensor, and the sensor reaches
// its side of that race within milliseconds while the analyzer takes seconds -
// so a string field read at construction latched UnknownVersion for the life of
// the pod, on every record, while the analyzer was reporting its version
// correctly the whole time.
//
// Deferring the read is the whole point; a caller that already knows the
// version says so with StaticVersion.
type VersionSource func() string

// StaticVersion is a version already known at construction time.
func StaticVersion(v string) VersionSource { return func() string { return v } }

// Resolve reads a version source, mapping both "no source" and "nothing yet" to
// UnknownVersion so a record always carries a schema-valid version.
//
// Every consumer goes through this rather than reading the function directly,
// so that one place decides what an unavailable version looks like on the wire.
func (s VersionSource) Resolve() string {
	if s == nil {
		return UnknownVersion
	}
	if v := s(); v != "" {
		return v
	}
	return UnknownVersion
}
