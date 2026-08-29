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

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// idLen is the hex length of a record ID.
const idLen = 32

// recordID derives a stable identifier for one observation.
//
// It is content-derived rather than random so that the same analyzer record,
// re-read after a sensor restart mid-file, produces the same ID and can be
// collapsed downstream. A random UUID would turn every restart into a burst of
// apparently new observations.
func recordID(kind SourceKind, correlator string, discriminator int64, eventTime time.Time) string {
	h := sha256.New()
	// Length-prefixed so field boundaries cannot be forged by content that
	// happens to contain the separator.
	for _, part := range []string{string(kind), correlator} {
		_, _ = fmt.Fprintf(h, "%d:%s", len(part), part)
	}
	_, _ = fmt.Fprintf(h, "%d|%d", discriminator, eventTime.UTC().UnixNano())
	return hex.EncodeToString(h.Sum(nil))[:idLen]
}

// recordIDFromParts derives an ID from arbitrary string components, for sources
// whose natural key is not a numeric rule ID.
func recordIDFromParts(kind SourceKind, eventTime time.Time, parts ...string) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%d:%s", len(string(kind)), string(kind))
	for _, part := range parts {
		_, _ = fmt.Fprintf(h, "%d:%s", len(part), part)
	}
	_, _ = fmt.Fprintf(h, "|%d", eventTime.UTC().UnixNano())
	return hex.EncodeToString(h.Sum(nil))[:idLen]
}
