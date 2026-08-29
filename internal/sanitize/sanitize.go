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

// Package sanitize bounds and redacts text before it crosses an external
// boundary: a log line, a Kubernetes condition message, an Event, a metric
// exemplar, or an audit record.
//
// The constitution forbids secrets and packet payloads from appearing in any of
// those places. Dependency errors are the main way they leak — an S3 client
// error carries the presigned URL, a Kubernetes client error carries the bearer
// token, an analyzer parse error carries the record that failed. Rather than
// audit every call site, every boundary routes through here.
//
// The redaction is deliberately aggressive. Losing a detail from an error
// message costs an operator one debugging step; leaking a credential into Loki
// costs a credential rotation.
package sanitize

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	// MaxMessageBytes bounds any sanitized string. Kubernetes conditions cap
	// messages at 512 bytes (contracts/telemetry.md), and that is the tightest
	// consumer, so it sets the bound for all of them.
	MaxMessageBytes = 512

	// Truncated marks a string that was cut, so a reader can tell a short
	// message from a clipped one.
	Truncated = "…[truncated]"

	// Redacted replaces a value that was removed.
	Redacted = "[redacted]"

	// DiagnosticHashLen is the hex length of a diagnostic fingerprint. Sixteen
	// hex characters is enough to distinguish malformed-record shapes in a
	// bounded window without being a useful lookup key for content.
	DiagnosticHashLen = 16
)

// Patterns that identify credential material anywhere in a string. Each is
// anchored on the token shape rather than a field name, because dependency
// errors rarely label what they are leaking.
var redactPatterns = []*regexp.Regexp{
	// JWTs and Kubernetes service-account tokens: three base64url segments.
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+`),
	// Authorization headers of any scheme.
	regexp.MustCompile(`(?i)\bauthorization\s*[:=]\s*\S+`),
	regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+`),
	// AWS/MinIO access key IDs.
	regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
	// Assignments to a sensitive-looking key, quoted or bare.
	regexp.MustCompile(`(?i)\b(secret[_-]?key|access[_-]?key|secret|password|passwd|token|api[_-]?key|credential)s?\s*[:=]\s*("[^"]*"|'[^']*'|\S+)`),
	// Any URL query string. Presigned URLs put the signature there, and no
	// query string is worth the risk of keeping.
	regexp.MustCompile(`(\bhttps?://[^\s?]+)\?\S*`),
	// PEM blocks.
	regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`),
}

// Field names whose values are always removed, independent of their content.
//
// nolint:goconst // set-membership keys; naming each as a constant would
// obscure the list without making it safer.
var sensitiveFieldNames = map[string]struct{}{
	"authorization": {}, "password": {}, "passwd": {}, "secret": {},
	"secret_key": {}, "secretkey": {}, "access_key": {}, "accesskey": {},
	"token": {}, "bearer_token": {}, "api_key": {}, "apikey": {},
	"credential": {}, "credentials": {}, "presigned_url": {}, "presignedurl": {},
	"private_key": {}, "privatekey": {}, "session_key": {}, "payload": {},
}

// String redacts, strips control characters from, and bounds s.
//
// The result is always valid UTF-8, free of control bytes other than tab, and
// no longer than MaxMessageBytes — the properties a condition message, log
// value, or audit field must satisfy.
func String(s string) string {
	for _, re := range redactPatterns {
		s = re.ReplaceAllString(s, redactionFor(re))
	}
	s = stripControl(s)
	s = strings.TrimSpace(s)
	return bound(s)
}

// redactionFor keeps the non-secret prefix where a pattern has one, so the
// reader still learns which endpoint or key was involved.
func redactionFor(re *regexp.Regexp) string {
	switch re.NumSubexp() {
	case 0:
		return Redacted
	case 1:
		// Single capture is the part worth keeping (a URL without its query,
		// or the scheme keyword).
		return "$1" + Redacted
	default:
		return "$1=" + Redacted
	}
}

// stripControl removes control bytes and replaces invalid UTF-8. Packet payload
// reaching a message is the case this exists for: it is binary, so it is
// dropped rather than escaped.
func stripControl(s string) string {
	if utf8.ValidString(s) && !strings.ContainsFunc(s, isControl) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == utf8.RuneError:
			// Invalid byte sequence; drop it rather than emit U+FFFD runs.
			continue
		case r == '\t' || r == ' ':
			b.WriteRune(r)
		case isControl(r):
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isControl(r rune) bool {
	return r < 0x20 && r != '\t' || r == 0x7f
}

// bound truncates on a rune boundary so the result stays valid UTF-8.
func bound(s string) string {
	if len(s) <= MaxMessageBytes {
		return s
	}
	limit := MaxMessageBytes - len(Truncated)
	for limit > 0 && !utf8.RuneStart(s[limit]) {
		limit--
	}
	return s[:limit] + Truncated
}

// sanitizedError is an error whose message has been redacted. It deliberately
// does not implement Unwrap: keeping the original reachable would let %+v or an
// errors.As target recover the very text that was removed.
type sanitizedError struct{ msg string }

func (e *sanitizedError) Error() string { return e.msg }

// Error returns err with its message redacted and bounded, or nil if err is nil.
//
// The original error is dropped rather than wrapped. That loses errors.Is/As
// matching, which is the intended trade at a boundary: callers that need to
// branch on an error must do so before sanitizing.
func Error(err error) error {
	if err == nil {
		return nil
	}
	return &sanitizedError{msg: String(err.Error())}
}

// Errorf formats and sanitizes in one step. Arguments are sanitized as well, so
// interpolating a dependency error cannot reintroduce what Error removed.
func Errorf(format string, args ...any) error {
	safe := make([]any, len(args))
	for i, a := range args {
		switch v := a.(type) {
		case error:
			safe[i] = Error(v)
		case string:
			safe[i] = String(v)
		default:
			safe[i] = String(fmt.Sprint(v))
		}
	}
	return &sanitizedError{msg: String(fmt.Sprintf(format, safe...))}
}

// Fields sanitizes a structured logging or audit key-value map. Values under a
// sensitive key name are removed entirely; every other value is sanitized.
func Fields(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		if _, sensitive := sensitiveFieldNames[strings.ToLower(k)]; sensitive {
			out[k] = Redacted
			continue
		}
		out[k] = String(v)
	}
	return out
}

// DiagnosticHash fingerprints content that must be counted but never stored.
//
// A malformed analyzer record is reported by this hash so operators can tell
// "one bad producer repeating" from "many distinct failures" without the record
// itself entering the logs.
func DiagnosticHash(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])[:DiagnosticHashLen]
}
