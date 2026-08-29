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

package sanitize

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

// Constitution III: secrets and packet payloads must never appear in logs,
// status fields, metrics, or error messages. Every external boundary routes its
// text through this package, so these cases are the enforcement point.

func TestErrorRedactsCredentialMaterial(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		absent  []string
		present []string
	}{
		{
			name:   "bearer token",
			in:     "request failed: Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IlhZWiJ9.payload.sig",
			absent: []string{"eyJhbGciOiJSUzI1NiIsImtpZCI6IlhZWiJ9", "payload.sig"},
		},
		{
			name:   "service account token in message",
			in:     "token eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzeXN0ZW0ifQ.abcdefghijklmnop rejected",
			absent: []string{"eyJzdWIiOiJzeXN0ZW0ifQ"},
		},
		{
			name:   "presigned url with signature",
			in:     "upload to https://minio.example:9000/trawl-artifacts/a/b.pcapng?X-Amz-Signature=deadbeefcafe&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE failed",
			absent: []string{"X-Amz-Signature=deadbeefcafe", "AKIAIOSFODNN7EXAMPLE", "deadbeefcafe"},
		},
		{
			name:   "query string stripped from any url",
			in:     "GET https://loki.example/loki/api/v1/query_range?query=%7Bjob%3D%22x%22%7D&token=s3cr3t timed out",
			absent: []string{"token=s3cr3t", "s3cr3t"},
		},
		{
			name:   "aws style secret key",
			in:     "storage init: secretKey=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			absent: []string{"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		},
		{
			name:   "password assignment",
			in:     `connect failed: password="hunter2trombone" host=minio`,
			absent: []string{"hunter2trombone"},
		},
		{
			name:    "keeps the actionable part",
			in:      "dial tcp 10.0.0.5:9000: connection refused; Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.aaaa.bbbb",
			absent:  []string{"eyJhbGciOiJIUzI1NiJ9"},
			present: []string{"connection refused"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Error(errors.New(tc.in)).Error()
			for _, s := range tc.absent {
				if strings.Contains(got, s) {
					t.Errorf("sanitized error leaked %q\ngot: %s", s, got)
				}
			}
			for _, s := range tc.present {
				if !strings.Contains(got, s) {
					t.Errorf("sanitized error dropped actionable text %q\ngot: %s", s, got)
				}
			}
		})
	}
}

func TestStringRejectsPacketBytes(t *testing.T) {
	// Raw packet data reaching a log line is the failure this guards. Binary
	// content is replaced wholesale rather than escaped, because escaping still
	// preserves the payload.
	payload := string([]byte{0x00, 0x1f, 0x8b, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x7f})
	got := String("captured frame: " + payload)

	if strings.ContainsAny(got, "\x00\x1f\x7f") {
		t.Errorf("sanitized string retained control bytes: %q", got)
	}
	if !utf8.ValidString(got) {
		t.Errorf("sanitized string is not valid UTF-8: %q", got)
	}
	if strings.Contains(got, "\xde\xad\xbe\xef") {
		t.Errorf("sanitized string retained packet bytes: %q", got)
	}
}

func TestStringIsBounded(t *testing.T) {
	// Conditions cap messages at 512 bytes (contracts/telemetry.md). An
	// unbounded dependency response must not be able to blow past that.
	got := String(strings.Repeat("a", 4096))
	if len(got) > MaxMessageBytes {
		t.Errorf("sanitized string is %d bytes, want <= %d", len(got), MaxMessageBytes)
	}
	if !strings.HasSuffix(got, Truncated) {
		t.Errorf("truncated string must be marked with %q, got tail %q", Truncated, got[len(got)-20:])
	}
}

func TestStringTruncationKeepsValidUTF8(t *testing.T) {
	// Truncating mid-rune would produce invalid UTF-8 in a status field.
	got := String(strings.Repeat("é", MaxMessageBytes))
	if !utf8.ValidString(got) {
		t.Errorf("truncation split a multi-byte rune: %q", got)
	}
	if len(got) > MaxMessageBytes {
		t.Errorf("got %d bytes, want <= %d", len(got), MaxMessageBytes)
	}
}

func TestErrorPreservesNil(t *testing.T) {
	if got := Error(nil); got != nil {
		t.Errorf("Error(nil) = %v, want nil", got)
	}
}

func TestErrorUnwrapsToSanitizedOnly(t *testing.T) {
	// Wrapping must not leave the original message reachable via %+v or Unwrap,
	// or the redaction is cosmetic.
	secret := "AKIAIOSFODNN7EXAMPLE"
	wrapped := fmt.Errorf("outer: %w", errors.New("inner secretKey="+secret))
	got := Error(wrapped)

	if strings.Contains(fmt.Sprintf("%v", got), secret) {
		t.Errorf("%%v leaked secret: %v", got)
	}
	if strings.Contains(fmt.Sprintf("%+v", got), secret) {
		t.Errorf("%%+v leaked secret: %+v", got)
	}
	if inner := errors.Unwrap(got); inner != nil && strings.Contains(inner.Error(), secret) {
		t.Errorf("Unwrap leaked secret: %v", inner)
	}
}

func TestFieldsRedactsByKeyName(t *testing.T) {
	// Structured logging takes key-value pairs; a sensitive key must be redacted
	// regardless of whether its value looks like a secret.
	in := map[string]string{
		"tap_name":      "mirror-0",
		"password":      "correct horse",
		"authorization": "Bearer abc",
		"secret_key":    "xyz",
		"token":         "t",
		"presigned_url": "https://x/y?sig=1",
		"error":         "connection refused",
	}
	got := Fields(in)

	for _, k := range []string{"password", "authorization", "secret_key", "token", "presigned_url"} {
		if got[k] != Redacted {
			t.Errorf("field %q = %q, want %q", k, got[k], Redacted)
		}
	}
	if got["tap_name"] != "mirror-0" {
		t.Errorf("field tap_name was altered: %q", got["tap_name"])
	}
	if got["error"] != "connection refused" {
		t.Errorf("field error was altered: %q", got["error"])
	}
}

func TestDiagnosticHashIsStableAndNonReversible(t *testing.T) {
	// Malformed analyzer records are reported by fingerprint, never by content
	// (plan.md "Observation processing").
	record := `{"alert":{"signature":"secret internal rule name"},"payload":"AAAA"}`

	h1, h2 := DiagnosticHash(record), DiagnosticHash(record)
	if h1 != h2 {
		t.Errorf("DiagnosticHash is not stable: %q vs %q", h1, h2)
	}
	if h1 == DiagnosticHash(record+" ") {
		t.Error("DiagnosticHash collided on differing input")
	}
	if strings.Contains(h1, "secret") || strings.Contains(h1, "AAAA") {
		t.Errorf("DiagnosticHash leaked content: %q", h1)
	}
	if len(h1) != DiagnosticHashLen {
		t.Errorf("DiagnosticHash length = %d, want %d", len(h1), DiagnosticHashLen)
	}
}

// FuzzStringNeverLeaksControlBytesOrExceedsBound asserts the two invariants that
// must hold for arbitrary dependency output, not just the cases above.
func FuzzStringNeverLeaksControlBytesOrExceedsBound(f *testing.F) {
	f.Add("plain message")
	f.Add("Bearer eyJhbGciOiJIUzI1NiJ9.a.b")
	f.Add(string([]byte{0x00, 0xff, 0xfe}))
	f.Add(strings.Repeat("x", 5000))
	f.Add("https://h/p?X-Amz-Signature=a&b=c")

	f.Fuzz(func(t *testing.T, in string) {
		got := String(in)

		if len(got) > MaxMessageBytes {
			t.Fatalf("length %d exceeds bound %d", len(got), MaxMessageBytes)
		}
		if !utf8.ValidString(got) {
			t.Fatalf("produced invalid UTF-8 from %q", in)
		}
		for _, r := range got {
			if r < 0x20 && r != '\t' || r == 0x7f {
				t.Fatalf("retained control byte %q from input %q", r, in)
			}
		}
	})
}
