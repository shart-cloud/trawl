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

package capture

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// pcapng builds a minimal file: one section header, one interface, and the
// given packet blocks. bigEndian selects the section byte order.
func pcapng(bigEndian bool, packets ...[]byte) []byte {
	var order binary.ByteOrder = binary.LittleEndian
	if bigEndian {
		order = binary.BigEndian
	}
	var out bytes.Buffer
	block := func(typ uint32, body []byte) {
		for len(body)%4 != 0 {
			body = append(body, 0)
		}
		total := uint32(12 + len(body)) //nolint:gosec // Test data is small.
		_ = binary.Write(&out, order, typ)
		_ = binary.Write(&out, order, total)
		out.Write(body)
		_ = binary.Write(&out, order, total)
	}
	shb := make([]byte, 16)
	order.PutUint32(shb[0:], 0x1A2B3C4D)
	order.PutUint16(shb[4:], 1)
	order.PutUint16(shb[6:], 0)
	order.PutUint64(shb[8:], 0xFFFFFFFFFFFFFFFF)
	block(0x0A0D0D0A, shb)
	idb := make([]byte, 8)
	order.PutUint16(idb[0:], 1) // LINKTYPE_ETHERNET
	order.PutUint32(idb[4:], 262144)
	block(1, idb)
	for _, p := range packets {
		body := make([]byte, 20+len(p))
		order.PutUint32(body[12:], uint32(len(p))) //nolint:gosec // Test data is small.
		order.PutUint32(body[16:], uint32(len(p))) //nolint:gosec // Test data is small.
		copy(body[20:], p)
		block(6, body)
	}
	return out.Bytes()
}

func TestCountAndHashWalksBlocks(t *testing.T) {
	for _, be := range []bool{false, true} {
		data := pcapng(be, []byte("abc"), []byte("defgh"), make([]byte, 1500))
		n, size, sum, err := CountAndHash(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("bigEndian=%v: %v", be, err)
		}
		want := sha256.Sum256(data)
		if n != 3 || size != int64(len(data)) || sum != hex.EncodeToString(want[:]) {
			t.Errorf("bigEndian=%v: packets=%d size=%d sum=%s", be, n, size, sum)
		}
	}
}

func TestCountAndHashCountsSimplePacketBlocks(t *testing.T) {
	data := pcapng(false)
	body := make([]byte, 4+8)
	binary.LittleEndian.PutUint32(body, 8)
	data = append(data, 3, 0, 0, 0, 24, 0, 0, 0)
	data = append(data, body...)
	data = append(data, 24, 0, 0, 0)
	n, _, _, err := CountAndHash(bytes.NewReader(data))
	if err != nil || n != 1 {
		t.Fatalf("packets=%d err=%v", n, err)
	}
}

func TestCountAndHashAcceptsZeroPackets(t *testing.T) {
	n, size, sum, err := CountAndHash(bytes.NewReader(pcapng(false)))
	if err != nil || n != 0 || size == 0 || len(sum) != 64 {
		t.Fatalf("packets=%d size=%d sum=%s err=%v", n, size, sum, err)
	}
}

func TestCountAndHashRejectsMalformedFiles(t *testing.T) {
	good := pcapng(false, []byte("abc"))
	cases := map[string][]byte{
		"empty":            {},
		"not pcapng":       []byte("\xd4\xc3\xb2\xa1 classic pcap header......."),
		"truncated block":  good[:len(good)-4],
		"bad trailer":      append(append([]byte{}, good[:len(good)-4]...), 9, 9, 9, 9),
		"undersized block": append(append([]byte{}, good...), 6, 0, 0, 0, 8, 0, 0, 0),
	}
	for name, data := range cases {
		if _, _, _, err := CountAndHash(bytes.NewReader(data)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestKeysAreNamespacedByUID(t *testing.T) {
	if got := ObjectKey("trawl-system", "u-1"); got != "captures/trawl-system/u-1/capture.pcapng" {
		t.Errorf("ObjectKey = %q", got)
	}
	if got := ManifestKey("trawl-system", "u-1"); got != "captures/trawl-system/u-1/manifest.json" {
		t.Errorf("ManifestKey = %q", got)
	}
}

func TestManifestRoundTripAndVerification(t *testing.T) {
	m := &Manifest{
		SchemaVersion: ManifestSchemaVersion, CaptureJobUID: "u-1", Namespace: "trawl-system", Name: "manual-tls",
		Interface: "eth0", StartedAt: time.Unix(100, 0).UTC(), EndedAt: time.Unix(160, 0).UTC(),
		StopReason: "Duration", PacketCount: 3, SizeBytes: 4096, SHA256: strings.Repeat("ab", 32),
	}
	raw, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if *back != *m {
		t.Errorf("round trip changed the manifest:\n%+v\n%+v", m, back)
	}

	meta := map[string]string{MetadataSHA256: m.SHA256, MetadataCaptureJobUID: "u-1"}
	if err := VerifyArtifact(back, "u-1", 4096, meta); err != nil {
		t.Errorf("matching artifact rejected: %v", err)
	}
	bad := map[string]struct {
		uid  string
		size int64
		meta map[string]string
	}{
		"size":        {"u-1", 4095, meta},
		"uid":         {"u-2", 4096, meta},
		"sha":         {"u-1", 4096, map[string]string{MetadataSHA256: strings.Repeat("cd", 32)}},
		"no sha":      {"u-1", 4096, map[string]string{}},
		"foreign uid": {"u-1", 4096, map[string]string{MetadataSHA256: m.SHA256, MetadataCaptureJobUID: "u-9"}},
	}
	for name, c := range bad {
		if err := VerifyArtifact(back, c.uid, c.size, c.meta); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseManifestRejectsBadInput(t *testing.T) {
	head := `{"schemaVersion":"` + ManifestSchemaVersion + `","captureJobUID":"u","sha256":"` + strings.Repeat("ab", 32) + `"`
	cases := map[string][]byte{
		"garbage":       []byte("{"),
		"wrong schema":  []byte(`{"schemaVersion":"other/v1","captureJobUID":"u","sha256":"` + strings.Repeat("ab", 32) + `"}`),
		"short sha":     []byte(`{"schemaVersion":"` + ManifestSchemaVersion + `","captureJobUID":"u","sha256":"abcd"}`),
		"upper sha":     []byte(`{"schemaVersion":"` + ManifestSchemaVersion + `","captureJobUID":"u","sha256":"` + strings.Repeat("AB", 32) + `"}`),
		"negative size": []byte(head + `,"sizeBytes":-1}`),
		"oversized":     []byte(head + `,"filter":"` + strings.Repeat("x", MaxManifestBytes) + `"}`),
	}
	for name, raw := range cases {
		if _, err := ParseManifest(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseManifestSanitizesStrings(t *testing.T) {
	// The JSON escape decodes to an ESC byte; the parser must strip it.
	raw := []byte(`{"schemaVersion":"` + ManifestSchemaVersion + `","captureJobUID":"u","sha256":"` +
		strings.Repeat("ab", 32) + `","interface":"eth0\u001b[31m"}`)
	m, err := ParseManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(m.Interface, 0x1b) {
		t.Errorf("control byte survived: %q", m.Interface)
	}
}
