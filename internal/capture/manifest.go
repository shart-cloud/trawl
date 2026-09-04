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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/sanitize"
)

const (
	// ManifestSchemaVersion identifies the manifest layout.
	ManifestSchemaVersion = "trawl.capture-manifest/v1"

	// MaxManifestBytes bounds what the controller will read back as a manifest.
	MaxManifestBytes = 16 << 10

	// ContentTypePcapng is the artifact's content type.
	ContentTypePcapng = "application/x-pcapng"
	// ContentTypeManifest is the manifest's content type.
	ContentTypeManifest = "application/json"

	// Object metadata keys. Storage lowercases keys, so these already are.
	MetadataSHA256        = "sha256"
	MetadataCaptureJobUID = "capturejob-uid"
	MetadataPacketCount   = "packet-count"
)

// ObjectKey is where the artifact for a capture lives. The UID keeps a
// recreated object with the same name from ever overwriting an earlier
// capture's evidence.
func ObjectKey(namespace, uid string) string {
	return "captures/" + namespace + "/" + uid + "/capture.pcapng"
}

// ManifestKey is where the manifest for a capture lives.
func ManifestKey(namespace, uid string) string {
	return "captures/" + namespace + "/" + uid + "/manifest.json"
}

// Manifest is the small object stored beside the artifact. It carries what
// the controller needs to verify the object and populate status, and nothing
// a requester could not already see: no credentials, no packet bytes.
type Manifest struct {
	SchemaVersion string `json:"schemaVersion"`
	CaptureJobUID string `json:"captureJobUID"`
	Namespace     string `json:"namespace"`
	Name          string `json:"name"`

	Interface string `json:"interface"`
	Filter    string `json:"filter,omitempty"`
	Snaplen   int32  `json:"snaplen,omitempty"`

	RequestedDuration string    `json:"requestedDuration"`
	RequestedMaxSize  int64     `json:"requestedMaxSizeBytes"`
	StartedAt         time.Time `json:"startedAt"`
	EndedAt           time.Time `json:"endedAt"`

	StopReason  trawlv1alpha1.CaptureStopReason `json:"stopReason"`
	PacketCount int64                           `json:"packetCount"`
	SizeBytes   int64                           `json:"sizeBytes"`
	SHA256      string                          `json:"sha256"`

	DumpcapVersion string `json:"dumpcapVersion,omitempty"`
	RunnerVersion  string `json:"runnerVersion,omitempty"`
}

// Marshal encodes the manifest for storage.
func (m *Manifest) Marshal() ([]byte, error) {
	return json.Marshal(m)
}

// ParseManifest decodes a manifest read back from storage. The bytes came
// from the artifact bucket, which a compromised runner could write, so the
// decode is bounded and every string is sanitized before it can reach status.
func ParseManifest(raw []byte) (*Manifest, error) {
	if len(raw) > MaxManifestBytes {
		return nil, fmt.Errorf("manifest: larger than %d bytes", MaxManifestBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, errors.New("manifest: not valid JSON for the manifest schema")
	}
	if m.SchemaVersion != ManifestSchemaVersion {
		return nil, errors.New("manifest: unsupported schema version")
	}
	if !isSHA256Hex(m.SHA256) {
		return nil, errors.New("manifest: sha256 is not 64 lowercase hex digits")
	}
	if m.SizeBytes < 0 || m.PacketCount < 0 || m.Snaplen < 0 || m.RequestedMaxSize < 0 {
		return nil, errors.New("manifest: negative counter")
	}
	for _, s := range []*string{
		&m.CaptureJobUID, &m.Namespace, &m.Name, &m.Interface, &m.Filter,
		&m.RequestedDuration, &m.DumpcapVersion, &m.RunnerVersion,
	} {
		*s = sanitize.String(*s)
	}
	m.StopReason = trawlv1alpha1.CaptureStopReason(sanitize.String(string(m.StopReason)))
	return &m, nil
}

// VerifyArtifact checks the stored object against its manifest and against
// the capture the controller believes it belongs to. The object's size and
// checksum metadata were written by the runner in the same conditional PUT as
// the bytes, so agreement between them and the manifest is the integrity
// check; the manifest alone proves nothing.
func VerifyArtifact(m *Manifest, captureJobUID string, size int64, metadata map[string]string) error {
	if m.CaptureJobUID != captureJobUID {
		return errors.New("manifest belongs to a different capture")
	}
	if uid, ok := metadata[MetadataCaptureJobUID]; ok && uid != captureJobUID {
		return errors.New("object belongs to a different capture")
	}
	if size != m.SizeBytes {
		return fmt.Errorf("object size %d does not match manifest size %d", size, m.SizeBytes)
	}
	sum, ok := metadata[MetadataSHA256]
	if !ok {
		return errors.New("object carries no checksum metadata")
	}
	if sum != m.SHA256 {
		return errors.New("object checksum does not match manifest")
	}
	return nil
}

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// pcapng block types.
const (
	blockSectionHeader  = 0x0A0D0D0A
	blockPacketObsolete = 0x00000002
	blockSimplePacket   = 0x00000003
	blockEnhancedPacket = 0x00000006

	byteOrderMagic = 0x1A2B3C4D
	minBlockLength = 12
)

// CountAndHash walks a pcapng stream once, counting packet blocks and hashing
// every byte. The count comes from the file rather than from dumpcap's
// stderr, so what status reports is what the artifact contains.
//
// The walk validates block framing; a truncated or corrupt file is an error,
// not a short count.
func CountAndHash(r io.Reader) (packets, size int64, sha256Hex string, err error) {
	h := sha256.New()
	tee := io.TeeReader(r, h)
	var order binary.ByteOrder
	var hdr [8]byte
	var trailer [4]byte

	for {
		n, rerr := io.ReadFull(tee, hdr[:])
		if rerr == io.EOF && n == 0 {
			break
		}
		if rerr != nil {
			return 0, 0, "", errors.New("pcapng: truncated block header")
		}
		size += 8

		typ := binary.LittleEndian.Uint32(hdr[0:4])
		if typ == blockSectionHeader {
			// The section header's byte-order magic decides how the rest of
			// the section is read; each new section may switch.
			var magic [4]byte
			if _, rerr := io.ReadFull(tee, magic[:]); rerr != nil {
				return 0, 0, "", errors.New("pcapng: truncated section header")
			}
			size += 4
			switch {
			case binary.LittleEndian.Uint32(magic[:]) == byteOrderMagic:
				order = binary.LittleEndian
			case binary.BigEndian.Uint32(magic[:]) == byteOrderMagic:
				order = binary.BigEndian
			default:
				return 0, 0, "", errors.New("pcapng: bad byte-order magic")
			}
			total := order.Uint32(hdr[4:8])
			if total < minBlockLength+4 || total%4 != 0 {
				return 0, 0, "", errors.New("pcapng: bad section header length")
			}
			rest := int64(total) - 16
			if _, rerr := io.CopyN(io.Discard, tee, rest); rerr != nil {
				return 0, 0, "", errors.New("pcapng: truncated section header")
			}
			size += rest
			if terr := checkTrailer(tee, order, total, trailer[:]); terr != nil {
				return 0, 0, "", terr
			}
			size += 4
			continue
		}
		if order == nil {
			return 0, 0, "", errors.New("pcapng: stream does not start with a section header")
		}
		typ = order.Uint32(hdr[0:4])
		total := order.Uint32(hdr[4:8])
		if total < minBlockLength || total%4 != 0 {
			return 0, 0, "", errors.New("pcapng: bad block length")
		}
		body := int64(total) - minBlockLength
		if _, rerr := io.CopyN(io.Discard, tee, body); rerr != nil {
			return 0, 0, "", errors.New("pcapng: truncated block")
		}
		size += body
		if terr := checkTrailer(tee, order, total, trailer[:]); terr != nil {
			return 0, 0, "", terr
		}
		size += 4
		switch typ {
		case blockEnhancedPacket, blockSimplePacket, blockPacketObsolete:
			packets++
		}
	}
	if order == nil {
		return 0, 0, "", errors.New("pcapng: empty stream")
	}
	return packets, size, hex.EncodeToString(h.Sum(nil)), nil
}

func checkTrailer(r io.Reader, order binary.ByteOrder, total uint32, buf []byte) error {
	if _, err := io.ReadFull(r, buf); err != nil {
		return errors.New("pcapng: truncated block trailer")
	}
	if order.Uint32(buf) != total {
		return errors.New("pcapng: block trailer does not match header")
	}
	return nil
}

func metaTime(t time.Time) metav1.Time { return metav1.Time{Time: t} }
