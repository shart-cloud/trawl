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
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

// ZeekLogType names a Zeek log stream. It selects which normalizer applies,
// since Zeek's JSON is one shape per log file rather than a tagged union.
type ZeekLogType string

const (
	ZeekConn   ZeekLogType = "conn"
	ZeekDNS    ZeekLogType = "dns"
	ZeekHTTP   ZeekLogType = "http"
	ZeekSSL    ZeekLogType = "ssl"
	ZeekX509   ZeekLogType = "x509"
	ZeekFiles  ZeekLogType = "files"
	ZeekNotice ZeekLogType = "notice"
	ZeekWeird  ZeekLogType = "weird"
)

// zeekBase is the envelope Zeek shares across log types.
//
// As with EVE, only named fields are decoded. Zeek logs can be configured to
// carry post-body content and cookies, and a generic map would make it easy for
// those to reach a stored record.
type zeekBase struct {
	TS          float64 `json:"ts"`
	UID         string  `json:"uid"`
	CommunityID string  `json:"community_id"`

	SourceIP   string `json:"id.orig_h"`
	SourcePort *int32 `json:"id.orig_p"`
	DestIP     string `json:"id.resp_h"`
	DestPort   *int32 `json:"id.resp_p"`
	Proto      string `json:"proto"`
}

// ZeekNormalizer converts Zeek JSON log lines into normalized observations.
type ZeekNormalizer struct {
	// Version is read per record, because the analyzer publishes it after the
	// sensor starts.
	Version VersionSource
	Tap     *Tap
	Target  Target
	Now     func() time.Time
}

// Normalize converts one Zeek JSON line from the named log.
func (n *ZeekNormalizer) Normalize(logType ZeekLogType, line []byte) (*Observation, error) {
	var base zeekBase
	if err := json.Unmarshal(line, &base); err != nil {
		return nil, errors.New("malformed Zeek record: invalid JSON")
	}
	if base.TS == 0 {
		return nil, errors.New("malformed Zeek record: missing ts")
	}
	eventTime, err := zeekTime(base.TS)
	if err != nil {
		return nil, err
	}

	details, err := n.detailsFor(logType, line)
	if err != nil {
		return nil, err
	}

	obsType, ok := details.TypeOf()
	if !ok {
		return nil, errors.New("malformed Zeek record: no subtype body produced")
	}

	return &Observation{
		SchemaVersion:   SchemaVersion,
		ID:              recordIDFromParts(SourceZeek, eventTime, string(logType), base.UID, base.CommunityID),
		EventTime:       eventTime,
		ObservedAt:      n.now(),
		Source:          Source{Kind: SourceZeek, Version: n.Version.Resolve()},
		Tap:             n.Tap,
		Target:          n.Target,
		ObservationType: obsType,
		Flow:            n.flowFrom(&base),
		Details:         details,
	}, nil
}

func (n *ZeekNormalizer) detailsFor(logType ZeekLogType, line []byte) (Details, error) {
	switch logType {
	case ZeekConn:
		return n.conn(line)
	case ZeekDNS:
		return n.dns(line)
	case ZeekHTTP:
		return n.http(line)
	case ZeekSSL:
		return n.ssl(line)
	case ZeekX509:
		return n.x509(line)
	case ZeekFiles:
		return n.files(line)
	case ZeekNotice:
		return n.notice(line)
	case ZeekWeird:
		return n.weird(line)
	default:
		return Details{}, fmt.Errorf("%w: zeek log %q", ErrUnsupportedRecord, safeEventType(string(logType)))
	}
}

func (n *ZeekNormalizer) conn(line []byte) (Details, error) {
	var rec struct {
		Service     string   `json:"service"`
		Duration    *float64 `json:"duration"`
		ConnState   string   `json:"conn_state"`
		OrigBytes   *int64   `json:"orig_bytes"`
		RespBytes   *int64   `json:"resp_bytes"`
		OrigPkts    *int64   `json:"orig_pkts"`
		RespPkts    *int64   `json:"resp_pkts"`
		MissedBytes *int64   `json:"missed_bytes"`
	}
	if err := json.Unmarshal(line, &rec); err != nil {
		return Details{}, errors.New("malformed Zeek conn record")
	}
	return Details{Connection: &Connection{
		Service:            rec.Service,
		DurationSeconds:    rec.Duration,
		State:              rec.ConnState,
		SourceBytes:        rec.OrigBytes,
		DestinationBytes:   rec.RespBytes,
		SourcePackets:      rec.OrigPkts,
		DestinationPackets: rec.RespPkts,
		// MissedBytes is Zeek reporting gaps in its own capture. It is the
		// analyzer's own admission that its view was incomplete, so it is
		// preserved rather than dropped as noise (FR-039).
		MissedBytes: rec.MissedBytes,
	}}, nil
}

func (n *ZeekNormalizer) dns(line []byte) (Details, error) {
	var rec struct {
		Query   string   `json:"query"`
		QType   string   `json:"qtype_name"`
		RCode   string   `json:"rcode_name"`
		Answers []string `json:"answers"`
	}
	if err := json.Unmarshal(line, &rec); err != nil {
		return Details{}, errors.New("malformed Zeek dns record")
	}
	if rec.Query == "" {
		return Details{}, errors.New("malformed Zeek dns record: missing query")
	}
	return Details{DNS: &DNS{
		Query:   rec.Query,
		QType:   rec.QType,
		RCode:   rec.RCode,
		Answers: rec.Answers,
	}}, nil
}

func (n *ZeekNormalizer) http(line []byte) (Details, error) {
	var rec struct {
		Method    string `json:"method"`
		Host      string `json:"host"`
		URI       string `json:"uri"`
		Status    *int32 `json:"status_code"`
		UserAgent string `json:"user_agent"`
	}
	if err := json.Unmarshal(line, &rec); err != nil {
		return Details{}, errors.New("malformed Zeek http record")
	}
	return Details{HTTP: &HTTP{
		Method: rec.Method,
		Host:   rec.Host,
		// Only the path is kept. A URI query string routinely carries session
		// tokens, API keys, and search terms; those belong in a capture
		// artifact under its authorization boundary, not in a log record that
		// far more people can read.
		URIPath:    stripQuery(rec.URI),
		StatusCode: rec.Status,
		UserAgent:  rec.UserAgent,
	}}, nil
}

func (n *ZeekNormalizer) ssl(line []byte) (Details, error) {
	var rec struct {
		Version     string `json:"version"`
		Cipher      string `json:"cipher"`
		ServerName  string `json:"server_name"`
		NextProto   string `json:"next_protocol"`
		Established *bool  `json:"established"`
		Resumed     *bool  `json:"resumed"`
		JA3         string `json:"ja3"`
		JA3S        string `json:"ja3s"`
		// The chain's certificates are identified by fingerprint, and that is
		// the only link between this record and the x509 records for the same
		// handshake. x509.log carries no uid, no conn_id and no Community ID,
		// so without this an observed certificate cannot be reached from the
		// flow that presented it.
		CertChainFPs []string `json:"cert_chain_fps"`
	}
	if err := json.Unmarshal(line, &rec); err != nil {
		return Details{}, errors.New("malformed Zeek ssl record")
	}
	return Details{TLS: &TLS{
		Version:                 rec.Version,
		Cipher:                  rec.Cipher,
		ServerName:              rec.ServerName,
		ALPN:                    rec.NextProto,
		Established:             rec.Established,
		Resumed:                 rec.Resumed,
		JA3:                     rec.JA3,
		JA3S:                    rec.JA3S,
		CertificateFingerprints: rec.CertChainFPs,
	}}, nil
}

// x509 decodes a Zeek x509.log record.
//
// The certificate fields are read from flattened dotted keys, not a nested
// object. Zeek's json-logs policy renders a record-valued field as one key per
// leaf, which is the same reason conn.log carries "id.orig_h" rather than a
// nested "id". X509::Info declares `certificate: X509::Certificate`, so Zeek
// writes "certificate.subject". Decoding a nested object here parsed without
// error and produced a certificate with every field empty - schema-valid,
// queryable, and describing nothing.
//
// There is also no validation_status: that field belongs to ssl.log under the
// validate-certs policy, which Trawl does not load, so it is not read here
// rather than read from a key that never exists.
func (n *ZeekNormalizer) x509(line []byte) (Details, error) {
	var rec struct {
		Fingerprint    string   `json:"fingerprint"`
		Subject        string   `json:"certificate.subject"`
		Issuer         string   `json:"certificate.issuer"`
		Serial         string   `json:"certificate.serial"`
		NotValidBefore *float64 `json:"certificate.not_valid_before"`
		NotValidAfter  *float64 `json:"certificate.not_valid_after"`
	}
	if err := json.Unmarshal(line, &rec); err != nil {
		return Details{}, errors.New("malformed Zeek x509 record")
	}
	if rec.Fingerprint == "" {
		return Details{}, errors.New("malformed Zeek x509 record: missing fingerprint")
	}
	cert := &Certificate{
		FingerprintSHA256: rec.Fingerprint,
		Subject:           rec.Subject,
		Issuer:            rec.Issuer,
		Serial:            rec.Serial,
	}
	if rec.NotValidBefore != nil {
		if t, err := zeekTime(*rec.NotValidBefore); err == nil {
			cert.NotValidBefore = &t
		}
	}
	if rec.NotValidAfter != nil {
		if t, err := zeekTime(*rec.NotValidAfter); err == nil {
			cert.NotValidAfter = &t
		}
	}
	return Details{Certificate: cert}, nil
}

func (n *ZeekNormalizer) files(line []byte) (Details, error) {
	var rec struct {
		FID      string `json:"fuid"`
		MIMEType string `json:"mime_type"`
		Filename string `json:"filename"`
		Seen     *int64 `json:"seen_bytes"`
		SHA256   string `json:"sha256"`
	}
	if err := json.Unmarshal(line, &rec); err != nil {
		return Details{}, errors.New("malformed Zeek files record")
	}
	return Details{File: &File{
		FileID:   rec.FID,
		MIMEType: rec.MIMEType,
		Filename: rec.Filename,
		// The hash and metadata are recorded; content never is.
		SizeBytes: rec.Seen,
		SHA256:    rec.SHA256,
	}}, nil
}

func (n *ZeekNormalizer) notice(line []byte) (Details, error) {
	var rec struct {
		Note string `json:"note"`
		Msg  string `json:"msg"`
		Sub  string `json:"sub"`
	}
	if err := json.Unmarshal(line, &rec); err != nil {
		return Details{}, errors.New("malformed Zeek notice record")
	}
	if rec.Note == "" {
		return Details{}, errors.New("malformed Zeek notice record: missing note")
	}
	return Details{Notice: &Notice{
		Type:       rec.Note,
		Message:    rec.Msg,
		SubMessage: rec.Sub,
	}}, nil
}

func (n *ZeekNormalizer) weird(line []byte) (Details, error) {
	var rec struct {
		Name string `json:"name"`
		Addl string `json:"addl"`
	}
	if err := json.Unmarshal(line, &rec); err != nil {
		return Details{}, errors.New("malformed Zeek weird record")
	}
	if rec.Name == "" {
		return Details{}, errors.New("malformed Zeek weird record: missing name")
	}
	return Details{Weird: &Weird{Name: rec.Name, AdditionalInfo: rec.Addl}}, nil
}

// flowFrom builds the shared flow envelope, preserving Community ID verbatim so
// it matches what Suricata reported for the same traffic.
func (n *ZeekNormalizer) flowFrom(base *zeekBase) *Flow {
	if base.SourceIP == "" && base.DestIP == "" {
		return nil
	}
	return &Flow{
		CommunityID: base.CommunityID,
		ZeekUID:     base.UID,
		Protocol:    strings.ToLower(base.Proto),
		Source:      Endpoint{IP: base.SourceIP, Port: base.SourcePort},
		Destination: Endpoint{IP: base.DestIP, Port: base.DestPort},
	}
}

func (n *ZeekNormalizer) now() time.Time {
	if n.Now != nil {
		return n.Now().UTC()
	}
	return time.Now().UTC()
}

// zeekTime converts Zeek's epoch-seconds float.
func zeekTime(ts float64) (time.Time, error) {
	if math.IsNaN(ts) || math.IsInf(ts, 0) || ts <= 0 {
		return time.Time{}, errors.New("malformed Zeek record: invalid ts")
	}
	sec, frac := math.Modf(ts)
	return time.Unix(int64(sec), int64(frac*float64(time.Second))).UTC(), nil
}

// stripQuery removes a URI query string.
//
// Zeek's uri field includes the query, which routinely carries session tokens
// and API keys. Trawl stores the path so an investigation can still see what
// was requested, without persisting credentials into log storage.
func stripQuery(uri string) string {
	path, _, _ := strings.Cut(uri, "?")
	return path
}
