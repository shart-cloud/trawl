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

// Package observation defines the normalized record Trawl emits for every
// analyzer output, and the code that produces it from Suricata and Zeek.
//
// Suricata and Zeek describe the same traffic with different field names,
// nesting, and timestamp conventions. Rather than push that difference onto
// every dashboard query, the sensor agent normalizes both into one versioned
// envelope before anything is stored (ADR-0001).
//
// Two envelope decisions carry most of the investigative value:
//
//   - Both the analyzer's event time and Trawl's observation time are kept.
//     Producers' clocks drift, and an analyst reconstructing a sequence needs to
//     see the skew rather than have it silently resolved.
//   - Community ID is preserved wherever an analyzer derives it. It is what
//     makes an exact pivot between a Suricata alert and a Zeek connection
//     possible without reconstructing the flow tuple by hand (FR-011).
package observation

import "time"

// SchemaVersion is the envelope version, stored on every record so a reader can
// interpret one written by an older sensor.
const SchemaVersion = "trawl.observation/v1alpha1"

// SourceKind identifies which analyzer produced a record.
type SourceKind string

const (
	SourceSuricata SourceKind = "Suricata"
	SourceZeek     SourceKind = "Zeek"
	SourceHubble   SourceKind = "Hubble"
)

// ObservationType is the record subtype. It is an indexed Loki label, so the
// set is closed.
type ObservationType string

const (
	TypeSignature   ObservationType = "signature"
	TypeConnection  ObservationType = "connection"
	TypeDNS         ObservationType = "dns"
	TypeHTTP        ObservationType = "http"
	TypeTLS         ObservationType = "tls"
	TypeCertificate ObservationType = "certificate"
	TypeFile        ObservationType = "file"
	TypeNotice      ObservationType = "notice"
	TypeWeird       ObservationType = "weird"
	TypeClusterFlow ObservationType = "cluster_flow"
)

// Source identifies the producing analyzer and its version.
type Source struct {
	Kind    SourceKind `json:"kind"`
	Version string     `json:"version,omitempty"`
}

// Tap identifies the NetworkTap a record belongs to.
//
// UID rather than name alone: a tap can be deleted and recreated with the same
// name, and observations from the old one must not silently attach to the new.
type Tap struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
}

// Target identifies where the record was observed.
type Target struct {
	Node             string `json:"node"`
	Interface        string `json:"interface,omitempty"`
	ObservationPoint string `json:"observation_point,omitempty"`
}

// Endpoint is one side of a flow.
type Endpoint struct {
	IP        string `json:"ip,omitempty"`
	Port      *int32 `json:"port,omitempty"`
	MAC       string `json:"mac,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Workload  string `json:"workload,omitempty"`
	Pod       string `json:"pod,omitempty"`
}

// Flow is the traffic context shared by every record that has one.
type Flow struct {
	// CommunityID is the standardized flow hash. It is the exact-pivot key
	// between analyzers, so it is preserved verbatim rather than recomputed.
	CommunityID string `json:"community_id,omitempty"`

	// ZeekUID correlates Zeek records with each other within a connection.
	ZeekUID string `json:"zeek_uid,omitempty"`

	Protocol    string   `json:"protocol"`
	VLAN        *int32   `json:"vlan,omitempty"`
	Source      Endpoint `json:"source"`
	Destination Endpoint `json:"destination"`
}

// Signature is a signature-based detection.
type Signature struct {
	RuleID   int64  `json:"rule_id"`
	Revision *int64 `json:"revision,omitempty"`
	Severity int32  `json:"severity"`
	Category string `json:"category"`
	Message  string `json:"message"`
	Action   string `json:"action,omitempty"`
}

// Connection summarizes a connection record.
type Connection struct {
	Service            string   `json:"service,omitempty"`
	DurationSeconds    *float64 `json:"duration_seconds,omitempty"`
	State              string   `json:"state,omitempty"`
	SourceBytes        *int64   `json:"source_bytes,omitempty"`
	DestinationBytes   *int64   `json:"destination_bytes,omitempty"`
	SourcePackets      *int64   `json:"source_packets,omitempty"`
	DestinationPackets *int64   `json:"destination_packets,omitempty"`
	MissedBytes        *int64   `json:"missed_bytes,omitempty"`
}

// DNS is a DNS exchange.
type DNS struct {
	Query   string   `json:"query"`
	QType   string   `json:"qtype,omitempty"`
	RCode   string   `json:"rcode,omitempty"`
	Answers []string `json:"answers,omitempty"`
}

// HTTP is an HTTP request/response pair.
//
// It carries no request or response body and no header block. Those are packet
// payload, which belongs in a capture artifact under its authorization
// boundary, not in a log record with far wider read access.
type HTTP struct {
	Method     string `json:"method,omitempty"`
	Host       string `json:"host,omitempty"`
	URIPath    string `json:"uri_path,omitempty"`
	StatusCode *int32 `json:"status_code,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
}

// TLS is a TLS handshake.
type TLS struct {
	Version     string `json:"version,omitempty"`
	Cipher      string `json:"cipher,omitempty"`
	ServerName  string `json:"server_name,omitempty"`
	ALPN        string `json:"alpn,omitempty"`
	Established *bool  `json:"established,omitempty"`
	Resumed     *bool  `json:"resumed,omitempty"`
	JA3         string `json:"ja3,omitempty"`
	JA3S        string `json:"ja3s,omitempty"`
}

// Certificate is an observed X.509 certificate.
type Certificate struct {
	FingerprintSHA256 string     `json:"fingerprint_sha256,omitempty"`
	Subject           string     `json:"subject,omitempty"`
	Issuer            string     `json:"issuer,omitempty"`
	Serial            string     `json:"serial,omitempty"`
	NotValidBefore    *time.Time `json:"not_valid_before,omitempty"`
	NotValidAfter     *time.Time `json:"not_valid_after,omitempty"`
	ValidationStatus  string     `json:"validation_status,omitempty"`
}

// File is a file transfer observation.
//
// It records the hash and metadata, never content.
type File struct {
	FileID    string `json:"file_id,omitempty"`
	MIMEType  string `json:"mime_type,omitempty"`
	Filename  string `json:"filename,omitempty"`
	SizeBytes *int64 `json:"size_bytes,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
}

// Notice is a Zeek notice.
type Notice struct {
	Type       string `json:"type"`
	Message    string `json:"message"`
	SubMessage string `json:"submessage,omitempty"`
}

// Weird is a Zeek protocol anomaly.
type Weird struct {
	Name           string `json:"name"`
	AdditionalInfo string `json:"additional_info,omitempty"`
}

// ClusterFlow is a Hubble flow verdict.
type ClusterFlow struct {
	Verdict    string `json:"verdict"`
	DropReason string `json:"drop_reason,omitempty"`
	Direction  string `json:"direction,omitempty"`
	EventType  string `json:"event_type,omitempty"`
	IsReply    *bool  `json:"is_reply,omitempty"`
}

// Details holds exactly one subtype body.
//
// The schema enforces exactly one property. A record carrying two bodies would
// be ambiguous about what it describes, and one carrying none would be an
// envelope with no observation in it.
type Details struct {
	Signature   *Signature   `json:"signature,omitempty"`
	Connection  *Connection  `json:"connection,omitempty"`
	DNS         *DNS         `json:"dns,omitempty"`
	HTTP        *HTTP        `json:"http,omitempty"`
	TLS         *TLS         `json:"tls,omitempty"`
	Certificate *Certificate `json:"certificate,omitempty"`
	File        *File        `json:"file,omitempty"`
	Notice      *Notice      `json:"notice,omitempty"`
	Weird       *Weird       `json:"weird,omitempty"`
	ClusterFlow *ClusterFlow `json:"cluster_flow,omitempty"`
}

// Observation is one normalized record.
type Observation struct {
	SchemaVersion string `json:"schema_version"`

	// ID is stable for a given record so a duplicate delivery can be collapsed.
	ID string `json:"id"`

	// EventTime is when the analyzer says the traffic happened.
	EventTime time.Time `json:"event_time"`

	// ObservedAt is when Trawl processed it. Keeping both is what lets an
	// analyst account for producer clock skew instead of guessing at it.
	ObservedAt time.Time `json:"observed_at"`

	Source Source `json:"source"`
	Tap    *Tap   `json:"tap,omitempty"`
	Target Target `json:"target"`

	ObservationType ObservationType `json:"observation_type"`

	Flow    *Flow   `json:"flow,omitempty"`
	Details Details `json:"details"`
}

// TypeOf returns the observation type implied by the populated details body,
// and whether exactly one was set.
func (d Details) TypeOf() (ObservationType, bool) {
	var found ObservationType
	count := 0
	for t, set := range map[ObservationType]bool{
		TypeSignature:   d.Signature != nil,
		TypeConnection:  d.Connection != nil,
		TypeDNS:         d.DNS != nil,
		TypeHTTP:        d.HTTP != nil,
		TypeTLS:         d.TLS != nil,
		TypeCertificate: d.Certificate != nil,
		TypeFile:        d.File != nil,
		TypeNotice:      d.Notice != nil,
		TypeWeird:       d.Weird != nil,
		TypeClusterFlow: d.ClusterFlow != nil,
	} {
		if set {
			found = t
			count++
		}
	}
	return found, count == 1
}
