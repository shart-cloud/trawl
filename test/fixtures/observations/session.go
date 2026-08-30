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

// Package observations provides deterministic correlated sessions for
// investigation tests.
//
// SC-005 measures whether an analyst can pivot from one record to its exact
// match in under three minutes, starting from either direction. That is only
// measurable against sessions where the correct answer is known in advance,
// which is what these fixtures provide: a session declares which of its records
// genuinely describe the same flow, so a test can assert the pivot found them
// and nothing else.
package observations

import (
	"fmt"
	"time"
)

// Session is one correlated exchange as the analyzers would report it.
type Session struct {
	// Name identifies the session in test output.
	Name string

	// CommunityID is shared by every record the analyzers could correlate
	// exactly. Empty means this session deliberately exercises the fallback.
	CommunityID string

	// SuricataEVE and ZeekLogs are raw analyzer output, so tests exercise the
	// real normalizers rather than hand-built envelopes. A fixture of
	// pre-normalized records would pass even if normalization were broken.
	SuricataEVE []string
	ZeekLogs    []ZeekLog

	// ExactMatches is how many records should correlate exactly. The test
	// asserts the pivot returns this many, so a normalizer that silently drops
	// Community ID fails rather than quietly reducing recall.
	ExactMatches int

	// FlowlessRecords is how many of this session's records carry no flow at
	// all, and so can never be correlated by Community ID or endpoint.
	//
	// This is a property of the evidence, not of Trawl. Zeek's X509::Info has
	// no uid and no conn_id - a certificate is reported as an object the
	// handshake referenced rather than as an event on the flow - so the only
	// route from a flow to a certificate is the fingerprint carried in
	// ssl.log's cert_chain_fps. Recording the count here keeps the pivot tests
	// honest: they assert these records report no match rather than quietly
	// excluding them.
	FlowlessRecords int
}

// Zeek log type names used by the fixtures. They mirror
// observation.ZeekLogType but stay plain strings so the fixture package does
// not constrain what a test can construct.
const (
	logConn   = "conn"
	logDNS    = "dns"
	logHTTP   = "http"
	logSSL    = "ssl"
	logX509   = "x509"
	logFiles  = "files"
	logNotice = "notice"
	logWeird  = "weird"
)

// ZeekLog pairs a log type with a raw JSON line.
type ZeekLog struct {
	Type string
	Line string
}

// BaseTime anchors every fixture so tests are reproducible.
var BaseTime = time.Date(2026, 8, 29, 11, 59, 30, 0, time.UTC)

// zeekTS renders a Zeek epoch-seconds timestamp.
func zeekTS(offset time.Duration) string {
	t := BaseTime.Add(offset)
	return fmt.Sprintf("%d.%06d", t.Unix(), t.Nanosecond()/1000)
}

// suricataTS renders a Suricata EVE timestamp.
func suricataTS(offset time.Duration) string {
	return BaseTime.Add(offset).Format("2006-01-02T15:04:05.000000-0700")
}

// TLSSessionWithAlert is the canonical correlated case: an outbound TLS
// connection that Zeek describes and Suricata alerts on, sharing a Community ID.
func TLSSessionWithAlert() Session {
	const cid = "1:LQU9qZlK+B5F3KDmev6m5PMibrg="

	return Session{
		Name:         "tls-session-with-alert",
		CommunityID:  cid,
		ExactMatches: 3,
		SuricataEVE: []string{
			fmt.Sprintf(`{"timestamp":%q,"event_type":"alert","src_ip":"192.168.1.50","src_port":44321,`+
				`"dest_ip":"203.0.113.10","dest_port":443,"proto":"TCP","community_id":%q,`+
				`"alert":{"action":"allowed","signature_id":2019401,"rev":5,`+
				`"signature":"ET POLICY Suspicious outbound TLS","category":"Potentially Bad Traffic","severity":2}}`,
				suricataTS(0), cid),
		},
		ZeekLogs: []ZeekLog{
			{logConn, fmt.Sprintf(`{"ts":%s,"uid":"CHhAvVGS1DHFjwGM9","community_id":%q,`+
				`"id.orig_h":"192.168.1.50","id.orig_p":44321,"id.resp_h":"203.0.113.10","id.resp_p":443,`+
				`"proto":"tcp","service":"ssl","duration":12.5,"conn_state":"SF","orig_bytes":1024,"resp_bytes":8192}`,
				zeekTS(0), cid)},
			{logSSL, fmt.Sprintf(`{"ts":%s,"uid":"CHhAvVGS1DHFjwGM9","community_id":%q,`+
				`"id.orig_h":"192.168.1.50","id.orig_p":44321,"id.resp_h":"203.0.113.10","id.resp_p":443,`+
				`"proto":"tcp","version":"TLSv13","cipher":"TLS_AES_256_GCM_SHA384",`+
				`"server_name":"suspicious.example","established":true,"ja3":"e7d705a3286e19ea42f587b344ee6865"}`,
				zeekTS(200*time.Millisecond), cid)},
		},
	}
}

// DNSLookupSession exercises DNS records, which carry a Community ID but no
// alert.
func DNSLookupSession() Session {
	const cid = "1:d4Bw9V0kQxJhLZ8mNpQrStUvWxY="

	return Session{
		Name:         "dns-lookup",
		CommunityID:  cid,
		ExactMatches: 2,
		ZeekLogs: []ZeekLog{
			{logConn, fmt.Sprintf(`{"ts":%s,"uid":"CDNSuid000001","community_id":%q,`+
				`"id.orig_h":"192.168.1.50","id.orig_p":53001,"id.resp_h":"192.168.1.1","id.resp_p":53,`+
				`"proto":"udp","service":"dns","conn_state":"SF"}`, zeekTS(0), cid)},
			{logDNS, fmt.Sprintf(`{"ts":%s,"uid":"CDNSuid000001","community_id":%q,`+
				`"id.orig_h":"192.168.1.50","id.orig_p":53001,"id.resp_h":"192.168.1.1","id.resp_p":53,`+
				`"proto":"udp","query":"suspicious.example","qtype_name":"A","rcode_name":"NOERROR",`+
				`"answers":["203.0.113.10"]}`, zeekTS(10*time.Millisecond), cid)},
		},
	}
}

// SessionWithoutCommunityID exercises the fallback path, where correlation must
// still work and must be reported as approximate.
func SessionWithoutCommunityID() Session {
	return Session{
		Name:         "no-community-id",
		CommunityID:  "",
		ExactMatches: 0,
		SuricataEVE: []string{
			fmt.Sprintf(`{"timestamp":%q,"event_type":"alert","src_ip":"10.1.1.5","src_port":51000,`+
				`"dest_ip":"10.1.1.9","dest_port":8080,"proto":"TCP",`+
				`"alert":{"signature_id":9000001,"rev":1,"signature":"Local rule","category":"Misc","severity":3}}`,
				suricataTS(0)),
		},
		ZeekLogs: []ZeekLog{
			{logConn, fmt.Sprintf(`{"ts":%s,"uid":"CNoCidUid0001",`+
				`"id.orig_h":"10.1.1.5","id.orig_p":51000,"id.resp_h":"10.1.1.9","id.resp_p":8080,`+
				`"proto":"tcp","service":"http","conn_state":"SF"}`, zeekTS(300*time.Millisecond))},
		},
	}
}

// HTTPSessionWithCredentialInQuery checks that a URI query carrying a token
// never reaches a stored record.
//
// It is a fixture rather than a unit test because the property must hold
// through the whole path an operator actually queries, not just at the function
// that strips it.
func HTTPSessionWithCredentialInQuery() Session {
	const cid = "1:HttpSessionCommunityIdValue="

	return Session{
		Name:         "http-with-token-in-query",
		CommunityID:  cid,
		ExactMatches: 2,
		ZeekLogs: []ZeekLog{
			{logConn, fmt.Sprintf(`{"ts":%s,"uid":"CHttpUid00001","community_id":%q,`+
				`"id.orig_h":"10.2.2.5","id.orig_p":52000,"id.resp_h":"10.2.2.9","id.resp_p":80,`+
				`"proto":"tcp","service":"http","conn_state":"SF"}`, zeekTS(0), cid)},
			{logHTTP, fmt.Sprintf(`{"ts":%s,"uid":"CHttpUid00001","community_id":%q,`+
				`"id.orig_h":"10.2.2.5","id.orig_p":52000,"id.resp_h":"10.2.2.9","id.resp_p":80,`+
				`"proto":"tcp","method":"GET","host":"api.internal",`+
				`"uri":"/v1/session?token=s3cr3t-session-value&user=alice","status_code":200}`,
				zeekTS(50*time.Millisecond), cid)},
		},
	}
}

// TLSSessionWithCertificate covers the certificate subtype and the one place
// the investigation path cannot use a flow pivot.
//
// The x509 line is shaped the way Zeek 8.0.10 actually writes it under the
// json-logs policy Trawl configures: dotted keys flattened from the nested
// X509::Certificate record, and no uid, conn_id or Community ID anywhere. The
// ssl record reaches it only through cert_chain_fps.
func TLSSessionWithCertificate() Session {
	const cid = "1:EGhnat6tSLYJl6Absav9mrL445A="
	const fingerprint = "e51dcbdb5041a9034cd463978f9d7769945c18081150abe9a20aab93ed6e58ed"

	return Session{
		Name:            "tls-session-with-certificate",
		CommunityID:     cid,
		ExactMatches:    2,
		FlowlessRecords: 1,
		ZeekLogs: []ZeekLog{
			{logConn, fmt.Sprintf(`{"ts":%s,"uid":"CCertUid00001","community_id":%q,`+
				`"id.orig_h":"10.3.3.5","id.orig_p":37816,"id.resp_h":"10.3.3.9","id.resp_p":443,`+
				`"proto":"tcp","service":"ssl","duration":0.0041,"conn_state":"RSTO",`+
				`"orig_bytes":358,"resp_bytes":2360,"missed_bytes":0}`, zeekTS(0), cid)},
			{logSSL, fmt.Sprintf(`{"ts":%s,"uid":"CCertUid00001","community_id":%q,`+
				`"id.orig_h":"10.3.3.5","id.orig_p":37816,"id.resp_h":"10.3.3.9","id.resp_p":443,`+
				`"version":"TLSv12","cipher":"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384","curve":"x25519",`+
				`"server_name":"suspicious.example","resumed":false,"established":true,`+
				`"cert_chain_fps":[%q],"sni_matches_cert":true}`, zeekTS(0), cid, fingerprint)},
			{logX509, fmt.Sprintf(`{"ts":%s,"fingerprint":%q,`+
				`"certificate.version":3,"certificate.serial":"638F18BD0AC7BAF03BD3E5458FE50AB7F8D679F4",`+
				`"certificate.subject":"C=US,O=Trawl Fixture,CN=suspicious.example",`+
				`"certificate.issuer":"C=US,O=Trawl Fixture,CN=suspicious.example",`+
				`"certificate.not_valid_before":%d.0,"certificate.not_valid_after":%d.0,`+
				`"certificate.key_alg":"rsaEncryption","certificate.sig_alg":"sha256WithRSAEncryption",`+
				`"certificate.key_type":"rsa","certificate.key_length":2048,`+
				`"basic_constraints.ca":true,"host_cert":true,"client_cert":false}`,
				zeekTS(50*time.Millisecond), fingerprint,
				BaseTime.Add(-24*time.Hour).Unix(), BaseTime.Add(48*time.Hour).Unix())},
		},
	}
}

// FileDownloadWithAnomalies covers the file, notice and weird subtypes.
//
// All four records carry a Community ID, including the files record: Zeek's
// Files::Info has carried uid and conn_id since 5.1, so a file transfer is
// reachable from the flow that carried it. The sha256 is present because
// Trawl's image loads its own hashing script; Zeek's stock hash-all-files
// computes MD5 and SHA1, neither of which Trawl stores.
func FileDownloadWithAnomalies() Session {
	const cid = "1:Yk4R2wd/Z5Ewhg08SPVFnW/THyM="
	const sha = "ff67a9d764d6a2367a187734e697f6a53217db9a21c101d410a113ca871a299d"

	return Session{
		Name:         "file-download-with-anomalies",
		CommunityID:  cid,
		ExactMatches: 5,
		ZeekLogs: []ZeekLog{
			{logConn, fmt.Sprintf(`{"ts":%s,"uid":"CFileUid00001","community_id":%q,`+
				`"id.orig_h":"10.4.4.5","id.orig_p":48512,"id.resp_h":"10.4.4.9","id.resp_p":80,`+
				`"proto":"tcp","service":"http","conn_state":"SF","orig_bytes":220,"resp_bytes":4096,`+
				`"missed_bytes":128}`, zeekTS(0), cid)},
			{logHTTP, fmt.Sprintf(`{"ts":%s,"uid":"CFileUid00001","community_id":%q,`+
				`"id.orig_h":"10.4.4.5","id.orig_p":48512,"id.resp_h":"10.4.4.9","id.resp_p":80,`+
				`"method":"GET","host":"files.internal","uri":"/download/payload.zip",`+
				`"status_code":200,"user_agent":"curl/8.5.0"}`, zeekTS(20*time.Millisecond), cid)},
			{logFiles, fmt.Sprintf(`{"ts":%s,"fuid":"FFOx3k2GH9yIQca1Pi","uid":"CFileUid00001",`+
				`"community_id":%q,"id.orig_h":"10.4.4.5","id.orig_p":48512,`+
				`"id.resp_h":"10.4.4.9","id.resp_p":80,"source":"HTTP","depth":0,`+
				`"analyzers":["SHA256"],"mime_type":"application/zip","filename":"payload.zip",`+
				`"is_orig":false,"seen_bytes":4096,"missing_bytes":0,"sha256":%q}`,
				zeekTS(120*time.Millisecond), cid, sha)},
			{logNotice, fmt.Sprintf(`{"ts":%s,"uid":"CFileUid00001","community_id":%q,`+
				`"id.orig_h":"10.4.4.5","id.orig_p":48512,"id.resp_h":"10.4.4.9","id.resp_p":80,`+
				`"proto":"tcp","note":"Trawl::Suspicious_Download",`+
				`"msg":"Archive retrieved from an internal host with no prior contact",`+
				`"sub":"payload.zip","src":"10.4.4.5","dst":"10.4.4.9","p":80,"peer":"zeek"}`,
				zeekTS(140*time.Millisecond), cid)},
			// missed_bytes above and this weird are the analyzer reporting the
			// limits of its own view. Both are preserved rather than dropped as
			// noise (FR-039): an investigation that cannot see where the
			// evidence is incomplete will read absence as absence of activity.
			{logWeird, fmt.Sprintf(`{"ts":%s,"uid":"CFileUid00001","community_id":%q,`+
				`"id.orig_h":"10.4.4.5","id.orig_p":48512,"id.resp_h":"10.4.4.9","id.resp_p":80,`+
				`"name":"content_gap","notice":false,"peer":"zeek","source":"TCP"}`,
				zeekTS(160*time.Millisecond), cid)},
		},
	}
}

// All returns every fixture session.
func All() []Session {
	return []Session{
		TLSSessionWithAlert(),
		DNSLookupSession(),
		SessionWithoutCommunityID(),
		HTTPSessionWithCredentialInQuery(),
		TLSSessionWithCertificate(),
		FileDownloadWithAnomalies(),
	}
}
