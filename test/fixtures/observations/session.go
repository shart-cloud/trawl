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
}

// Zeek log type names used by the fixtures. They mirror
// observation.ZeekLogType but stay plain strings so the fixture package does
// not constrain what a test can construct.
const (
	logConn = "conn"
	logDNS  = "dns"
	logHTTP = "http"
	logSSL  = "ssl"
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

// All returns every fixture session.
func All() []Session {
	return []Session{
		TLSSessionWithAlert(),
		DNSLookupSession(),
		SessionWithoutCommunityID(),
		HTTPSessionWithCredentialInQuery(),
	}
}
