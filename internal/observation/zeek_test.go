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
	"errors"
	"strings"
	"testing"
	"time"
)

func zeekNormalizer() *ZeekNormalizer {
	fixed := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	return &ZeekNormalizer{
		Version: "8.0.10",
		Tap:     &Tap{Namespace: "trawl-system", Name: "mirror-0", UID: "tap-uid-1"},
		Target:  Target{Node: "sensor-01", Interface: "enp5s0"},
		Now:     func() time.Time { return fixed },
	}
}

// The shared connection identity Zeek stamps on every record for one flow.
const zeekFlowFields = `"ts": 1787054370.123456,
  "uid": "CHhAvVGS1DHFjwGM9",
  "community_id": "1:LQU9qZlK+B5F3KDmev6m5PMibrg=",
  "id.orig_h": "192.168.1.50",
  "id.orig_p": 44321,
  "id.resp_h": "203.0.113.10",
  "id.resp_p": 443,
  "proto": "tcp"`

func TestZeekNormalizesEachSupportedLogType(t *testing.T) {
	n := zeekNormalizer()

	cases := []struct {
		logType ZeekLogType
		line    string
		want    ObservationType
		check   func(*testing.T, Details)
	}{
		{ZeekConn, `{` + zeekFlowFields + `, "service":"ssl","duration":12.5,"conn_state":"SF","orig_bytes":1024,"resp_bytes":8192,"missed_bytes":0}`,
			TypeConnection, func(t *testing.T, d Details) {
				if d.Connection.Service != "ssl" || d.Connection.State != "SF" {
					t.Errorf("connection = %+v", d.Connection)
				}
				if d.Connection.SourceBytes == nil || *d.Connection.SourceBytes != 1024 {
					t.Errorf("source_bytes = %v", d.Connection.SourceBytes)
				}
			}},
		{ZeekDNS, `{` + zeekFlowFields + `, "query":"example.com","qtype_name":"A","rcode_name":"NOERROR","answers":["93.184.216.34"]}`,
			TypeDNS, func(t *testing.T, d Details) {
				if d.DNS.Query != "example.com" || d.DNS.QType != "A" {
					t.Errorf("dns = %+v", d.DNS)
				}
				if len(d.DNS.Answers) != 1 {
					t.Errorf("answers = %v", d.DNS.Answers)
				}
			}},
		{ZeekHTTP, `{` + zeekFlowFields + `, "method":"GET","host":"example.com","uri":"/index.html","status_code":200,"user_agent":"curl/8"}`,
			TypeHTTP, func(t *testing.T, d Details) {
				if d.HTTP.Method != "GET" || d.HTTP.URIPath != "/index.html" {
					t.Errorf("http = %+v", d.HTTP)
				}
				if d.HTTP.StatusCode == nil || *d.HTTP.StatusCode != 200 {
					t.Errorf("status = %v", d.HTTP.StatusCode)
				}
			}},
		{ZeekSSL, `{` + zeekFlowFields + `, "version":"TLSv13","cipher":"TLS_AES_256_GCM_SHA384","server_name":"example.com","established":true,"ja3":"abc123"}`,
			TypeTLS, func(t *testing.T, d Details) {
				if d.TLS.Version != "TLSv13" || d.TLS.ServerName != "example.com" {
					t.Errorf("tls = %+v", d.TLS)
				}
				if d.TLS.Established == nil || !*d.TLS.Established {
					t.Errorf("established = %v", d.TLS.Established)
				}
			}},
		// Flattened dotted keys, copied from a real x509.log written by Zeek
		// 8.0.10 under the json-logs policy Trawl configures. The previous
		// fixture used a nested "certificate" object, which Zeek never emits:
		// it parsed cleanly into an empty Certificate, so the assertion below
		// was the only thing standing between a broken parser and a stored
		// record that described nothing.
		{ZeekX509, `{"ts":1787054370.1,"fingerprint":"abababababababababababababababababababababababababababababababab",` +
			`"certificate.version":3,"certificate.serial":"01","certificate.subject":"CN=example.com",` +
			`"certificate.issuer":"CN=CA","certificate.not_valid_before":1787054000.0,` +
			`"certificate.not_valid_after":1790054000.0,"certificate.key_alg":"rsaEncryption",` +
			`"certificate.key_length":2048,"host_cert":true,"client_cert":false}`,
			TypeCertificate, func(t *testing.T, d Details) {
				if d.Certificate.Subject != "CN=example.com" {
					t.Errorf("certificate = %+v", d.Certificate)
				}
				if d.Certificate.Issuer != "CN=CA" || d.Certificate.Serial != "01" {
					t.Errorf("certificate = %+v", d.Certificate)
				}
				if d.Certificate.NotValidAfter == nil {
					t.Error("not_valid_after was not parsed")
				}
			}},
		{ZeekFiles, `{"ts":1787054370.1,"fuid":"FakNcS","mime_type":"application/zip","filename":"payload.zip","seen_bytes":4096,"sha256":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"}`,
			TypeFile, func(t *testing.T, d Details) {
				if d.File.MIMEType != "application/zip" || d.File.SHA256 != strings.Repeat("cd", 32) {
					t.Errorf("file = %+v", d.File)
				}
			}},
		{ZeekNotice, `{` + zeekFlowFields + `, "note":"Scan::Port_Scan","msg":"scanned 20 ports","sub":"detail"}`,
			TypeNotice, func(t *testing.T, d Details) {
				if d.Notice.Type != "Scan::Port_Scan" {
					t.Errorf("notice = %+v", d.Notice)
				}
			}},
		{ZeekWeird, `{` + zeekFlowFields + `, "name":"bad_TCP_checksum","addl":"x"}`,
			TypeWeird, func(t *testing.T, d Details) {
				if d.Weird.Name != "bad_TCP_checksum" {
					t.Errorf("weird = %+v", d.Weird)
				}
			}},
	}

	for _, tc := range cases {
		t.Run(string(tc.logType), func(t *testing.T) {
			obs, err := n.Normalize(tc.logType, []byte(tc.line))
			if err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			if obs.ObservationType != tc.want {
				t.Errorf("observation_type = %q, want %q", obs.ObservationType, tc.want)
			}
			tc.check(t, obs.Details)

			// Every subtype must satisfy the normative schema, not just the
			// ones that happen to be exercised elsewhere.
			if err := Validate(obs); err != nil {
				t.Errorf("%s record violates the schema: %v", tc.logType, err)
			}
		})
	}
}

func TestZeekPreservesCommunityIDForCrossAnalyzerPivot(t *testing.T) {
	// The whole point of FR-011: this value must equal what Suricata reported
	// for the same flow, so an analyst can pivot exactly rather than
	// reconstructing the tuple by hand.
	suricata := suricataNormalizer()
	suricataObs, _, err := suricata.Normalize([]byte(eveAlert))
	if err != nil {
		t.Fatalf("suricata Normalize: %v", err)
	}

	zeek := zeekNormalizer()
	zeekObs, err := zeek.Normalize(ZeekConn, []byte(`{`+zeekFlowFields+`, "service":"ssl","conn_state":"SF"}`))
	if err != nil {
		t.Fatalf("zeek Normalize: %v", err)
	}

	if suricataObs.Flow.CommunityID != zeekObs.Flow.CommunityID {
		t.Errorf("community IDs differ across analyzers: %q vs %q",
			suricataObs.Flow.CommunityID, zeekObs.Flow.CommunityID)
	}
	if zeekObs.Flow.CommunityID == "" {
		t.Error("Zeek community_id is empty")
	}
}

func TestZeekCarriesUIDForIntraConnectionCorrelation(t *testing.T) {
	// Zeek's uid ties a connection to its DNS, HTTP, and TLS records. It is
	// kept alongside community_id because it correlates within one analyzer's
	// view where community_id correlates across analyzers.
	n := zeekNormalizer()
	obs, err := n.Normalize(ZeekHTTP, []byte(`{`+zeekFlowFields+`, "method":"GET","host":"h","uri":"/"}`))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if obs.Flow.ZeekUID != "CHhAvVGS1DHFjwGM9" {
		t.Errorf("zeek_uid = %q", obs.Flow.ZeekUID)
	}
}

func TestZeekStripsURIQueryString(t *testing.T) {
	// A URI query routinely carries session tokens, API keys, and search terms.
	// Those belong in a capture artifact under its authorization boundary, not
	// in a log record with far wider read access.
	n := zeekNormalizer()
	line := `{` + zeekFlowFields + `, "method":"GET","host":"api.example.com","uri":"/v1/session?token=s3cr3tvalue&user=alice"}`

	obs, err := n.Normalize(ZeekHTTP, []byte(line))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if got := obs.Details.HTTP.URIPath; got != "/v1/session" {
		t.Errorf("uri_path = %q, want the path without its query", got)
	}
	if strings.Contains(obs.Details.HTTP.URIPath, "s3cr3tvalue") {
		t.Error("query string with a token was retained")
	}
}

func TestZeekPreservesMissedBytes(t *testing.T) {
	// missed_bytes is Zeek admitting its own view was incomplete. Dropping it
	// as noise would hide a capture gap from the analyst relying on the record.
	n := zeekNormalizer()
	obs, err := n.Normalize(ZeekConn, []byte(`{`+zeekFlowFields+`, "conn_state":"SF","missed_bytes":4096}`))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if obs.Details.Connection.MissedBytes == nil || *obs.Details.Connection.MissedBytes != 4096 {
		t.Errorf("missed_bytes = %v, want 4096", obs.Details.Connection.MissedBytes)
	}
}

func TestZeekRejectsMalformedRecords(t *testing.T) {
	n := zeekNormalizer()

	cases := map[string]struct {
		logType ZeekLogType
		line    string
	}{
		"invalid json":        {ZeekConn, `{"ts": 1787054370`},
		"missing ts":          {ZeekConn, `{"uid":"C1","conn_state":"SF"}`},
		"negative ts":         {ZeekConn, `{"ts":-5,"uid":"C1"}`},
		"dns without query":   {ZeekDNS, `{"ts":1787054370.1,"uid":"C1"}`},
		"notice without note": {ZeekNotice, `{"ts":1787054370.1,"uid":"C1","msg":"m"}`},
		"weird without name":  {ZeekWeird, `{"ts":1787054370.1,"uid":"C1"}`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			obs, err := n.Normalize(tc.logType, []byte(tc.line))
			if err == nil {
				t.Fatal("malformed record accepted")
			}
			if obs != nil {
				t.Error("malformed record produced an observation")
			}
		})
	}
}

func TestZeekRejectsUnsupportedLogType(t *testing.T) {
	n := zeekNormalizer()
	_, err := n.Normalize(ZeekLogType("smtp"), []byte(`{"ts":1787054370.1,"uid":"C1"}`))
	if !errors.Is(err, ErrUnsupportedRecord) {
		t.Fatalf("err = %v, want ErrUnsupportedRecord", err)
	}
}

func TestZeekErrorsNeverEchoRecordContent(t *testing.T) {
	n := zeekNormalizer()
	line := `{"ts":-1,"uid":"C1","query":"password=hunter2trombone.example.com"}`

	_, err := n.Normalize(ZeekDNS, []byte(line))
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "hunter2trombone") {
		t.Errorf("error echoed record content: %v", err)
	}
}

func TestZeekMalformedRecordDoesNotAffectItsNeighbours(t *testing.T) {
	// FR-016: one bad record must not stop valid ones. This is the unit-level
	// half; the tailer covers the streaming half.
	n := zeekNormalizer()
	good := `{` + zeekFlowFields + `, "service":"ssl","conn_state":"SF"}`

	if _, err := n.Normalize(ZeekConn, []byte(good)); err != nil {
		t.Fatalf("first good record: %v", err)
	}
	if _, err := n.Normalize(ZeekConn, []byte(`{"ts":`)); err == nil {
		t.Fatal("malformed record accepted")
	}
	if _, err := n.Normalize(ZeekConn, []byte(good)); err != nil {
		t.Fatalf("good record after a malformed one: %v", err)
	}
}

func TestZeekTimestampConversion(t *testing.T) {
	// Zeek emits epoch seconds as a float; the sub-second part is what orders
	// records within a burst.
	n := zeekNormalizer()
	obs, err := n.Normalize(ZeekConn, []byte(`{`+zeekFlowFields+`, "conn_state":"SF"}`))
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	want := time.Unix(1787054370, 123456000).UTC()
	if diff := obs.EventTime.Sub(want); diff > time.Millisecond || diff < -time.Millisecond {
		t.Errorf("event_time = %v, want ~%v", obs.EventTime, want)
	}
}

// A line captured from Zeek 8.0.10 running Trawl's own configuration on a node
// interface, taken verbatim from conn.log. The unit tests around it all passed
// while every record the deployed sensor read was rejected: the normalizer
// produced a correct observation and Validate refused it, because source.version
// is required with minLength 1 and the Version field was never set by the
// caller. The tailer counted it malformed, the sensor stayed ready, and the
// symptom was an interface that looked like it carried no traffic.
func TestRealZeekConnLinePassesTheFullAcceptPath(t *testing.T) {
	const line = `{"ts":1788116709.963403,"uid":"CGUv4r2as4kLerjD13","id.orig_h":"192.168.0.6",` +
		`"id.orig_p":50264,"id.resp_h":"185.199.108.154","id.resp_p":443,"proto":"tcp",` +
		`"service":"ssl","duration":0.6301510334014893,"orig_bytes":3203,"resp_bytes":0,` +
		`"conn_state":"S0","local_orig":true,"local_resp":false,"missed_bytes":0,` +
		`"history":"SAD","orig_pkts":283,"orig_ip_bytes":17963,"resp_pkts":0,` +
		`"resp_ip_bytes":0,"ip_proto":6,"community_id":"1:KKM1GXJNfDGxIwFg9L4zVHxF4TU="}`

	n := &ZeekNormalizer{
		Tap:     &Tap{Namespace: "trawl-system", Name: "node-eno1", UID: "f1bb32c4-eecb-4a55-bda7-ac7928b9d8ce"},
		Target:  Target{Node: "talos-node", Interface: "eno1"},
		Version: "zeek version 8.0.10",
	}

	obs, err := n.Normalize(ZeekConn, []byte(line))
	if err != nil {
		t.Fatalf("normalizing a real conn.log line: %v", err)
	}
	if err := Normalize(obs); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	// This is the step that rejected every record on the cluster.
	if err := Validate(obs); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if obs.Source.Version == "" {
		t.Error("source.version is empty; the schema requires it and the record would be dropped")
	}
	if obs.Flow == nil || obs.Flow.CommunityID == "" {
		t.Error("no community_id survived normalization; the exact pivot depends on it")
	}
}
