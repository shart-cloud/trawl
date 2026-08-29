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
	"strings"
	"time"
)

// ErrUnsupportedRecord marks an analyzer record Trawl does not model.
//
// It is distinct from a malformed record: unsupported means well-formed but not
// one of the types this release normalizes, and the two are counted separately
// so an operator can tell "the analyzer emits something new" from "the analyzer
// is producing garbage".
var ErrUnsupportedRecord = errors.New("unsupported analyzer record")

// suricataTimeLayout is Suricata's EVE timestamp format: ISO 8601 with
// microseconds and a numeric offset.
const suricataTimeLayout = "2006-01-02T15:04:05.999999-0700"

// eveRecord is the subset of Suricata EVE JSON that Trawl reads.
//
// Only named fields are decoded. EVE carries far more, including payload,
// packet bytes, and full HTTP headers, and decoding into a generic map would
// make it easy for that content to reach a log line by accident.
type eveRecord struct {
	Timestamp   string `json:"timestamp"`
	EventType   string `json:"event_type"`
	FlowID      int64  `json:"flow_id"`
	CommunityID string `json:"community_id"`

	SrcIP    string  `json:"src_ip"`
	SrcPort  *int32  `json:"src_port"`
	DestIP   string  `json:"dest_ip"`
	DestPort *int32  `json:"dest_port"`
	Proto    string  `json:"proto"`
	VLAN     []int32 `json:"vlan"`

	Alert *struct {
		SignatureID int64  `json:"signature_id"`
		Rev         *int64 `json:"rev"`
		Signature   string `json:"signature"`
		Category    string `json:"category"`
		Severity    int32  `json:"severity"`
		Action      string `json:"action"`
	} `json:"alert"`

	Stats *eveStats `json:"stats"`
}

// eveStats is Suricata's periodic counter record. It is not an observation; it
// feeds target health, which is why packet and drop counters are read here
// rather than inferred from record volume.
type eveStats struct {
	Capture struct {
		KernelPackets *int64 `json:"kernel_packets"`
		KernelDrops   *int64 `json:"kernel_drops"`
	} `json:"capture"`
	Decoder struct {
		Packets *int64 `json:"pkts"`
	} `json:"decoder"`
}

// SuricataStats carries counters lifted from an EVE stats record.
type SuricataStats struct {
	KernelPackets  *int64
	KernelDrops    *int64
	DecoderPackets *int64
	Timestamp      time.Time
}

// SuricataNormalizer converts EVE JSON into normalized observations.
type SuricataNormalizer struct {
	// Version is the analyzer version reported on each record.
	Version string
	// Tap and Target identify where these records came from.
	Tap    *Tap
	Target Target
	// Now supplies the observation timestamp.
	Now func() time.Time
}

// Normalize converts one EVE line.
//
// A stats record returns (nil, nil, stats): it is health data, not an
// observation, and emitting it as one would inflate observation counts with
// records that describe no traffic.
func (n *SuricataNormalizer) Normalize(line []byte) (*Observation, *SuricataStats, error) {
	var rec eveRecord
	if err := json.Unmarshal(line, &rec); err != nil {
		// The raw line may contain traffic content, so it is never echoed.
		return nil, nil, fmt.Errorf("malformed EVE record: invalid JSON")
	}

	switch rec.EventType {
	case "alert":
		obs, err := n.normalizeAlert(&rec)
		return obs, nil, err
	case "stats":
		return nil, n.normalizeStats(&rec), nil
	case "":
		return nil, nil, errors.New("malformed EVE record: missing event_type")
	default:
		// Suricata emits dns, http, tls and more. Zeek is Trawl's source for
		// protocol metadata (ADR-0001), so consuming Suricata's too would
		// double-count every exchange.
		return nil, nil, fmt.Errorf("%w: event_type %q", ErrUnsupportedRecord, safeEventType(rec.EventType))
	}
}

func (n *SuricataNormalizer) normalizeAlert(rec *eveRecord) (*Observation, error) {
	if rec.Alert == nil {
		return nil, errors.New("malformed EVE alert: missing alert body")
	}
	if rec.Alert.SignatureID == 0 {
		return nil, errors.New("malformed EVE alert: missing signature_id")
	}

	eventTime, err := parseSuricataTime(rec.Timestamp)
	if err != nil {
		return nil, err
	}

	obs := &Observation{
		SchemaVersion:   SchemaVersion,
		ID:              recordID(SourceSuricata, rec.CommunityID, rec.Alert.SignatureID, eventTime),
		EventTime:       eventTime,
		ObservedAt:      n.now(),
		Source:          Source{Kind: SourceSuricata, Version: n.Version},
		Tap:             n.Tap,
		Target:          n.Target,
		ObservationType: TypeSignature,
		Flow:            n.flowFrom(rec),
		Details: Details{
			Signature: &Signature{
				RuleID:   rec.Alert.SignatureID,
				Revision: rec.Alert.Rev,
				Severity: rec.Alert.Severity,
				Category: rec.Alert.Category,
				Message:  rec.Alert.Signature,
				Action:   rec.Alert.Action,
			},
		},
	}
	return obs, nil
}

// flowFrom builds the shared flow envelope.
//
// Community ID is copied verbatim from Suricata rather than recomputed. It is
// the exact-pivot key to Zeek's records, and two independent implementations of
// the hash would eventually disagree on an edge case, silently breaking
// correlation for exactly the flows that are hardest to reason about.
func (n *SuricataNormalizer) flowFrom(rec *eveRecord) *Flow {
	if rec.SrcIP == "" && rec.DestIP == "" {
		return nil
	}
	flow := &Flow{
		CommunityID: rec.CommunityID,
		Protocol:    strings.ToLower(rec.Proto),
		Source:      Endpoint{IP: rec.SrcIP, Port: rec.SrcPort},
		Destination: Endpoint{IP: rec.DestIP, Port: rec.DestPort},
	}
	if len(rec.VLAN) > 0 {
		vlan := rec.VLAN[0]
		flow.VLAN = &vlan
	}
	return flow
}

func (n *SuricataNormalizer) normalizeStats(rec *eveRecord) *SuricataStats {
	if rec.Stats == nil {
		return nil
	}
	ts, err := parseSuricataTime(rec.Timestamp)
	if err != nil {
		ts = n.now()
	}
	return &SuricataStats{
		KernelPackets:  rec.Stats.Capture.KernelPackets,
		KernelDrops:    rec.Stats.Capture.KernelDrops,
		DecoderPackets: rec.Stats.Decoder.Packets,
		Timestamp:      ts,
	}
}

func (n *SuricataNormalizer) now() time.Time {
	if n.Now != nil {
		return n.Now().UTC()
	}
	return time.Now().UTC()
}

func parseSuricataTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, errors.New("malformed EVE record: missing timestamp")
	}
	t, err := time.Parse(suricataTimeLayout, s)
	if err != nil {
		// Try RFC3339, which Suricata emits when configured for it.
		if t2, err2 := time.Parse(time.RFC3339Nano, s); err2 == nil {
			return t2.UTC(), nil
		}
		return time.Time{}, errors.New("malformed EVE record: unparseable timestamp")
	}
	return t.UTC(), nil
}

// safeEventType bounds an event_type before it appears in an error, since it
// originates from the analyzer's input.
func safeEventType(s string) string {
	const max = 32
	if len(s) > max {
		return s[:max]
	}
	return s
}
