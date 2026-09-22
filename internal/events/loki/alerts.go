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

package loki

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"trawl.cloud/trawl/internal/observation"
)

// AlertQuery selects Suricata signature observations.
//
// Deliberately not narrowed by severity or rule. Each armed policy carries its
// own filters and is evaluated independently, so encoding one policy's criteria
// into the shared query would starve every other policy of the records it needs.
// The labels here are the three the pipeline promotes, and they are what makes
// this stream cheap to select (contracts/telemetry.md).
const AlertQuery = `{service_name="trawl-observation", observation_type="signature", source_kind="Suricata"}`

// DefaultLimit bounds one range query.
//
// A poll that returns everything Loki holds would be unbounded work on a busy
// sensor and an unbounded response to hold in memory. Hitting the limit is
// reported rather than hidden, because a truncated page means records were not
// examined.
const DefaultLimit = 1000

// Client reads alerts back out of the observation pipeline.
type Client struct {
	endpoint string
	tenantID string
	http     *http.Client

	// Limit bounds one query. Zero means DefaultLimit.
	Limit int
}

// NewClient addresses a Loki instance.
func NewClient(endpoint, tenantID string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		endpoint: strings.TrimSuffix(endpoint, "/"),
		tenantID: tenantID,
		http:     httpClient,
	}
}

// Result is one page of decoded alerts.
type Result struct {
	// Rows are the cursor facts for every row Loki returned, including rows
	// whose observation payload was malformed. A row with a valid Loki
	// timestamp was consumed and must remain representable independently of
	// whether attacker-influenced content decoded.
	Rows []Row

	// Observations are the records that decoded successfully, oldest first.
	// Deprecated: callers that advance a cursor must iterate Rows so malformed
	// payloads cannot pin progress.
	Observations []*observation.Observation

	// Malformed counts records that could not be decoded. They are skipped
	// rather than fatal: one unreadable line must not stop the alerts around
	// it from being evaluated.
	Malformed int

	// Truncated says the page hit the limit, so more records exist in the
	// window than were returned.
	Truncated bool
}

// Row is one consumed Loki row.
//
// Timestamp and ID are deliberately independent of Observation. They are the
// minimum facts a cursor needs to advance past a malformed payload without
// storing or logging that payload. Observation is nil when decoding failed.
type Row struct {
	Timestamp   time.Time
	ID          string
	Observation *observation.Observation
}

// Alerts queries one bounded time range.
func (c *Client) Alerts(ctx context.Context, start, end time.Time) (Result, error) {
	limit := c.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}

	params := url.Values{}
	params.Set("query", AlertQuery)
	params.Set("start", strconv.FormatInt(start.UnixNano(), 10))
	params.Set("end", strconv.FormatInt(end.UnixNano(), 10))
	params.Set("limit", strconv.Itoa(limit))
	// Oldest first, so a truncated page is the front of the window rather than
	// an arbitrary slice of it and the cursor can advance over what was read.
	params.Set("direction", "forward")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.endpoint+"/loki/api/v1/query_range?"+params.Encode(), nil)
	if err != nil {
		return Result{}, fmt.Errorf("building alert query: %w", err)
	}
	if c.tenantID != "" {
		req.Header.Set("X-Scope-OrgID", c.tenantID)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("querying alerts: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("querying alerts: loki returned %s", resp.Status)
	}

	var body queryRangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return Result{}, fmt.Errorf("decoding alert response: %w", err)
	}

	return decode(body, limit)
}

// queryRangeResponse is the subset of Loki's response this reads.
//
// Each value is [timestamp, line]. The promoted labels and structured metadata
// arrive in the stream map, but the line carries the whole envelope and is
// authoritative, so only the line is decoded - the labels are what made the
// query cheap, not a second copy of the record.
type queryRangeResponse struct {
	Data struct {
		Result []struct {
			Values [][]any `json:"values"`
		} `json:"result"`
	} `json:"data"`
}

func decode(body queryRangeResponse, limit int) (Result, error) {
	var result Result
	entries := 0

	for streamIndex, stream := range body.Data.Result {
		for rowIndex, value := range stream.Values {
			entries++
			if len(value) == 0 {
				return Result{}, fmt.Errorf("decoding alert response: row %d in stream %d has no timestamp", rowIndex, streamIndex)
			}
			rawTimestamp, ok := value[0].(string)
			if !ok {
				return Result{}, fmt.Errorf("decoding alert response: row %d in stream %d has a non-string timestamp", rowIndex, streamIndex)
			}
			nanoseconds, err := strconv.ParseInt(rawTimestamp, 10, 64)
			if err != nil || nanoseconds < 0 {
				return Result{}, fmt.Errorf("decoding alert response: row %d in stream %d has an unusable timestamp", rowIndex, streamIndex)
			}
			at := time.Unix(0, nanoseconds).UTC()

			if len(value) < 2 {
				result.Rows = append(result.Rows, Row{
					Timestamp: at,
					ID:        malformedRowID(rawTimestamp, []byte("missing-line")),
				})
				result.Malformed++
				continue
			}
			line, ok := value[1].(string)
			if !ok {
				encoded, marshalErr := json.Marshal(value[1])
				if marshalErr != nil {
					encoded = []byte(fmt.Sprintf("%T", value[1]))
				}
				result.Rows = append(result.Rows, Row{
					Timestamp: at,
					ID:        malformedRowID(rawTimestamp, encoded),
				})
				result.Malformed++
				continue
			}
			var obs observation.Observation
			if err := json.Unmarshal([]byte(line), &obs); err != nil {
				// The line is not included anywhere. A record that failed to
				// decode is still evidence, and it reached us from the network:
				// logging it would copy attacker-influenced content into the
				// worker's own logs, which are read by people and shipped to
				// the same Loki. The count is what an operator needs.
				result.Rows = append(result.Rows, Row{
					Timestamp: at,
					ID:        malformedRowID(rawTimestamp, []byte(line)),
				})
				result.Malformed++
				continue
			}
			id := obs.ID
			if id == "" {
				// A JSON object can decode without satisfying the observation
				// contract. Retain a row-specific identity so several such
				// records do not all collapse onto the empty ID.
				id = malformedRowID(rawTimestamp, []byte(line))
			}
			result.Rows = append(result.Rows, Row{Timestamp: at, ID: id, Observation: &obs})
			result.Observations = append(result.Observations, &obs)
		}
	}

	result.Truncated = entries >= limit
	return result, nil
}

// malformedRowID produces a stable, non-payload cursor identity. The digest is
// intentionally not exposed as diagnostics; it exists only to let the bounded
// handled set recognize the same Loki row during overlap replay.
func malformedRowID(timestamp string, payload []byte) string {
	h := sha256.New()
	_, _ = h.Write([]byte(timestamp))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(payload)
	return fmt.Sprintf("loki-row-%x", h.Sum(nil))
}
