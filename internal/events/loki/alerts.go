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
	// Observations are the records that decoded successfully, oldest first.
	Observations []*observation.Observation

	// Malformed counts records that could not be decoded. They are skipped
	// rather than fatal: one unreadable line must not stop the alerts around
	// it from being evaluated.
	Malformed int

	// Truncated says the page hit the limit, so more records exist in the
	// window than were returned.
	Truncated bool
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

	return decode(body, limit), nil
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

func decode(body queryRangeResponse, limit int) Result {
	var result Result
	entries := 0

	for _, stream := range body.Data.Result {
		for _, value := range stream.Values {
			entries++
			if len(value) < 2 {
				result.Malformed++
				continue
			}
			line, ok := value[1].(string)
			if !ok {
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
				result.Malformed++
				continue
			}
			result.Observations = append(result.Observations, &obs)
		}
	}

	result.Truncated = entries >= limit
	return result
}
