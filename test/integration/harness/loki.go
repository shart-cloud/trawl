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

package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"trawl.cloud/trawl/internal/observation"
)

const (
	// lokiImage is pinned like every other image the tests run.
	lokiImage = "docker.io/grafana/loki:3.4.2"

	lokiStartupTimeout = 120 * time.Second

	// lokiRequestTimeout bounds a single API call.
	lokiRequestTimeout = 30 * time.Second
)

// lokiConfig enables the two features Trawl's label discipline depends on.
//
// TSDB with schema v13 and allow_structured_metadata are what make it possible
// to keep addresses, ports and rule IDs queryable without turning each into a
// Loki stream. Without them these tests would pass against a Loki that cannot
// actually support the query patterns the dashboards use.
const lokiConfig = `
auth_enabled: false
server:
  http_listen_port: 3100
  log_level: warn
common:
  instance_addr: 127.0.0.1
  path_prefix: /loki
  storage:
    filesystem:
      chunks_directory: /loki/chunks
      rules_directory: /loki/rules
  replication_factor: 1
  ring:
    kvstore:
      store: inmemory
schema_config:
  configs:
    - from: 2024-01-01
      store: tsdb
      object_store: filesystem
      schema: v13
      index:
        prefix: index_
        period: 24h
limits_config:
  allow_structured_metadata: true
  # Wide enough that fixtures anchored to a fixed date are accepted; a real
  # deployment would not permit this.
  reject_old_samples: false
  max_query_lookback: 0
`

// Loki is a running Loki container.
type Loki struct {
	// BaseURL addresses the Loki HTTP API.
	BaseURL string

	containerID string
	client      *http.Client
}

// RequireLoki starts Loki for one test, skipping when Docker is unavailable.
func RequireLoki(t *testing.T) *Loki {
	t.Helper()
	requireDocker(t)

	port, err := freePort(t.Context())
	if err != nil {
		t.Fatalf("finding a free port: %v", err)
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "loki.yaml")
	// 0644, not 0600: Loki runs as uid 10001 inside the container and cannot
	// read a file owned by the test user with owner-only permissions - the
	// container exits immediately and the failure looks like a startup timeout.
	// This is a non-secret test config, so world-readable is fine here.
	//nolint:gosec // G306: non-secret test configuration that the container must read
	if err := os.WriteFile(cfgPath, []byte(lokiConfig), 0o644); err != nil {
		t.Fatalf("writing loki config: %v", err)
	}

	out, err := exec.CommandContext(t.Context(), "docker", "run", "--detach", "--rm",
		"--publish", fmt.Sprintf("%d:3100", port),
		"--volume", cfgPath+":/etc/loki/local-config.yaml:ro",
		lokiImage,
		"-config.file=/etc/loki/local-config.yaml",
	).Output()
	if err != nil {
		t.Fatalf("starting Loki: %v", err)
	}

	l := &Loki{
		BaseURL:     fmt.Sprintf("http://127.0.0.1:%d", port),
		containerID: string(bytes.TrimSpace(out)),
		client:      &http.Client{Timeout: lokiRequestTimeout},
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := exec.CommandContext(stopCtx, "docker", "stop", l.containerID).Run(); err != nil {
			t.Logf("stopping Loki container %s: %v", l.containerID, err)
		}
	})

	if err := l.waitReady(t.Context()); err != nil {
		// Without the container's own logs a startup failure is
		// indistinguishable from a slow start, which cost real debugging time
		// the first time it happened.
		logs, _ := exec.CommandContext(t.Context(), "docker", "logs", "--tail", "20", l.containerID).CombinedOutput()
		t.Fatalf("waiting for Loki: %v\ncontainer logs:\n%s", err, logs)
	}
	return l
}

func (l *Loki) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(lokiStartupTimeout)
	var lastErr error

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.BaseURL+"/ready", nil)
		if err != nil {
			return err
		}
		resp, err := l.client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				// Loki reports ready slightly before it accepts writes.
				time.Sleep(2 * time.Second)
				return nil
			}
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("Loki did not become ready within %s: %w", lokiStartupTimeout, lastErr)
}

// Stream is one labelled stream of records to push.
type Stream struct {
	Labels  map[string]string
	Entries []Entry
}

// Entry is one log line with its timestamp and structured metadata.
type Entry struct {
	Timestamp          time.Time
	Line               string
	StructuredMetadata map[string]string
}

// Push writes streams to Loki, mirroring what Alloy sends.
func (l *Loki) Push(ctx context.Context, streams []Stream) error {
	type wireStream struct {
		Stream map[string]string `json:"stream"`
		Values [][]any           `json:"values"`
	}

	payload := struct {
		Streams []wireStream `json:"streams"`
	}{}

	for _, s := range streams {
		ws := wireStream{Stream: s.Labels}
		for _, e := range s.Entries {
			value := []any{strconv.FormatInt(e.Timestamp.UnixNano(), 10), e.Line}
			if len(e.StructuredMetadata) > 0 {
				value = append(value, e.StructuredMetadata)
			}
			ws.Values = append(ws.Values, value)
		}
		payload.Streams = append(payload.Streams, ws)
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.BaseURL+"/loki/api/v1/push", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := l.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode/100 != 2 {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		return fmt.Errorf("loki push returned %d: %s", resp.StatusCode, buf.String())
	}
	return nil
}

// QueryResult is one returned stream.
type QueryResult struct {
	Labels map[string]string
	Values [][]string
}

// Query runs a LogQL query over a time range.
func (l *Loki) Query(ctx context.Context, query string, start, end time.Time) ([]QueryResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.BaseURL+"/loki/api/v1/query_range", nil)
	if err != nil {
		return nil, err
	}
	q := req.URL.Query()
	q.Set("query", query)
	q.Set("start", strconv.FormatInt(start.UnixNano(), 10))
	q.Set("end", strconv.FormatInt(end.UnixNano(), 10))
	q.Set("limit", "1000")
	req.URL.RawQuery = q.Encode()

	resp, err := l.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		return nil, fmt.Errorf("loki query returned %d: %s", resp.StatusCode, buf.String())
	}

	var decoded struct {
		Data struct {
			Result []struct {
				Stream map[string]string `json:"stream"`
				Values [][]string        `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, err
	}

	out := make([]QueryResult, 0, len(decoded.Data.Result))
	for _, r := range decoded.Data.Result {
		out = append(out, QueryResult{Labels: r.Stream, Values: r.Values})
	}
	return out, nil
}

// CountEntries totals the entries across results.
func CountEntries(results []QueryResult) int {
	n := 0
	for _, r := range results {
		n += len(r.Values)
	}
	return n
}

// AttachLoki addresses a Loki this process did not start.
//
// The e2e investigation test runs against the cluster's shared Loki rather than
// a throwaway one, because what it is measuring - whether an analyst can find a
// record within thirty seconds of the traffic - is a property of the deployed
// ingestion path, not of Loki in general. A private instance would measure a
// pipeline nobody uses.
func AttachLoki(baseURL string) *Loki {
	return &Loki{
		BaseURL: strings.TrimSuffix(baseURL, "/"),
		client:  &http.Client{Timeout: lokiRequestTimeout},
	}
}

// ObservationStreams renders records the way the Alloy pipeline does: the four
// contract labels become stream labels, and the fields an analyst filters on
// become structured metadata.
//
// Both the integration tests and the e2e investigation test build their input
// through this function, so a change to the label discipline cannot leave one
// of them asserting against a shape the pipeline no longer produces.
//
// The offset shifts event times into a window Loki will serve; pass zero for
// records that are already recent.
func ObservationStreams(records []*observation.Observation, cluster string, offset time.Duration) []Stream {
	byLabels := map[string]*Stream{}

	for _, obs := range records {
		labels := map[string]string{
			"service_name":     "trawl-observation",
			"cluster":          cluster,
			"source_kind":      string(obs.Source.Kind),
			"observation_type": string(obs.ObservationType),
		}
		key := labels["source_kind"] + "|" + labels["observation_type"]
		if _, ok := byLabels[key]; !ok {
			byLabels[key] = &Stream{Labels: labels}
		}

		line, err := json.Marshal(obs)
		if err != nil {
			// An observation that cannot be encoded cannot be pushed; callers
			// build these from normalizers that have already validated them.
			continue
		}

		metadata := map[string]string{
			"tap_uid":          obs.Tap.UID,
			"tap_name":         obs.Tap.Name,
			"tap_namespace":    obs.Tap.Namespace,
			"target_node":      obs.Target.Node,
			"target_interface": obs.Target.Interface,
		}
		if obs.Flow != nil {
			metadata["community_id"] = obs.Flow.CommunityID
			metadata["zeek_uid"] = obs.Flow.ZeekUID
			metadata["protocol"] = obs.Flow.Protocol
			metadata["source_ip"] = obs.Flow.Source.IP
			metadata["destination_ip"] = obs.Flow.Destination.IP
			if p := obs.Flow.Source.Port; p != nil {
				metadata["source_port"] = strconv.Itoa(int(*p))
			}
			if p := obs.Flow.Destination.Port; p != nil {
				metadata["destination_port"] = strconv.Itoa(int(*p))
			}
		}
		if sig := obs.Details.Signature; sig != nil {
			metadata["severity"] = strconv.Itoa(int(sig.Severity))
			metadata["rule_id"] = strconv.Itoa(int(sig.RuleID))
			metadata["category"] = sig.Category
		}
		// Loki rejects empty structured-metadata values.
		for k, v := range metadata {
			if v == "" {
				delete(metadata, k)
			}
		}

		byLabels[key].Entries = append(byLabels[key].Entries, Entry{
			Timestamp:          obs.EventTime.Add(offset),
			Line:               string(line),
			StructuredMetadata: metadata,
		})
	}

	streams := make([]Stream, 0, len(byLabels))
	for _, s := range byLabels {
		streams = append(streams, *s)
	}
	return streams
}
