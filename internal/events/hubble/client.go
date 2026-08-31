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

package hubble

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"

	"trawl.cloud/trawl/internal/config"
	"trawl.cloud/trawl/internal/observation"
	"trawl.cloud/trawl/internal/sanitize"
)

// Reconnect bounds.
const (
	initialBackoff = time.Second
	maxBackoff     = 30 * time.Second

	// replayOverlap is how far back the stream resumes after a reconnect.
	//
	// Hubble's stream is lossy across disconnects and has no cursor, so the
	// only choices are to re-read a little or to skip a little. Re-reading is
	// the safe direction: duplicate flows carry stable IDs and are collapsed
	// downstream, whereas a skipped denied flow is a trigger that never fires
	// and evidence nobody knows is missing.
	replayOverlap = 30 * time.Second
)

// Client streams flows from Hubble Relay.
type Client struct {
	endpoint   string
	tlsConfig  *tls.Config
	normalizer *Normalizer

	mu        sync.Mutex
	connected bool
	watermark time.Time

	// OnGap is called when the client knows it lost coverage, so the gap is
	// reported rather than silently absorbed (FR-039).
	OnGap func(reason string)

	// OnReject is called when a flow produced no record Trawl can store, so a
	// dropped record is counted rather than being indistinguishable from
	// traffic that never happened (FR-016).
	OnReject func(reason string)

	// OnConnectionChange reports connection state for
	// trawl_trigger_source_connected.
	OnConnectionChange func(connected bool)
}

// NewClient builds a Hubble client from mounted mTLS material.
//
// Hubble Relay is authenticated with mutual TLS: the flows it serves describe
// every connection in the cluster, so an unauthenticated reader would be a
// cluster-wide traffic disclosure.
func NewClient(cfg config.HubbleConfig, normalizer *Normalizer) (*Client, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("hubble endpoint is not configured")
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, sanitize.Errorf("loading hubble client certificate: %v", err)
	}
	caPEM, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, sanitize.Errorf("reading hubble CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("hubble CA file contains no usable certificate")
	}

	return &Client{
		endpoint:   cfg.Endpoint,
		normalizer: normalizer,
		tlsConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      pool,
			ServerName:   cfg.ServerName,
			MinVersion:   tls.VersionTLS13,
		},
	}, nil
}

// Connected reports whether the flow stream is currently healthy.
func (c *Client) Connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

// Watermark returns the event time of the latest fully processed flow.
//
// It is the resume point after a reconnect and the input to trigger lag.
func (c *Client) Watermark() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.watermark
}

// Run streams flows until ctx is cancelled, reconnecting with backoff.
//
// A disconnect is a coverage gap, not a fatal error: the cluster keeps
// producing flows whether or not Trawl is listening. Run therefore reconnects
// indefinitely and reports each gap rather than returning, because exiting
// would turn a transient relay restart into a permanent loss of denied-flow
// triggers.
func (c *Client) Run(ctx context.Context, handle func(context.Context, *ParsedFlow) error) error {
	backoff := initialBackoff

	for {
		if err := ctx.Err(); err != nil {
			return nil
		}

		err := c.streamOnce(ctx, handle)
		c.setConnected(false)

		switch {
		case ctx.Err() != nil:
			return nil
		case err != nil:
			c.reportGap("stream_error")
		default:
			// A clean end of stream is still a gap: the relay stopped sending
			// and flows continued in the cluster meanwhile.
			c.reportGap("stream_closed")
		}

		if !sleepCtx(ctx, backoff) {
			return nil
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

// ParsedFlow is one normalized flow handed to the worker.
type ParsedFlow struct {
	Observation *observation.Observation
	EventTime   time.Time
}

func (c *Client) streamOnce(ctx context.Context, handle func(context.Context, *ParsedFlow) error) error {
	conn, err := grpc.NewClient(c.endpoint,
		grpc.WithTransportCredentials(credentials.NewTLS(c.tlsConfig)))
	if err != nil {
		return sanitize.Errorf("connecting to hubble: %v", err)
	}
	defer func() { _ = conn.Close() }()

	client := observerpb.NewObserverClient(conn)

	// Resume slightly before the watermark. See replayOverlap: duplicates are
	// collapsible, a skipped denied flow is not recoverable.
	req := &observerpb.GetFlowsRequest{Follow: true}
	if since := c.resumePoint(); !since.IsZero() {
		req.Since = timestamppb.New(since)
	}

	stream, err := client.GetFlows(ctx, req)
	if err != nil {
		return sanitize.Errorf("opening hubble flow stream: %v", err)
	}

	c.setConnected(true)

	for {
		resp, err := stream.Recv()
		switch {
		case errors.Is(err, io.EOF):
			return nil
		case err != nil:
			if ctx.Err() != nil {
				return nil
			}
			return sanitize.Errorf("receiving hubble flow: %v", err)
		}

		// The relay reports its own losses. Passing them through is the
		// difference between a known gap and silently thinner evidence.
		if lost := resp.GetLostEvents(); lost != nil {
			c.reportGap("relay_lost_events")
			continue
		}

		flow := resp.GetFlow()
		if flow == nil {
			continue
		}

		obs, ok := c.accept(flow)
		if !ok {
			continue
		}

		parsed := &ParsedFlow{Observation: obs, EventTime: obs.EventTime}
		if err := handle(ctx, parsed); err != nil {
			return err
		}
		c.advanceWatermark(obs.EventTime)
	}
}

// accept converts one flow into a record the worker may emit.
//
// The validation here is the same discipline the sensor's tailer applies, and
// for the same reason: Loki enforces no schema, so a record that does not
// satisfy the contract is stored without complaint and only discovered when a
// dashboard query silently returns nothing. Validating at the worker turns that
// into a counted rejection.
//
// One bad flow must never end the stream, so both failures drop the record and
// continue - but neither drops it silently.
func (c *Client) accept(flow *flowpb.Flow) (*observation.Observation, bool) {
	obs, err := c.normalizer.Normalize(flow)
	if err != nil {
		c.reportReject(RejectUnparseable)
		return nil, false
	}
	if err := observation.Validate(obs); err != nil {
		// The error quotes the offending instance, which for a flow includes
		// addresses. Only the reason is reported.
		c.reportReject(RejectSchema)
		return nil, false
	}
	return obs, true
}

func (c *Client) reportReject(reason string) {
	if c.OnReject != nil {
		c.OnReject(reason)
	}
}

// Reasons a flow produced no storable record.
const (
	// RejectUnparseable means the flow could not be normalized at all.
	RejectUnparseable = "unparseable"

	// RejectSchema means the record did not satisfy the observation contract -
	// most likely a field whose value set has widened in a newer Cilium.
	RejectSchema = "schema"
)

// resumePoint returns where a reconnecting stream should restart.
func (c *Client) resumePoint() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.watermark.IsZero() {
		return time.Time{}
	}
	return c.watermark.Add(-replayOverlap)
}

// advanceWatermark moves the watermark forward only.
//
// Hubble can deliver slightly out of order, and letting the watermark move
// backwards would re-request flows already handled on every subsequent
// reconnect.
func (c *Client) advanceWatermark(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t.After(c.watermark) {
		c.watermark = t
	}
}

func (c *Client) setConnected(v bool) {
	c.mu.Lock()
	changed := c.connected != v
	c.connected = v
	c.mu.Unlock()

	if changed && c.OnConnectionChange != nil {
		c.OnConnectionChange(v)
	}
}

func (c *Client) reportGap(reason string) {
	if c.OnGap != nil {
		c.OnGap(reason)
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
