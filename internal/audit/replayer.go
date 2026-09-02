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

package audit

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"trawl.cloud/trawl/internal/sanitize"
	"trawl.cloud/trawl/internal/telemetry"
)

// DefaultReplayInterval is how often the ledger is swept for records the
// searchable stream has not seen.
//
// Audit search is not on any request path, so the interval trades promptness
// against a LIST per tick against the object store. Thirty seconds keeps an
// admission decision searchable well inside the minute an operator would wait
// before assuming something is wrong.
const DefaultReplayInterval = 30 * time.Second

// CursorStore persists the replay cursor across restarts.
//
// Load returns the empty string when no cursor has been stored yet. That is
// distinct from an error: an absent cursor means "replay from the beginning",
// while an error means "the cursor is unknown", and replaying from the
// beginning because the API server was briefly unreachable would re-forward the
// entire ledger on every tick of an outage.
type CursorStore interface {
	Load(ctx context.Context) (string, error)
	Save(ctx context.Context, cursor string) error
}

// ReplayOptions configures a Replayer.
type ReplayOptions struct {
	// Sink is the ledger being replayed.
	Sink *Sink

	// Cursor persists how far replay has got.
	Cursor CursorStore

	// Out is the searchable stream. In the manager this is os.Stdout, which
	// Alloy collects into Loki (config/alloy/trawl-audit.alloy).
	Out io.Writer

	// Metrics is optional; when set, the replay counter and the two backlog
	// gauges are maintained.
	Metrics *telemetry.Metrics

	// Interval defaults to DefaultReplayInterval.
	Interval time.Duration

	// Now is indirected for tests.
	Now func() time.Time
}

// Replayer forwards committed ledger records to the searchable stream.
//
// The ledger is authoritative and this stream is a copy, which decides every
// tradeoff here. Duplicate delivery is acceptable because copies keep their
// stable key and audit views collapse by it; a skipped record is not, because
// nothing would ever notice it missing. So the cursor advances only over
// records the stream actually accepted, and it is re-delivered on the next
// pass rather than stepped over.
//
// This is the producer the Alloy audit pipeline consumes. Without it the
// pipeline is well-formed and collects nothing, and an audit query returns an
// empty result rather than an error.
type Replayer struct {
	sink     *Sink
	cursor   CursorStore
	out      io.Writer
	metrics  *telemetry.Metrics
	interval time.Duration
	now      func() time.Time

	// writes to Out are serialised: the manager's stdout is shared with its
	// logger, and a record interleaved with a log line is a record no JSON
	// parser recovers.
	mu sync.Mutex
}

// NewReplayer validates the options and returns a Replayer.
func NewReplayer(opts ReplayOptions) (*Replayer, error) {
	switch {
	case opts.Sink == nil:
		return nil, errors.New("audit replayer requires a sink")
	case opts.Cursor == nil:
		return nil, errors.New("audit replayer requires a cursor store")
	case opts.Out == nil:
		return nil, errors.New("audit replayer requires an output stream")
	}

	r := &Replayer{
		sink:     opts.Sink,
		cursor:   opts.Cursor,
		out:      opts.Out,
		metrics:  opts.Metrics,
		interval: opts.Interval,
		now:      opts.Now,
	}
	if r.interval <= 0 {
		r.interval = DefaultReplayInterval
	}
	if r.now == nil {
		r.now = time.Now
	}
	return r, nil
}

// NeedLeaderElection reports that only the leader replays.
//
// Two replicas sweeping one ledger would double every audit line in Loki and
// write conflicting cursors to the same ConfigMap.
func (r *Replayer) NeedLeaderElection() bool { return true }

// Start runs replay until the context is cancelled, satisfying
// manager.Runnable.
//
// A failed pass is logged by its caller and retried on the next tick rather
// than returned: returning would stop the manager, and an audit stream that is
// behind is not a reason to stop reconciling taps. The ledger is unaffected
// either way.
func (r *Replayer) Start(ctx context.Context) error {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	// Sweep immediately. A manager that has just taken leadership is exactly
	// when the backlog is largest.
	_ = r.ReplayOnce(ctx)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			_ = r.ReplayOnce(ctx)
		}
	}
}

// ReplayOnce forwards everything the stream has not seen and persists how far
// it got.
func (r *Replayer) ReplayOnce(ctx context.Context) error {
	cursor, err := r.cursor.Load(ctx)
	if err != nil {
		return sanitize.Errorf("loading the audit replay cursor: %v", err)
	}

	// last names the final record the stream accepted, which is what the cursor
	// may advance to. Replay's own count is not enough: it says how many were
	// forwarded, not which key that leaves us at.
	last := ""
	delivered, replayErr := r.sink.Replay(ctx, cursor, func(_ context.Context, rec Record) error {
		if err := r.write(rec); err != nil {
			return err
		}
		last = rec.LedgerKey
		return nil
	})

	if r.metrics != nil && delivered > 0 {
		r.metrics.AuditReplayTotal.WithLabelValues(telemetry.AuditResultSuccess).Add(float64(delivered))
	}

	// Persist before returning any error. A pass that forwarded ten records and
	// failed on the eleventh must not re-forward those ten on every retry.
	saveErr := error(nil)
	if last != "" && last != cursor {
		if saveErr = r.cursor.Save(ctx, last); saveErr != nil {
			saveErr = sanitize.Errorf("persisting the audit replay cursor: %v", saveErr)
		}
	}

	if replayErr != nil && r.metrics != nil {
		r.metrics.AuditReplayTotal.WithLabelValues(telemetry.AuditResultUnavailable).Inc()
	}

	// The backlog is reported against the cursor that was actually persisted.
	// Reporting against the one replay reached would claim a drained stream
	// whenever the cursor write was the thing that failed.
	reported := cursor
	if saveErr == nil && last != "" {
		reported = last
	}
	r.reportBacklog(ctx, reported)

	return errors.Join(replayErr, saveErr)
}

// write emits one record as a single JSON line.
func (r *Replayer) write(rec Record) error {
	body, err := Encode(rec)
	if err != nil {
		return sanitize.Errorf("encoding an audit record for the stream: %v", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err := r.out.Write(append(body, '\n')); err != nil {
		return sanitize.Errorf("writing an audit record to the stream: %v", err)
	}
	return nil
}

// reportBacklog maintains the two gauges that say whether the searchable copy
// is keeping up with the ledger.
//
// Both were registered long before anything set them, so they read zero -
// "nothing unforwarded" - while the entire ledger was unforwarded. A failure
// to measure the backlog is reported as no measurement rather than as a zero,
// which is the distinction that made the original silence possible.
func (r *Replayer) reportBacklog(ctx context.Context, cursor string) {
	if r.metrics == nil {
		return
	}
	objects, oldest, err := r.sink.Backlog(ctx, cursor)
	if err != nil {
		return
	}
	r.metrics.AuditBacklogObjects.Set(float64(objects))
	if objects == 0 || oldest.IsZero() {
		r.metrics.AuditOldestUnforwardedSecs.Set(0)
		return
	}
	r.metrics.AuditOldestUnforwardedSecs.Set(r.now().Sub(oldest).Seconds())
}
