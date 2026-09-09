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

package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/controller"
	"trawl.cloud/trawl/internal/events/hubble"
	"trawl.cloud/trawl/internal/events/loki"
	"trawl.cloud/trawl/internal/observation"
	"trawl.cloud/trawl/internal/sanitize"
	"trawl.cloud/trawl/internal/status"
	"trawl.cloud/trawl/internal/telemetry"
)

const (
	// alertOverlap is how far before the cursor each alert query starts.
	//
	// The observation pipeline writes each record with its event time, not its
	// ingestion time, so records are ordered by the producer's clock and an
	// older record can be written after a newer one. Overlapping and
	// suppressing by identity is the only way to catch those; the cursor's
	// handled-set is what stops the overlap re-triggering them.
	alertOverlap = 2 * time.Minute

	// maxAlertLookback bounds how far back a cold or stale cursor resumes.
	//
	// Without it a lost cursor would ask Loki for every record it holds, and
	// every alert in that history would be evaluated as if it had just
	// happened - a capture storm caused by restarting the worker.
	maxAlertLookback = time.Hour

	// gapCursorLost is the coverage the alert cursor could not span.
	gapCursorLost = "cursor_beyond_lookback"

	// gapQueryFailed is a poll that returned nothing because it failed.
	gapQueryFailed = "alert_query_failed"

	// eventReplayed counts a record the overlap re-delivered and the cursor
	// suppressed. Distinct from accepted: a rising replay count with a flat
	// accepted count is an overlap wider than it needs to be, not traffic.
	eventReplayed = "replayed"

	// finalFlushGrace bounds the last status write after the context is
	// cancelled, so a handoff records what this leader decided instead of
	// losing it.
	finalFlushGrace = 5 * time.Second
)

// worker is the leader-elected half of the event worker.
//
// Everything here evaluates policies or creates captures, which is exactly what
// two workers must not do at once: two leaders would create two captures for
// one event. The probe server and the metrics registry deliberately live
// outside it, so a standby still answers probes and reports why it is standing
// by.
type worker struct {
	engine  *controller.PolicyEngine
	tracker *controller.PolicyStatusTracker
	emitter *emitter

	flows   *hubble.Client
	alerts  *loki.Client
	cursors *loki.ConfigMapStore

	// reader is the cache-backed client used to recompute the replay window.
	reader    client.Reader
	namespace string
	metrics   *telemetry.Metrics

	pollInterval   time.Duration
	statusInterval time.Duration

	mu          sync.Mutex
	alertHealth controller.SourceHealth
}

// NeedLeaderElection keeps this off every worker but the leader.
func (w *worker) NeedLeaderElection() bool { return true }

// Start runs the three loops until the context is cancelled.
//
// They are independent on purpose. A Loki outage must not stop denied-flow
// triggers, a Hubble reconnect must not stall alert polling, and neither must
// stop status being written - otherwise the first failure would take the
// policies' own reporting with it, and an operator would see healthy policies
// and no captures (FR-038).
func (w *worker) Start(ctx context.Context) error {
	var wg sync.WaitGroup
	for _, loop := range []func(context.Context){w.runFlows, w.runAlerts, w.runStatus} {
		wg.Go(func() { loop(ctx) })
	}
	wg.Wait()

	// The decisions taken since the last flush are still only in memory.
	// Losing them at a handoff would understate what this leader collected,
	// and the counters are meant to be a record of the policy rather than of
	// whichever leader happened to be running.
	flushCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), finalFlushGrace)
	defer cancel()
	if err := w.tracker.Flush(flushCtx, w.sourceHealth()); err != nil {
		logf("final status flush: %v", sanitize.Error(err))
	}
	return nil
}

// runFlows consumes the Hubble stream.
func (w *worker) runFlows(ctx context.Context) {
	err := w.flows.Run(ctx, func(ctx context.Context, flow *hubble.ParsedFlow) error {
		w.metrics.TriggerEventsTotal.
			WithLabelValues(telemetry.TriggerSourceHubbleRelay, telemetry.RecordAccepted).Inc()
		w.metrics.TriggerLagSeconds.
			WithLabelValues(telemetry.TriggerSourceHubbleRelay).
			Set(time.Since(flow.EventTime).Seconds())

		// Emitted first. The observation record is US2's contract and does not
		// depend on any policy being armed, so a policy failure must not cost
		// the evidence that the flow happened.
		if err := w.emitter.emit(flow.Observation); err != nil {
			return err
		}
		w.evaluate(ctx, flow.Observation)
		return nil
	})
	if err != nil {
		logf("hubble stream: %v", sanitize.Error(err))
	}
}

// runAlerts polls the Suricata alert stream.
//
// Polled rather than streamed because alerts reach the worker through the
// observation pipeline: the sensor writes them to stdout, Alloy ships them, and
// Loki holds them. There is no connection to hold open, so the poll interval is
// the floor on how late a signature-triggered capture starts.
func (w *worker) runAlerts(ctx context.Context) {
	cursor, err := w.cursors.Load(ctx)
	if err != nil {
		// Could not read the resume position. The zero cursor resumes at the
		// bounded lookback and says so, which is recoverable; refusing to poll
		// would mean no signature triggers at all until someone noticed.
		logf("reading the alert cursor: %v", sanitize.Error(err))
	}

	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()
	for {
		if err := w.pollAlerts(ctx, &cursor); err != nil {
			logf("polling alerts: %v", sanitize.Error(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// pollAlerts reads one bounded window and evaluates what it returns.
func (w *worker) pollAlerts(ctx context.Context, cursor *loki.Cursor) error {
	now := time.Now()
	start, gap := cursor.Resume(now, alertOverlap, maxAlertLookback)
	if gap {
		// The window between the cursor and the lookback floor was never
		// examined and cannot be now. Saying so is what separates "the network
		// was quiet" from "nobody was looking" (FR-039).
		w.metrics.TriggerGapTotal.
			WithLabelValues(telemetry.TriggerSourceSuricataLoki, gapCursorLost).Inc()
	}

	result, err := w.alerts.Alerts(ctx, start, now)
	if err != nil {
		w.setAlertHealth(controller.SourceHealth{
			Reason:  status.ReasonSourceDisconnected,
			Message: "the alert query did not answer",
		})
		w.metrics.TriggerSourceConnected.WithLabelValues(telemetry.TriggerSourceSuricataLoki).Set(0)
		w.metrics.TriggerGapTotal.
			WithLabelValues(telemetry.TriggerSourceSuricataLoki, gapQueryFailed).Inc()
		// The cursor is deliberately not advanced and not saved. Advancing over
		// a window that was never read would turn a transient outage into
		// permanently unexamined coverage.
		return err
	}

	w.setAlertHealth(controller.SourceHealth{Connected: true})
	w.metrics.TriggerSourceConnected.WithLabelValues(telemetry.TriggerSourceSuricataLoki).Set(1)

	for range result.Malformed {
		w.metrics.TriggerEventsTotal.
			WithLabelValues(telemetry.TriggerSourceSuricataLoki, telemetry.RecordMalformed).Inc()
	}
	if result.Truncated {
		// Not counted as a gap. The page is the front of the window and the
		// cursor advances over what was read, so the rest is backlog rather
		// than lost coverage - and if the backlog ever outruns the lookback,
		// Resume reports that as the gap it then really is.
		logf("the alert query filled its page; the worker is behind")
	}

	for _, obs := range result.Observations {
		if cursor.Handled(obs.ID) {
			w.metrics.TriggerEventsTotal.
				WithLabelValues(telemetry.TriggerSourceSuricataLoki, eventReplayed).Inc()
			continue
		}
		w.metrics.TriggerEventsTotal.
			WithLabelValues(telemetry.TriggerSourceSuricataLoki, telemetry.RecordAccepted).Inc()
		w.metrics.TriggerLagSeconds.
			WithLabelValues(telemetry.TriggerSourceSuricataLoki).
			Set(now.Sub(obs.EventTime).Seconds())

		w.evaluate(ctx, obs)
		// Advanced whatever the evaluation decided, including a failure. The
		// failure is already recorded on the policy, and re-delivering the
		// record next poll would retry it forever without the cursor ever
		// moving.
		cursor.Advance(obs.EventTime, obs.ID)
	}

	cursor.Prune(alertOverlap)
	if err := w.cursors.Save(ctx, *cursor); err != nil {
		// Reported, not fatal. The next poll re-reads from the unsaved
		// position, and the handled-set in memory still suppresses the
		// duplicates until a restart.
		return err
	}
	return nil
}

// evaluate offers one observation to the policies and records what they decided.
func (w *worker) evaluate(ctx context.Context, obs *observation.Observation) {
	results, err := w.engine.Evaluate(ctx, obs)
	if err != nil {
		// No policy could be evaluated at all, which is not the same as no
		// policy matching: one is quiet traffic and the other is evaluation
		// that has stopped.
		logf("evaluating an observation: %v", sanitize.Error(err))
		return
	}
	for _, res := range results {
		w.tracker.Record(res)
		if res.Err != nil {
			logf("policy %s: %v", res.Policy, sanitize.Error(res.Err))
		}
	}
}

// runStatus writes policy status and keeps the replay window current.
func (w *worker) runStatus(ctx context.Context) {
	ticker := time.NewTicker(w.statusInterval)
	defer ticker.Stop()
	for {
		w.refreshReplayWindow(ctx)
		if err := w.tracker.Flush(ctx, w.sourceHealth()); err != nil {
			logf("writing policy status: %v", sanitize.Error(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// refreshReplayWindow tells the Hubble client how far back a reconnect must go.
//
// A threshold policy rebuilds its rolling window from whatever the stream
// delivers. Resuming short of the widest armed window would leave a threshold
// that was one flow from firing to rebuild from almost nothing and never fire,
// with no error anywhere - the failure an operator cannot see.
func (w *worker) refreshReplayWindow(ctx context.Context) {
	var policies trawlv1alpha1.CapturePolicyList
	if err := w.reader.List(ctx, &policies, client.InNamespace(w.namespace)); err != nil {
		// Left as it was. A stale window is longer or shorter than ideal;
		// zeroing it on a failed read would silently shorten every reconnect.
		logf("listing policies for the replay window: %v", sanitize.Error(err))
		return
	}
	w.flows.SetReplayWindow(widestThresholdWindow(policies.Items))
}

// widestThresholdWindow is the longest rolling window any armed policy needs.
//
// Disarmed policies are excluded: their windows are not evidence anything is
// waiting on, and letting one hold the stream's replay open would make arming a
// policy free and disarming it not.
func widestThresholdWindow(policies []trawlv1alpha1.CapturePolicy) time.Duration {
	var widest time.Duration
	for i := range policies {
		p := &policies[i]
		if !p.Spec.Armed || p.Spec.Trigger.HubbleDrop == nil {
			continue
		}
		if t := p.Spec.Trigger.HubbleDrop.Threshold; t != nil && t.Window.Duration > widest {
			widest = t.Window.Duration
		}
	}
	return widest
}

// alertSourceHealth is the last thing a poll learned about the alert stream.
//
// Unlike the flow stream, which knows whether its connection is open, the alert
// path has nothing to ask between polls: its health is whatever the last query
// did.
func (w *worker) alertSourceHealth() controller.SourceHealth {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.alertHealth
}

// sourceHealth is what the worker currently knows about both streams.
func (w *worker) sourceHealth() map[trawlv1alpha1.CaptureTriggerType]controller.SourceHealth {
	alerts := w.alertSourceHealth()

	drops := controller.SourceHealth{Connected: w.flows.Connected()}
	if !drops.Connected {
		drops.Reason = status.ReasonSourceDisconnected
		drops.Message = "the Hubble flow stream is not connected"
	}

	return map[trawlv1alpha1.CaptureTriggerType]controller.SourceHealth{
		trawlv1alpha1.CaptureTriggerSuricataAlert: alerts,
		trawlv1alpha1.CaptureTriggerHubbleDrop:    drops,
	}
}

func (w *worker) setAlertHealth(h controller.SourceHealth) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.alertHealth = h
}

// logf writes one operational line.
//
// Sanitization is the caller's job on anything derived from an error or from
// evidence: this process reads attacker-influenced content, and its own logs
// are shipped to the same Loki an analyst reads.
func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "event-worker: "+format+"\n", args...)
}
