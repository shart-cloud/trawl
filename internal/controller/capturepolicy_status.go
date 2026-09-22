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

package controller

import (
	"context"
	"errors"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/policy"
	"trawl.cloud/trawl/internal/sanitize"
	"trawl.cloud/trawl/internal/status"
	"trawl.cloud/trawl/internal/telemetry"
)

// SourceHealth is what the worker currently knows about one trigger source.
//
// It is per source rather than per policy because the sources fail
// independently: a Loki outage says nothing about the Hubble stream, and a
// denied-flow policy reported Degraded because the alert query path is down
// would send an operator looking in the wrong place (FR-038).
type SourceHealth struct {
	// Connected says the source is delivering.
	Connected bool

	// Reason is a status reason from internal/status when it is not -
	// SourceDisconnected for a source that is not answering, SourceGap for one
	// that is connected but known to have missed coverage.
	Reason string

	// Message is sanitized detail for the condition.
	Message string
}

// PolicyStatusTracker accumulates policy decisions and writes them to status.
//
// Decisions are batched rather than written as they happen. A busy signature
// produces decisions faster than the API server should be asked to record
// them, and a status write per event would make the policy's own reporting the
// thing that falls over first under the load it exists to describe.
type PolicyStatusTracker struct {
	// Client reads policies, taps and captures, and writes policy status.
	Client client.Client

	// Namespace is the configured Trawl namespace.
	Namespace string

	// Metrics is optional.
	Metrics *telemetry.Metrics

	// Now is time.Now unless a test replaced it.
	Now func() time.Time

	mu      sync.Mutex
	pending map[types.UID]*decisionBatch
}

// decisionBatch is what one policy decided since its last successful write.
//
// Deltas, not totals. The counters on the object are the record of everything
// the policy has done, so a batch that recomputed them would reset a policy
// that had matched a thousand times to whatever happened in the last few
// seconds.
type decisionBatch struct {
	counters trawlv1alpha1.PolicyDecisionCounters
	captures int64

	lastTrigger time.Time
	lastCapture string
	tapUID      types.UID
}

func (b *decisionBatch) merge(other *decisionBatch) {
	if other == nil {
		return
	}
	b.counters.Matched += other.counters.Matched
	b.counters.NotMatched += other.counters.NotMatched
	b.counters.Duplicate += other.counters.Duplicate
	b.counters.RateLimited += other.counters.RateLimited
	b.counters.Failed += other.counters.Failed
	b.captures += other.captures

	if other.lastTrigger.After(b.lastTrigger) {
		b.lastTrigger = other.lastTrigger
	}
	if other.lastCapture != "" {
		b.lastCapture = other.lastCapture
	}
	if other.tapUID != "" {
		b.tapUID = other.tapUID
	}
}

// Record accumulates one decision.
func (t *PolicyStatusTracker) Record(res PolicyResult) {
	if res.PolicyUID == "" {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pending == nil {
		t.pending = map[types.UID]*decisionBatch{}
	}
	batch, ok := t.pending[res.PolicyUID]
	if !ok {
		batch = &decisionBatch{}
		t.pending[res.PolicyUID] = batch
	}

	switch res.Outcome {
	case OutcomeCreated:
		batch.counters.Matched++
		batch.captures++
		batch.lastCapture = res.CaptureName
	case OutcomeDuplicate:
		batch.counters.Duplicate++
		// The capture this event's packets are in. It is what turns
		// "suppressed" into something an analyst can follow.
		batch.lastCapture = res.CaptureName
	case OutcomeRateLimited:
		batch.counters.RateLimited++
	case OutcomeNotMatched:
		batch.counters.NotMatched++
	case OutcomeFailed:
		batch.counters.Failed++
	case OutcomeDisarmed:
		// Counted in telemetry only. A disarmed policy's decisions are not
		// part of what it has collected, and there is deliberately no counter
		// for them on the API.
	}

	// Set for every outcome that followed a match, including the suppressed
	// ones: a policy that is matching and suppressing is working, and one that
	// is not matching at all is a different problem.
	if res.TriggerTime.After(batch.lastTrigger) {
		batch.lastTrigger = res.TriggerTime
	}
	if res.TapUID != "" {
		batch.tapUID = res.TapUID
	}
}

// Flush writes every policy's status, applying whatever it has decided.
//
// Every policy is reconciled, not only the ones with decisions pending. A
// policy that has never matched anything still has to say whether it is
// watching; leaving it with an empty status would be indistinguishable from a
// worker that is not running.
func (t *PolicyStatusTracker) Flush(
	ctx context.Context, health map[trawlv1alpha1.CaptureTriggerType]SourceHealth,
) error {
	var policies trawlv1alpha1.CapturePolicyList
	if err := t.Client.List(ctx, &policies, client.InNamespace(t.Namespace)); err != nil {
		return sanitize.Errorf("listing capture policies: %v", err)
	}
	var jobs trawlv1alpha1.CaptureJobList
	if err := t.Client.List(ctx, &jobs, client.InNamespace(t.Namespace)); err != nil {
		return sanitize.Errorf("listing captures: %v", err)
	}

	// Taken all at once, so decisions arriving during the flush accumulate
	// into a fresh batch rather than being written and then cleared unwritten.
	batches := t.take()
	usageByPolicy := policy.UsageByPolicy(jobs.Items, t.now())

	var errs []error
	for i := range policies.Items {
		p := &policies.Items[i]
		batch := batches[p.UID]
		if !p.DeletionTimestamp.IsZero() {
			// On its way out. Writing status would only lose a conflict with
			// the finalizer, and the decisions describe a policy that will not
			// be there to report them.
			continue
		}
		if err := t.apply(ctx, p, batch, usageByPolicy[p.UID], health); err != nil {
			// Kept for the next flush rather than dropped: a conflict or a
			// brief API outage has nothing to do with the policy, and losing
			// the batch would silently lose the record of decisions that
			// really happened. Isolated per policy, so one policy's failure
			// does not stop the rest being written (FR-038).
			t.restore(p.UID, batch)
			errs = append(errs, err)
			if t.Metrics != nil {
				t.Metrics.StatusUpdateFailures.WithLabelValues("CapturePolicy", status.ReasonPending).Inc()
			}
		}
	}
	// Batches whose policy no longer exists are simply not restored. Retrying
	// them forever would keep one entry per deleted policy for as long as the
	// worker runs.
	return errors.Join(errs...)
}

// take removes and returns every pending batch.
func (t *PolicyStatusTracker) take() map[types.UID]*decisionBatch {
	t.mu.Lock()
	defer t.mu.Unlock()
	batches := t.pending
	t.pending = nil
	return batches
}

// restore puts an unwritten batch back, merged with anything recorded since.
func (t *PolicyStatusTracker) restore(uid types.UID, batch *decisionBatch) {
	if batch == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pending == nil {
		t.pending = map[types.UID]*decisionBatch{}
	}
	if current, ok := t.pending[uid]; ok {
		batch.merge(current)
	}
	t.pending[uid] = batch
}

// apply computes and writes one policy's status.
func (t *PolicyStatusTracker) apply(
	ctx context.Context,
	p *trawlv1alpha1.CapturePolicy,
	batch *decisionBatch,
	usage policy.Usage,
	health map[trawlv1alpha1.CaptureTriggerType]SourceHealth,
) error {
	desired := p.Status.DeepCopy()
	desired.ObservedGeneration = p.Generation

	if batch != nil {
		desired.Decisions.Matched += batch.counters.Matched
		desired.Decisions.NotMatched += batch.counters.NotMatched
		desired.Decisions.Duplicate += batch.counters.Duplicate
		desired.Decisions.RateLimited += batch.counters.RateLimited
		desired.Decisions.Failed += batch.counters.Failed
		desired.TotalCaptures += batch.captures

		if !batch.lastTrigger.IsZero() &&
			(desired.LastTriggerTime == nil || batch.lastTrigger.After(desired.LastTriggerTime.Time)) {
			at := metav1.NewTime(batch.lastTrigger)
			desired.LastTriggerTime = &at
		}
		if batch.lastCapture != "" {
			desired.LastCaptureRef = &corev1.LocalObjectReference{Name: batch.lastCapture}
		}
	}

	// Rebuilt from the captures on every flush rather than counted in memory,
	// so a restart does not lose the count and a job that finished while the
	// worker was down is not still reported as running.
	desired.ActiveCaptures = usage.Active

	tapReason := t.tapCondition(ctx, p, desired)
	sourceReason := t.sourceCondition(p, desired, health)
	limitReason := t.rateLimitCondition(p, desired, usage)

	desired.Phase, _ = phaseFor(p, tapReason, sourceReason, limitReason)
	t.readyCondition(p, desired, tapReason, sourceReason, limitReason)

	if equality.Semantic.DeepEqual(p.Status, *desired) {
		// Nothing moved. A flush that wrote regardless would put one update per
		// policy per interval on the API server for no new information.
		return nil
	}
	p.Status = *desired
	if err := t.Client.Status().Update(ctx, p); err != nil {
		return sanitize.Errorf("writing capture policy status: %v", err)
	}
	return nil
}

// tapCondition resolves the policy's tap and reports it. The returned reason is
// empty when the tap is bound.
func (t *PolicyStatusTracker) tapCondition(
	ctx context.Context, p *trawlv1alpha1.CapturePolicy, desired *trawlv1alpha1.CapturePolicyStatus,
) string {
	tap, reason, err := resolveTap(ctx, t.Client, p)
	if err != nil {
		status.Set(&desired.Conditions, status.New(
			status.TypeTapResolved, metav1.ConditionFalse, reason, err.Error(), p.Generation))
		return reason
	}
	// Bound for this generation. The UID is what makes a tap deleted and
	// recreated under the same name visible as the different tap it is.
	desired.ResolvedTapUID = tap.UID
	status.Set(&desired.Conditions, status.New(
		status.TypeTapResolved, metav1.ConditionTrue, status.ReasonTapResolved,
		"observing on "+tap.Name, p.Generation))
	return ""
}

// sourceCondition reports the health of the stream this policy is armed
// against.
func (t *PolicyStatusTracker) sourceCondition(
	p *trawlv1alpha1.CapturePolicy,
	desired *trawlv1alpha1.CapturePolicyStatus,
	health map[trawlv1alpha1.CaptureTriggerType]SourceHealth,
) string {
	h, known := health[p.Spec.Trigger.Type]
	switch {
	case !known:
		// No word on the source at all. Reported as disconnected rather than
		// assumed healthy: absence of evidence is not evidence of coverage.
		status.Set(&desired.Conditions, status.New(
			status.TypeSourceConnected, metav1.ConditionFalse, status.ReasonSourceDisconnected,
			"the worker has not reported on this trigger source", p.Generation))
		return status.ReasonSourceDisconnected

	case !h.Connected:
		reason := h.Reason
		if reason == "" {
			reason = status.ReasonSourceDisconnected
		}
		status.Set(&desired.Conditions, status.New(
			status.TypeSourceConnected, metav1.ConditionFalse, reason, h.Message, p.Generation))
		return reason
	}

	status.Set(&desired.Conditions, status.New(
		status.TypeSourceConnected, metav1.ConditionTrue, status.ReasonSourceConnected,
		h.Message, p.Generation))
	return ""
}

// rateLimitCondition reports whether the policy may still capture.
func (t *PolicyStatusTracker) rateLimitCondition(
	p *trawlv1alpha1.CapturePolicy, desired *trawlv1alpha1.CapturePolicyStatus, usage policy.Usage,
) string {
	// Derived from the captures rather than latched on the last suppressed
	// decision, so it clears itself as they age out of the trailing hour. A
	// latched state would leave a recovered policy reporting RateLimited until
	// the next event happened to arrive.
	if policy.CheckLimits(usage, p.Spec.RateLimit) == policy.LimitRateLimited {
		status.Set(&desired.Conditions, status.New(
			status.TypeWithinRateLimit, metav1.ConditionFalse, status.ReasonRateLimited,
			"the hourly capture limit is reached", p.Generation))
		return status.ReasonRateLimited
	}
	status.Set(&desired.Conditions, status.New(
		status.TypeWithinRateLimit, metav1.ConditionTrue, status.ReasonWithinRateLimit,
		"", p.Generation))
	return ""
}

// readyCondition summarizes the rest.
func (t *PolicyStatusTracker) readyCondition(
	p *trawlv1alpha1.CapturePolicy,
	desired *trawlv1alpha1.CapturePolicyStatus,
	tapReason, sourceReason, limitReason string,
) {
	phase, reason := phaseFor(p, tapReason, sourceReason, limitReason)
	if phase == trawlv1alpha1.CapturePolicyArmed {
		status.Set(&desired.Conditions, status.New(
			status.TypeReady, metav1.ConditionTrue, status.ReasonAccepted,
			"armed and evaluating events", p.Generation))
		return
	}
	status.Set(&desired.Conditions, status.New(
		status.TypeReady, metav1.ConditionFalse, reason, "", p.Generation))
}

// phaseFor is the policy's operational position, and the reason behind it.
//
// Ordered by what an operator has to act on. Disarmed first because it is a
// choice rather than a problem; then the two ways a policy can be armed and not
// working, which need investigation; then the limit, which recovers on its own.
func phaseFor(
	p *trawlv1alpha1.CapturePolicy, tapReason, sourceReason, limitReason string,
) (trawlv1alpha1.CapturePolicyPhase, string) {
	switch {
	case !p.Spec.Armed:
		return trawlv1alpha1.CapturePolicyDisarmed, status.ReasonDisarmed
	case tapReason != "":
		return trawlv1alpha1.CapturePolicyDegraded, tapReason
	case sourceReason != "":
		return trawlv1alpha1.CapturePolicyDegraded, sourceReason
	case limitReason != "":
		return trawlv1alpha1.CapturePolicyRateLimited, limitReason
	}
	return trawlv1alpha1.CapturePolicyArmed, status.ReasonAccepted
}

func (t *PolicyStatusTracker) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}
