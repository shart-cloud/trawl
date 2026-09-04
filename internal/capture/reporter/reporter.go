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

// Package reporter relays the capture runner's progress records into
// CaptureJob status.
//
// The runner holds capture privileges and no API token; the reporter holds
// a token scoped to one CaptureJob's status and no capture privileges. The
// two share an emptyDir of progress records (capture.ReadRecords) and
// nothing else. The reporter polls that directory and server-side-applies
// only the fields it owns - resolvedInterface, startedAt, captureEndedAt,
// runnerResult, and the FilterValid and CaptureStarted conditions - so the
// controller's writes and the reporter's never conflict.
//
// Everything the reporter writes is derived from records the runner wrote.
// Records are untrusted input: they cross a boundary from a process that
// handles attacker-controlled packets. capture.ReadRecords bounds and
// sanitizes them, and Derive here only copies typed fields.
package reporter

import (
	"context"
	"fmt"
	"reflect"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/capture"
	"trawl.cloud/trawl/internal/sanitize"
	"trawl.cloud/trawl/internal/status"
)

const (
	// FieldOwner is the server-side-apply manager name. It must differ from
	// the controller's so each side's fields are tracked separately.
	FieldOwner = "trawl-capture-reporter"

	// DefaultInterval is how often the progress directory is read.
	DefaultInterval = time.Second

	// DefaultFinalTimeout bounds the last apply after the runner finishes or
	// the reporter is told to stop.
	DefaultFinalTimeout = 10 * time.Second
)

// Patch is the reporter-owned slice of CaptureJobStatus. It is what Derive
// produces and what one apply writes; nothing else is ever sent.
type Patch struct {
	ResolvedInterface string
	StartedAt         *metav1.Time
	CaptureEndedAt    *metav1.Time
	RunnerResult      *trawlv1alpha1.RunnerResult
	Conditions        []metav1.Condition
}

// Derive maps the records seen so far to the status patch they justify.
// It is total and deterministic: condition transition times come from the
// records' own timestamps, so re-deriving the same records yields the same
// patch and a steady runner produces no writes.
//
// generation is the CaptureJob generation the Job was created for; the spec
// fields that shape a capture are immutable, so the conditions describe that
// generation truthfully even if retention was edited since.
func Derive(records []capture.Record, generation int64) Patch {
	var p Patch
	var ended *capture.Record
	for i := range records {
		rec := &records[i]
		at := metav1.NewTime(rec.RecordedAt)
		switch rec.Kind {
		case capture.RecordFilter:
			p.ResolvedInterface = rec.Fields.Interface
			setCondition(&p.Conditions, status.TypeFilterValid, metav1.ConditionTrue,
				status.ReasonFilterValid, "the filter compiled against the interface", generation, at)
		case capture.RecordStarted:
			p.StartedAt = timeOrRecorded(rec.Fields.StartedAt, at)
			setCondition(&p.Conditions, status.TypeCaptureStarted, metav1.ConditionTrue,
				status.ReasonCaptureStarted, "dumpcap opened the interface and is writing packets", generation, at)
		case capture.RecordEnded:
			p.CaptureEndedAt = timeOrRecorded(rec.Fields.EndedAt, at)
			ended = rec
		case capture.RecordResult:
			p.RunnerResult = result(rec, ended)
			if p.RunnerResult.Outcome == trawlv1alpha1.RunnerOutcomeFailed {
				failed(&p, generation, at)
			}
		}
	}
	return p
}

// failed sets the conditions a failed result falsifies. Only conditions
// whose fact is now known false change: a capture that failed after it
// started did start.
func failed(p *Patch, generation int64, at metav1.Time) {
	res := p.RunnerResult
	msg := res.Message
	if msg == "" {
		msg = "the runner reported " + string(res.Reason)
	}
	if res.Reason == trawlv1alpha1.FailureInvalidFilter {
		setCondition(&p.Conditions, status.TypeFilterValid, metav1.ConditionFalse,
			status.ReasonFilterInvalid, msg, generation, at)
	}
	if p.StartedAt == nil {
		setCondition(&p.Conditions, status.TypeCaptureStarted, metav1.ConditionFalse,
			status.ReasonCaptureFailed, msg, generation, at)
	}
}

// result assembles the RunnerResult from the result record, borrowing the
// counters from the ended record, which is where the runner puts them.
func result(res, ended *capture.Record) *trawlv1alpha1.RunnerResult {
	out := &trawlv1alpha1.RunnerResult{
		Outcome: res.Fields.Outcome,
		Reason:  res.Fields.Reason,
		SHA256:  res.Fields.SHA256,
		Message: sanitize.String(res.Fields.Message),
	}
	if res.Fields.ExitCode != nil {
		out.ExitCode = *res.Fields.ExitCode
	}
	if ended != nil {
		out.StopReason = ended.Fields.StopReason
		out.PacketCount = copyInt64(ended.Fields.PacketCount)
		out.SizeBytes = copyInt64(ended.Fields.SizeBytes)
	}
	return out
}

func copyInt64(v *int64) *int64 {
	if v == nil {
		return nil
	}
	c := *v
	return &c
}

func timeOrRecorded(t *time.Time, recorded metav1.Time) *metav1.Time {
	if t == nil {
		return &recorded
	}
	m := metav1.NewTime(*t)
	return &m
}

// setCondition inserts or replaces the condition of that type. The record
// that established the fact supplies the transition time, so the patch is
// a pure function of the records rather than of when they were read.
func setCondition(conds *[]metav1.Condition, typ string, st metav1.ConditionStatus,
	reason, msg string, generation int64, at metav1.Time,
) {
	c := status.New(typ, st, reason, msg, generation)
	c.LastTransitionTime = at
	for i := range *conds {
		if (*conds)[i].Type == typ {
			(*conds)[i] = c
			return
		}
	}
	*conds = append(*conds, c)
}

// IsEmpty reports whether the patch carries nothing, so no apply is needed.
func (p Patch) IsEmpty() bool {
	return p.ResolvedInterface == "" && p.StartedAt == nil && p.CaptureEndedAt == nil &&
		p.RunnerResult == nil && len(p.Conditions) == 0
}

// Terminal reports whether the runner has finished: after the result record
// nothing further will arrive.
func (p Patch) Terminal() bool { return p.RunnerResult != nil }

// ApplyConfiguration renders the patch as the server-side-apply body for
// the named CaptureJob's status. Only set fields appear, so the reporter
// never claims ownership of a field it has nothing to say about.
func (p Patch) ApplyConfiguration(namespace, name string) (runtime.ApplyConfiguration, error) {
	st := map[string]any{}
	if p.ResolvedInterface != "" {
		st["resolvedInterface"] = p.ResolvedInterface
	}
	if p.StartedAt != nil {
		st["startedAt"] = p.StartedAt.UTC().Format(time.RFC3339)
	}
	if p.CaptureEndedAt != nil {
		st["captureEndedAt"] = p.CaptureEndedAt.UTC().Format(time.RFC3339)
	}
	if p.RunnerResult != nil {
		rr, err := runtime.DefaultUnstructuredConverter.ToUnstructured(p.RunnerResult)
		if err != nil {
			return nil, fmt.Errorf("converting runner result: %w", err)
		}
		st["runnerResult"] = rr
	}
	if len(p.Conditions) > 0 {
		conds := make([]any, 0, len(p.Conditions))
		for i := range p.Conditions {
			c, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&p.Conditions[i])
			if err != nil {
				return nil, fmt.Errorf("converting condition: %w", err)
			}
			conds = append(conds, c)
		}
		st["conditions"] = conds
	}
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": trawlv1alpha1.GroupVersion.String(),
		"kind":       "CaptureJob",
		"metadata":   map[string]any{"namespace": namespace, "name": name},
		"status":     st,
	}}
	return client.ApplyConfigurationFromUnstructured(u), nil
}

// Reporter polls the progress directory and applies what it derives.
type Reporter struct {
	Client client.Client

	Namespace     string
	Name          string
	CaptureJobUID string
	Generation    int64
	ProgressDir   string

	Interval     time.Duration
	FinalTimeout time.Duration
	// Logf receives progress lines; every argument is fixed or sanitized.
	Logf func(format string, args ...any)

	applied *Patch
}

// Run polls until the runner's result has been applied or ctx is done. On
// ctx cancellation it makes one final bounded read-and-apply so a SIGTERM
// racing the result record does not lose it. It returns nil when the last
// observed state was applied.
func (r *Reporter) Run(ctx context.Context) error {
	if r.Interval == 0 {
		r.Interval = DefaultInterval
	}
	if r.FinalTimeout == 0 {
		r.FinalTimeout = DefaultFinalTimeout
	}
	if r.Logf == nil {
		r.Logf = func(string, ...any) {}
	}
	ticker := time.NewTicker(r.Interval)
	defer ticker.Stop()
	for {
		terminal, err := r.Once(ctx)
		if err != nil {
			r.Logf("status apply failed, will retry: %s", sanitize.Error(err))
		} else if terminal {
			return nil
		}
		select {
		case <-ctx.Done():
			final, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.FinalTimeout)
			defer cancel()
			if _, err := r.Once(final); err != nil {
				return fmt.Errorf("final status apply: %w", err)
			}
			return nil
		case <-ticker.C:
		}
	}
}

// Once reads the records and applies the derived patch when it differs
// from the last one applied. It reports whether the runner has finished.
func (r *Reporter) Once(ctx context.Context) (bool, error) {
	records, problems := capture.ReadRecords(r.ProgressDir, r.CaptureJobUID)
	for _, pr := range problems {
		// Problems are logged, never relayed: a record the reader rejected
		// is not evidence of anything except that it was rejected.
		r.Logf("ignoring progress record: file=%s reason=%s", sanitize.String(pr.File), sanitize.String(pr.Reason))
	}
	p := Derive(records, r.Generation)
	if p.IsEmpty() {
		return false, nil
	}
	if r.applied != nil && reflect.DeepEqual(*r.applied, p) {
		return p.Terminal(), nil
	}
	ac, err := p.ApplyConfiguration(r.Namespace, r.Name)
	if err != nil {
		return false, err
	}
	if err := r.Client.Status().Apply(ctx, ac, client.FieldOwner(FieldOwner), client.ForceOwnership); err != nil {
		return false, fmt.Errorf("applying status: %w", err)
	}
	r.applied = &p
	r.Logf("status applied: records=%d terminal=%v", len(records), p.Terminal())
	return p.Terminal(), nil
}
