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

package reporter

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/capture"
	"trawl.cloud/trawl/internal/status"
)

var (
	t0 = time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	t1 = t0.Add(2 * time.Second)
	t2 = t0.Add(62 * time.Second)
	t3 = t0.Add(70 * time.Second)
)

func rec(kind capture.RecordKind, at time.Time, f capture.Fields) capture.Record {
	return capture.Record{
		SchemaVersion: capture.ProgressSchemaVersion, Kind: kind, Seq: capture.SeqFor(kind),
		CaptureJobUID: "u-1", RecordedAt: at, RunnerInstance: "r-1", Fields: f,
	}
}

func ptr[T any](v T) *T { return &v }

func condition(p Patch, typ string) *metav1.Condition {
	return status.Get(p.Conditions, typ)
}

func fixtures() map[string]capture.Record {
	return map[string]capture.Record{
		"filter":  rec(capture.RecordFilter, t0, capture.Fields{Interface: "eno1"}),
		"started": rec(capture.RecordStarted, t1, capture.Fields{StartedAt: ptr(t1)}),
		"ended": rec(capture.RecordEnded, t2, capture.Fields{
			EndedAt: ptr(t2), StopReason: trawlv1alpha1.CaptureStopDuration, PacketCount: ptr[int64](42), SizeBytes: ptr[int64](8192),
		}),
		"ok": rec(capture.RecordResult, t3, capture.Fields{
			Outcome: trawlv1alpha1.RunnerOutcomeSucceeded, SHA256: strings.Repeat("ab", 32), ExitCode: ptr[int32](0),
		}),
		"badFilter": rec(capture.RecordResult, t1, capture.Fields{
			Outcome: trawlv1alpha1.RunnerOutcomeFailed, Reason: trawlv1alpha1.FailureInvalidFilter,
			ExitCode: ptr[int32](capture.ExitInvalidFilter), Message: "the filter did not compile",
		}),
		"noIface": rec(capture.RecordResult, t1, capture.Fields{
			Outcome: trawlv1alpha1.RunnerOutcomeFailed, Reason: trawlv1alpha1.FailureInterfaceUnavailable,
			ExitCode: ptr[int32](capture.ExitInterfaceUnavailable),
		}),
		"uploadFailed": rec(capture.RecordResult, t3, capture.Fields{
			Outcome: trawlv1alpha1.RunnerOutcomeFailed, Reason: trawlv1alpha1.FailureUploadFailed,
			ExitCode: ptr[int32](capture.ExitUploadFailed), Message: "storage refused the object",
		}),
	}
}

func derive(names ...string) Patch {
	f := fixtures()
	recs := make([]capture.Record, 0, len(names))
	for _, n := range names {
		recs = append(recs, f[n])
	}
	return Derive(recs, 3)
}

func wantCondition(t *testing.T, p Patch, typ string, st metav1.ConditionStatus, reason string, at time.Time) *metav1.Condition {
	t.Helper()
	c := condition(p, typ)
	if c == nil || c.Status != st || c.Reason != reason || c.ObservedGeneration != 3 || (!at.IsZero() && !c.LastTransitionTime.Time.Equal(at)) {
		t.Errorf("%s = %+v, want %s/%s at %s", typ, c, st, reason, at)
	}
	return c
}

func TestDeriveNothingYet(t *testing.T) {
	if p := derive(); !p.IsEmpty() || p.Terminal() {
		t.Errorf("patch %+v, want empty", p)
	}
}

func TestDeriveFilterCompiled(t *testing.T) {
	p := derive("filter")
	if p.ResolvedInterface != "eno1" || p.StartedAt != nil || p.Terminal() {
		t.Errorf("patch %+v", p)
	}
	wantCondition(t, p, status.TypeFilterValid, metav1.ConditionTrue, status.ReasonFilterValid, t0)
	if condition(p, status.TypeCaptureStarted) != nil {
		t.Error("CaptureStarted set before the started record")
	}
}

func TestDeriveCapturing(t *testing.T) {
	p := derive("filter", "started")
	if p.StartedAt == nil || !p.StartedAt.Time.Equal(t1) || p.CaptureEndedAt != nil {
		t.Errorf("patch %+v", p)
	}
	wantCondition(t, p, status.TypeCaptureStarted, metav1.ConditionTrue, status.ReasonCaptureStarted, t1)
}

func TestDeriveStoring(t *testing.T) {
	p := derive("filter", "started", "ended")
	if p.CaptureEndedAt == nil || !p.CaptureEndedAt.Time.Equal(t2) || p.RunnerResult != nil || p.Terminal() {
		t.Errorf("patch %+v", p)
	}
}

func TestDeriveSucceeded(t *testing.T) {
	p := derive("filter", "started", "ended", "ok")
	r := p.RunnerResult
	if !p.Terminal() || r.Outcome != trawlv1alpha1.RunnerOutcomeSucceeded || r.ExitCode != 0 ||
		r.StopReason != trawlv1alpha1.CaptureStopDuration || r.PacketCount == nil || *r.PacketCount != 42 ||
		r.SizeBytes == nil || *r.SizeBytes != 8192 || r.SHA256 != strings.Repeat("ab", 32) {
		t.Errorf("runnerResult %+v", r)
	}
	wantCondition(t, p, status.TypeFilterValid, metav1.ConditionTrue, status.ReasonFilterValid, t0)
	wantCondition(t, p, status.TypeCaptureStarted, metav1.ConditionTrue, status.ReasonCaptureStarted, t1)
}

func TestDeriveInvalidFilter(t *testing.T) {
	p := derive("badFilter")
	if !p.Terminal() || p.RunnerResult.Reason != trawlv1alpha1.FailureInvalidFilter || p.RunnerResult.ExitCode != capture.ExitInvalidFilter {
		t.Errorf("runnerResult %+v", p.RunnerResult)
	}
	c := wantCondition(t, p, status.TypeFilterValid, metav1.ConditionFalse, status.ReasonFilterInvalid, t1)
	if c != nil && c.Message != "the filter did not compile" {
		t.Errorf("FilterValid message %q", c.Message)
	}
	wantCondition(t, p, status.TypeCaptureStarted, metav1.ConditionFalse, status.ReasonCaptureFailed, t1)
}

func TestDeriveInterfaceUnavailable(t *testing.T) {
	p := derive("noIface")
	if condition(p, status.TypeFilterValid) != nil {
		t.Error("FilterValid asserted for a failure that says nothing about the filter")
	}
	c := wantCondition(t, p, status.TypeCaptureStarted, metav1.ConditionFalse, status.ReasonCaptureFailed, t1)
	if c != nil && !strings.Contains(c.Message, "InterfaceUnavailable") {
		t.Errorf("CaptureStarted message %q", c.Message)
	}
}

func TestDeriveUploadFailedAfterCapture(t *testing.T) {
	// The capture did start and the filter did compile; only the runner
	// result says what went wrong.
	p := derive("filter", "started", "ended", "uploadFailed")
	wantCondition(t, p, status.TypeFilterValid, metav1.ConditionTrue, status.ReasonFilterValid, t0)
	wantCondition(t, p, status.TypeCaptureStarted, metav1.ConditionTrue, status.ReasonCaptureStarted, t1)
	if p.RunnerResult.Reason != trawlv1alpha1.FailureUploadFailed || p.RunnerResult.SizeBytes == nil {
		t.Errorf("runnerResult %+v", p.RunnerResult)
	}
}

func TestDeriveIsDeterministic(t *testing.T) {
	recs := []capture.Record{
		rec(capture.RecordFilter, t0, capture.Fields{Interface: "eno1"}),
		rec(capture.RecordStarted, t1, capture.Fields{StartedAt: ptr(t1)}),
	}
	a, _ := json.Marshal(Derive(recs, 1))
	time.Sleep(5 * time.Millisecond)
	b, _ := json.Marshal(Derive(recs, 1))
	if string(a) != string(b) {
		t.Errorf("same records derived differently:\n%s\n%s", a, b)
	}
}

func TestApplyConfigurationCarriesOnlySetFields(t *testing.T) {
	p := Derive([]capture.Record{rec(capture.RecordFilter, t0, capture.Fields{Interface: "eno1"})}, 2)
	ac, err := p.ApplyConfiguration("trawl-system", "manual-tls")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(ac)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	st, _ := got["status"].(map[string]any)
	if st["resolvedInterface"] != "eno1" {
		t.Errorf("status %v", st)
	}
	for _, absent := range []string{"phase", "startedAt", "captureEndedAt", "runnerResult", "packetCount", "sha256"} {
		if _, ok := st[absent]; ok {
			t.Errorf("patch claims %s, which the reporter does not own or know", absent)
		}
	}
	if got["apiVersion"] != "trawl.cloud/v1alpha1" || got["kind"] != "CaptureJob" {
		t.Errorf("envelope %v", got)
	}
}

func newJob() *trawlv1alpha1.CaptureJob {
	return &trawlv1alpha1.CaptureJob{
		ObjectMeta: metav1.ObjectMeta{Namespace: "trawl-system", Name: "manual-tls", UID: types.UID("u-1"), Generation: 2},
		Status: trawlv1alpha1.CaptureJobStatus{
			Phase: trawlv1alpha1.CapturePhasePending,
			Conditions: []metav1.Condition{{
				Type: status.TypeTargetReady, Status: metav1.ConditionTrue, Reason: status.ReasonTargetReady,
				ObservedGeneration: 2, LastTransitionTime: metav1.NewTime(t0),
			}},
		},
	}
}

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := trawlv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestReporterAppliesOnceAndPreservesControllerFields(t *testing.T) {
	dir := t.TempDir()
	w := &capture.RecordWriter{Dir: dir, CaptureJobUID: "u-1", RunnerInstance: "r-1", Now: func() time.Time { return t0 }}
	applies := 0
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(newJob()).
		WithStatusSubresource(&trawlv1alpha1.CaptureJob{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceApply: func(ctx context.Context, cl client.Client, sub string, obj runtime.ApplyConfiguration, opts ...client.SubResourceApplyOption) error {
				applies++
				return cl.SubResource(sub).Apply(ctx, obj, opts...)
			},
		}).Build()
	r := &Reporter{Client: c, Namespace: "trawl-system", Name: "manual-tls", CaptureJobUID: "u-1", Generation: 2, ProgressDir: dir, Logf: t.Logf}
	ctx := t.Context()

	if term, err := r.Once(ctx); err != nil || term || applies != 0 {
		t.Fatalf("empty dir: terminal=%v applies=%d err=%v", term, applies, err)
	}
	if err := w.Write(capture.RecordFilter, capture.Fields{Interface: "eno1"}); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if term, err := r.Once(ctx); err != nil || term {
			t.Fatalf("pass %d: terminal=%v err=%v", i, term, err)
		}
	}
	if applies != 1 {
		t.Errorf("unchanged records applied %d times, want 1", applies)
	}

	var job trawlv1alpha1.CaptureJob
	if err := c.Get(ctx, client.ObjectKeyFromObject(newJob()), &job); err != nil {
		t.Fatal(err)
	}
	if job.Status.ResolvedInterface != "eno1" {
		t.Errorf("resolvedInterface = %q", job.Status.ResolvedInterface)
	}
	// The fake client merges scalar fields but has no CRD schema, so it
	// cannot merge the conditions list by type; that half of the
	// guarantee is proved against envtest in test/integration.
	if job.Status.Phase != trawlv1alpha1.CapturePhasePending {
		t.Errorf("controller-owned fields disturbed: %+v", job.Status)
	}
	if c := status.Get(job.Status.Conditions, status.TypeFilterValid); c == nil || c.Status != metav1.ConditionTrue {
		t.Errorf("FilterValid = %+v", c)
	}

	w.Now = func() time.Time { return t3 }
	if err := w.Write(capture.RecordResult, capture.Fields{
		Outcome: trawlv1alpha1.RunnerOutcomeFailed, Reason: trawlv1alpha1.FailureInterfaceUnavailable, ExitCode: ptr[int32](11),
	}); err != nil {
		t.Fatal(err)
	}
	if term, err := r.Once(ctx); err != nil || !term {
		t.Fatalf("after result: terminal=%v err=%v", term, err)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(newJob()), &job); err != nil {
		t.Fatal(err)
	}
	if job.Status.RunnerResult == nil || job.Status.RunnerResult.ExitCode != 11 {
		t.Errorf("runnerResult %+v", job.Status.RunnerResult)
	}
}

func TestRunStopsAtResultAndAppliesOnCancel(t *testing.T) {
	dir := t.TempDir()
	w := &capture.RecordWriter{Dir: dir, CaptureJobUID: "u-1", RunnerInstance: "r-1", Now: func() time.Time { return t0 }}
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(newJob()).
		WithStatusSubresource(&trawlv1alpha1.CaptureJob{}).Build()
	r := &Reporter{Client: c, Namespace: "trawl-system", Name: "manual-tls", CaptureJobUID: "u-1", Generation: 2,
		ProgressDir: dir, Interval: 10 * time.Millisecond, Logf: t.Logf}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	// The records land while Run is polling; Run must return by itself
	// once the result is applied.
	_ = w.Write(capture.RecordFilter, capture.Fields{Interface: "eno1"})
	time.Sleep(30 * time.Millisecond)
	_ = w.Write(capture.RecordResult, capture.Fields{Outcome: trawlv1alpha1.RunnerOutcomeSucceeded, ExitCode: ptr[int32](0)})
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the result record")
	}
	cancel()

	// A second reporter cancelled with a fresh record pending applies it
	// on the way out.
	dir2 := t.TempDir()
	w2 := &capture.RecordWriter{Dir: dir2, CaptureJobUID: "u-1", RunnerInstance: "r-2", Now: func() time.Time { return t0 }}
	r2 := &Reporter{Client: c, Namespace: "trawl-system", Name: "manual-tls", CaptureJobUID: "u-1", Generation: 2,
		ProgressDir: dir2, Interval: time.Hour, Logf: t.Logf}
	ctx2, cancel2 := context.WithCancel(t.Context())
	done2 := make(chan error, 1)
	go func() { done2 <- r2.Run(ctx2) }()
	time.Sleep(20 * time.Millisecond)
	_ = w2.Write(capture.RecordFilter, capture.Fields{Interface: "eno2"})
	cancel2()
	if err := <-done2; err != nil {
		t.Fatal(err)
	}
	var job trawlv1alpha1.CaptureJob
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(newJob()), &job); err != nil {
		t.Fatal(err)
	}
	if job.Status.ResolvedInterface != "eno2" {
		t.Errorf("final apply on cancel did not land: resolvedInterface = %q", job.Status.ResolvedInterface)
	}
}

func TestOnceReportsApplyFailure(t *testing.T) {
	dir := t.TempDir()
	w := &capture.RecordWriter{Dir: dir, CaptureJobUID: "u-1", RunnerInstance: "r-1", Now: func() time.Time { return t0 }}
	_ = w.Write(capture.RecordFilter, capture.Fields{Interface: "eno1"})
	boom := errors.New("apiserver unavailable https://user:pass@10.0.0.1")
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(newJob()).
		WithStatusSubresource(&trawlv1alpha1.CaptureJob{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceApply: func(context.Context, client.Client, string, runtime.ApplyConfiguration, ...client.SubResourceApplyOption) error {
				return boom
			},
		}).Build()
	r := &Reporter{Client: c, Namespace: "trawl-system", Name: "manual-tls", CaptureJobUID: "u-1", ProgressDir: dir}
	if _, err := r.Once(t.Context()); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped apply error", err)
	}
	// Nothing was applied, so the next pass must try again rather than
	// believe the patch landed.
	if r.applied != nil {
		t.Error("failed apply recorded as applied")
	}
}
