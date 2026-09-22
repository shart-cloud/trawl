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

package policy_test

import (
	"fmt"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/policy"
)

const policyUID = types.UID("11111111-1111-4111-8111-111111111111")

// job builds a policy-created CaptureJob as the event worker would have left
// it: requested at a given time, on a given generation, in a given phase.
func job(requestedAt time.Time, phase trawlv1alpha1.CapturePhase, mutate ...func(*trawlv1alpha1.CaptureJob)) trawlv1alpha1.CaptureJob {
	at := metav1.NewTime(requestedAt)
	j := trawlv1alpha1.CaptureJob{
		Spec: trawlv1alpha1.CaptureJobSpec{
			RequestType: trawlv1alpha1.CaptureRequestPolicy,
			PolicyRef: &trawlv1alpha1.ImmutablePolicyReference{
				Name: "ssh-brute", UID: policyUID, Generation: 1,
			},
		},
		Status: trawlv1alpha1.CaptureJobStatus{Phase: phase, RequestedAt: &at},
	}
	for _, m := range mutate {
		m(&j)
	}
	return j
}

func TestTheHourlyCountCoversOnlyThisPolicysRecentCaptures(t *testing.T) {
	// The limit is what stops one noisy signature turning into a capture storm
	// that fills the artifact bucket. It is counted from the CaptureJobs
	// themselves rather than from a counter held in memory, which is what makes
	// it survive a restart or a leader handoff - a worker that forgot its
	// count would start the hour again and blow straight through the limit.
	now := time.Date(2026, 9, 9, 22, 0, 0, 0, time.UTC)
	other := types.UID("22222222-2222-4222-8222-222222222222")

	jobs := []trawlv1alpha1.CaptureJob{
		job(now.Add(-10*time.Minute), trawlv1alpha1.CapturePhaseCompleted),
		job(now.Add(-50*time.Minute), trawlv1alpha1.CapturePhaseCompleted),
		// Another policy's capture. Limits are per policy.
		job(now.Add(-5*time.Minute), trawlv1alpha1.CapturePhaseCompleted, func(j *trawlv1alpha1.CaptureJob) {
			j.Spec.PolicyRef.UID = other
		}),
		// A manual capture an analyst asked for. Not this policy's doing, and
		// counting it would let an analyst's work disarm an armed policy.
		job(now.Add(-5*time.Minute), trawlv1alpha1.CapturePhaseCompleted, func(j *trawlv1alpha1.CaptureJob) {
			j.Spec.RequestType = trawlv1alpha1.CaptureRequestManual
			j.Spec.PolicyRef = nil
		}),
	}

	got := policy.UsageFrom(jobs, policyUID, now)

	if got.Hourly != 2 {
		t.Errorf("hourly count = %d, want 2", got.Hourly)
	}
}

func TestActiveCountsOnlyCapturesStillInFlight(t *testing.T) {
	// Active captures are the ones still holding a runner and writing to the
	// work volume. The count feeds status.activeCaptures, which is what tells
	// an operator whether a policy is currently consuming capacity - a number
	// that included finished jobs would only ever climb.
	now := time.Date(2026, 9, 9, 22, 0, 0, 0, time.UTC)

	jobs := []trawlv1alpha1.CaptureJob{
		job(now.Add(-1*time.Minute), trawlv1alpha1.CapturePhasePending),
		job(now.Add(-2*time.Minute), trawlv1alpha1.CapturePhaseCapturing),
		job(now.Add(-3*time.Minute), trawlv1alpha1.CapturePhaseStoring),
		job(now.Add(-4*time.Minute), trawlv1alpha1.CapturePhaseCompleted),
		job(now.Add(-5*time.Minute), trawlv1alpha1.CapturePhaseFailed),
		job(now.Add(-6*time.Minute), trawlv1alpha1.CapturePhaseExpired),
	}

	got := policy.UsageFrom(jobs, policyUID, now)

	if got.Active != 3 {
		t.Errorf("active = %d, want 3 (Pending, Capturing, Storing)", got.Active)
	}
	if got.Hourly != 6 {
		t.Errorf("hourly = %d, want all 6: the limit counts what was requested, not what survived", got.Hourly)
	}
}

func TestAPolicyEditDoesNotResetTheHourlyBudget(t *testing.T) {
	// Counting is by policy UID and spans generations. Were it per generation,
	// an operator at the limit could edit any field of the spec and get a fresh
	// hour's worth of captures - which turns a bound into a suggestion, and the
	// edit that resets it need not change anything about the trigger.
	now := time.Date(2026, 9, 9, 22, 0, 0, 0, time.UTC)

	jobs := []trawlv1alpha1.CaptureJob{
		job(now.Add(-30*time.Minute), trawlv1alpha1.CapturePhaseCompleted),
		job(now.Add(-20*time.Minute), trawlv1alpha1.CapturePhaseCompleted, func(j *trawlv1alpha1.CaptureJob) {
			j.Spec.PolicyRef.Generation = 2
		}),
		job(now.Add(-10*time.Minute), trawlv1alpha1.CapturePhaseCompleted, func(j *trawlv1alpha1.CaptureJob) {
			j.Spec.PolicyRef.Generation = 3
		}),
	}

	if got := policy.UsageFrom(jobs, policyUID, now); got.Hourly != 3 {
		t.Errorf("hourly = %d, want 3 across generations", got.Hourly)
	}
}

func TestUsageByPolicyMatchesIndependentUsageAcrossPolicyIdentities(t *testing.T) {
	now := time.Date(2026, 9, 9, 22, 0, 0, 0, time.UTC)
	oldUID := types.UID("22222222-2222-4222-8222-222222222222")
	jobs := []trawlv1alpha1.CaptureJob{
		job(now.Add(-10*time.Minute), trawlv1alpha1.CapturePhasePending),
		job(now.Add(-2*time.Hour), trawlv1alpha1.CapturePhaseCompleted),
		job(now.Add(-20*time.Minute), trawlv1alpha1.CapturePhaseFailed, func(j *trawlv1alpha1.CaptureJob) {
			// The name is deliberately the same: deletion and recreation under
			// that name must not transfer usage to the new UID.
			j.Spec.PolicyRef.UID = oldUID
		}),
		job(now.Add(-5*time.Minute), trawlv1alpha1.CapturePhaseCapturing, func(j *trawlv1alpha1.CaptureJob) {
			j.Spec.PolicyRef = nil
			j.Spec.RequestType = trawlv1alpha1.CaptureRequestManual
		}),
	}

	got := policy.UsageByPolicy(jobs, now)
	for _, uid := range []types.UID{policyUID, oldUID, "never-captured"} {
		want := policy.UsageFrom(jobs, uid, now)
		if got[uid] != want {
			t.Errorf("usage for %q = %+v, want independent result %+v", uid, got[uid], want)
		}
	}
}

var benchmarkUsageByPolicy map[types.UID]policy.Usage

func BenchmarkUsageByPolicy(b *testing.B) {
	now := time.Date(2026, 9, 9, 22, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		policies int
		jobs     int
	}{{10, 1_000}, {100, 10_000}, {1_000, 10_000}} {
		b.Run(fmt.Sprintf("policies_%d/jobs_%d", tc.policies, tc.jobs), func(b *testing.B) {
			jobs := make([]trawlv1alpha1.CaptureJob, tc.jobs)
			for i := range jobs {
				uid := types.UID(fmt.Sprintf("policy-%d", i%tc.policies))
				jobs[i] = job(now.Add(-time.Duration(i%120)*time.Minute),
					trawlv1alpha1.CapturePhaseCompleted, func(j *trawlv1alpha1.CaptureJob) {
						j.Spec.PolicyRef.UID = uid
					})
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				benchmarkUsageByPolicy = policy.UsageByPolicy(jobs, now)
			}
		})
	}
}

func TestTheHourIsRollingNotACalendarHour(t *testing.T) {
	// A calendar-hour bucket lets a policy spend its whole budget at 10:59 and
	// its whole budget again at 11:01. The bound people believe they set is
	// "this many per hour", not "this many per clock hour".
	now := time.Date(2026, 9, 9, 22, 0, 0, 0, time.UTC)

	jobs := []trawlv1alpha1.CaptureJob{
		job(now.Add(-59*time.Minute), trawlv1alpha1.CapturePhaseCompleted),
		job(now.Add(-61*time.Minute), trawlv1alpha1.CapturePhaseCompleted),
	}

	if got := policy.UsageFrom(jobs, policyUID, now); got.Hourly != 1 {
		t.Errorf("hourly = %d, want 1: only the capture inside the trailing hour counts", got.Hourly)
	}
}

func TestTheLimitIsReachedAtTheConfiguredCountNotAfterIt(t *testing.T) {
	// An off-by-one here is a bound that permits one more capture than the
	// operator set. maxCapturesPerHour is the number allowed in the hour, so
	// the request that would make it that many plus one is the one refused.
	now := time.Date(2026, 9, 9, 22, 0, 0, 0, time.UTC)
	limits := trawlv1alpha1.CaptureRateLimit{MaxCapturesPerHour: 3}

	for _, tc := range []struct {
		hourly int32
		want   policy.LimitVerdict
	}{
		{0, policy.LimitAllowed},
		{2, policy.LimitAllowed},
		{3, policy.LimitRateLimited},
		{4, policy.LimitRateLimited},
	} {
		usage := policy.Usage{Hourly: tc.hourly, Last: now.Add(-time.Minute)}
		if got := policy.CheckLimits(usage, limits); got != tc.want {
			t.Errorf("with %d captures this hour against a limit of 3: verdict = %q, want %q",
				tc.hourly, got, tc.want)
		}
	}
}

func TestAPolicyWithNoRecordedCapturesIsAllowed(t *testing.T) {
	// The zero usage is a policy that has never fired, or one whose captures
	// have all aged out of the hour. Refusing it would leave a freshly armed
	// policy permanently rate-limited.
	limits := trawlv1alpha1.CaptureRateLimit{MaxCapturesPerHour: 1}

	if got := policy.CheckLimits(policy.Usage{}, limits); got != policy.LimitAllowed {
		t.Errorf("verdict = %q, want %q", got, policy.LimitAllowed)
	}
}
