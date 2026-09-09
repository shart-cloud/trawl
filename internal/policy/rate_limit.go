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

package policy

import (
	"time"

	"k8s.io/apimachinery/pkg/types"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
)

// Usage is what a policy's own CaptureJobs say about its recent activity.
//
// Derived from the jobs rather than counted in memory, which is what makes it
// survive a restart or a leader handoff. A worker holding the count itself
// would start the hour again after every restart and go straight through the
// limit - and restarts are most likely exactly when a policy is firing hard.
type Usage struct {
	// Hourly is how many captures this policy requested in the trailing hour.
	Hourly int32

	// Active is how many of its captures have not reached a terminal phase.
	Active int32

	// Last is when it most recently requested one.
	Last time.Time
}

// UsageFrom summarizes one policy's captures as of now.
//
// Selection is by policy UID, not name: a policy deleted and recreated with the
// same name is a different policy, and inheriting the old one's hourly count
// would either throttle a new policy for its predecessor's activity or, worse,
// let a recreated one start with a used-up budget it never spent.
func UsageFrom(jobs []trawlv1alpha1.CaptureJob, uid types.UID, now time.Time) Usage {
	var usage Usage
	hourAgo := now.Add(-time.Hour)

	for _, job := range jobs {
		ref := job.Spec.PolicyRef
		if ref == nil || ref.UID != uid {
			continue
		}

		requested := requestedAt(job)
		if requested.After(hourAgo) {
			usage.Hourly++
		}
		if requested.After(usage.Last) {
			usage.Last = requested
		}
		if !terminal(job.Status.Phase) {
			usage.Active++
		}
	}
	return usage
}

// terminal says whether a capture has finished, one way or another.
//
// Listed positively rather than as "not one of the in-flight phases": a phase
// added later would otherwise be counted as active forever, and an active count
// that only climbs would eventually hold a policy at its limit permanently.
func terminal(phase trawlv1alpha1.CapturePhase) bool {
	switch phase {
	case trawlv1alpha1.CapturePhaseCompleted,
		trawlv1alpha1.CapturePhaseFailed,
		trawlv1alpha1.CapturePhaseExpired:
		return true
	default:
		return false
	}
}

// requestedAt is when the job was asked for.
func requestedAt(job trawlv1alpha1.CaptureJob) time.Time {
	if job.Status.RequestedAt != nil {
		return job.Status.RequestedAt.Time
	}
	// Falls back to the object's own creation stamp. Status is written after
	// the object exists, so a job created moments ago may not carry one yet -
	// and skipping it would let a burst slip under the limit in exactly the
	// window the limit is meant to cover.
	return job.CreationTimestamp.Time
}

// LimitVerdict is whether a policy may capture right now.
//
// A closed set, because it reaches status.decisions and the WithinRateLimit
// condition; a free-form string would let a new path invent a state nothing
// aggregates or displays.
type LimitVerdict string

const (
	// LimitAllowed means the policy is within its bounds.
	LimitAllowed LimitVerdict = "Allowed"

	// LimitRateLimited means the hourly ceiling is reached. The decision is
	// recorded and the capture is not created; the policy recovers on its own
	// as captures age out of the trailing hour.
	LimitRateLimited LimitVerdict = "RateLimited"
)

// CheckLimits decides whether a policy may request another capture.
//
// Compared with >=, not >: MaxCapturesPerHour is how many are allowed in the
// hour, so once that many exist the next request is the one over the line. The
// off-by-one in the other direction would quietly permit one more capture than
// the operator configured.
func CheckLimits(usage Usage, limits trawlv1alpha1.CaptureRateLimit) LimitVerdict {
	if usage.Hourly >= limits.MaxCapturesPerHour {
		return LimitRateLimited
	}
	return LimitAllowed
}
