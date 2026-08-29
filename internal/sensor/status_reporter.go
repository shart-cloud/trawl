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

package sensor

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/content"
	"trawl.cloud/trawl/internal/sanitize"
)

// AnalyzerObserver supplies one analyzer's observed state to the reporter.
//
// It is an interface so the reporter depends on observations rather than on how
// they were obtained: a tailer, a stats record, or a probe all satisfy it.
type AnalyzerObserver interface {
	// Name identifies the analyzer.
	Name() trawlv1alpha1.AnalyzerName

	// Healthy reports observed liveness, not desired state.
	Healthy() (bool, string)

	// Version reports the analyzer's version, empty when unknown.
	Version() string

	// LastRecord is when this analyzer last produced a record.
	LastRecord() (time.Time, bool)

	// Counters returns the tailer outcomes for this analyzer.
	Counters() Counters

	// ContentStatus reports which detection content this analyzer loaded.
	ContentStatus() content.Status
}

// PacketCounters are capture-boundary counts a sensor can observe.
//
// KernelDrops is a pointer because "zero drops" and "the analyzer does not
// report drops" are different answers, and flattening them would claim a clean
// capture that was never measured (FR-039).
type PacketCounters struct {
	PacketsObserved int64
	KernelDrops     *int64
	LastPacketTime  *time.Time
}

// StatusReporter builds the TargetStatus this sensor owns.
//
// The sensor patches only its own target entry, keyed by node name. The list is
// associative on the API side, so two sensors reporting concurrently merge
// rather than overwriting each other.
type StatusReporter struct {
	// NodeName and Interface identify this target.
	NodeName  string
	Interface string

	// InstanceID identifies this sensor process.
	//
	// Counters reset when a sensor restarts. Without knowing the instance
	// changed, a consumer would read that reset as traffic having stopped,
	// which is the opposite of what happened.
	InstanceID string

	// Analyzers are the analyzers running beside this sensor.
	Analyzers []AnalyzerObserver

	// Duplicates supplies the duplicate-detection state.
	Duplicates *DuplicateCache

	// Packets supplies capture-boundary counters.
	Packets func() PacketCounters

	// Now is indirected for tests.
	Now func() time.Time
}

// Build produces the TargetStatus for this sensor's node.
//
// It reports observed reality: an analyzer that has produced no records is not
// healthy merely because its process is running, and a target with no packets
// does not claim a last-packet time it never saw.
func (r *StatusReporter) Build() trawlv1alpha1.TargetStatus {
	now := r.now()

	status := trawlv1alpha1.TargetStatus{
		NodeName:         r.NodeName,
		Interface:        r.Interface,
		ReporterInstance: r.InstanceID,
		HeartbeatTime:    metav1.NewTime(now),
		Duplication:      trawlv1alpha1.DuplicationUnknown,
	}

	if r.Duplicates != nil {
		status.Duplication = r.Duplicates.State()
	}

	if r.Packets != nil {
		p := r.Packets()
		status.PacketsObserved = p.PacketsObserved
		status.KernelDrops = p.KernelDrops
		if p.LastPacketTime != nil {
			t := metav1.NewTime(*p.LastPacketTime)
			status.LastPacketTime = &t
		}
	}

	var rejected int64
	for _, a := range r.Analyzers {
		as := trawlv1alpha1.AnalyzerStatus{Name: a.Name()}

		healthy, reason := a.Healthy()
		as.Healthy = healthy
		if !healthy {
			// The reason is surfaced in status and read by operators, so it is
			// sanitized and bounded like any other external message.
			as.Reason = truncateReason(sanitize.String(reason))
		}
		as.Version = sanitize.String(a.Version())

		if last, ok := a.LastRecord(); ok {
			t := metav1.NewTime(last)
			as.LastRecordTime = &t
		}

		// FR-045: content currency is visible in status so an operator can
		// check it without exec'ing into a pod.
		cs := a.ContentStatus()
		if !cs.UpstreamFetchedAt.IsZero() {
			t := metav1.NewTime(cs.UpstreamFetchedAt)
			as.UpstreamFetchedAt = &t
		}
		as.CustomContentDigest = cs.CustomDigest

		c := a.Counters()
		rejected += c.Malformed + c.Unsupported

		status.Analyzers = append(status.Analyzers, as)
	}

	// Raw rejected content is never stored, only the count (FR-016).
	status.RejectedRecords = rejected
	return status
}

// AllHealthy reports whether every analyzer this sensor observes is healthy.
//
// Used to decide readiness. A partially healthy sensor is not ready, because a
// tap that reports Active while one analyzer is dead would tell an analyst the
// evidence is complete when it is not.
func (r *StatusReporter) AllHealthy() bool {
	if len(r.Analyzers) == 0 {
		return false
	}
	for _, a := range r.Analyzers {
		if healthy, _ := a.Healthy(); !healthy {
			return false
		}
	}
	return true
}

func (r *StatusReporter) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

// maxReasonBytes matches the AnalyzerStatus.reason bound in the CRD contract.
const maxReasonBytes = 256

func truncateReason(s string) string {
	if len(s) <= maxReasonBytes {
		return s
	}
	return s[:maxReasonBytes-3] + "..."
}
