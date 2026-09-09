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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"trawl.cloud/trawl/internal/observation"
)

// FlowKey renders a flow as a direction-neutral canonical string.
//
// One conversation reaches the worker as two records - the client's packets and
// the server's reply, endpoints swapped - and both describe traffic a single
// capture would collect. Ordering the two endpoints puts them in the same
// bucket, so the pair collapses instead of capturing the same conversation
// twice.
func FlowKey(flow *observation.Flow) string {
	if flow == nil {
		return ""
	}
	a := endpointKey(flow.Source)
	b := endpointKey(flow.Destination)
	if b < a {
		a, b = b, a
	}
	return strings.Join([]string{flow.Protocol, a, b}, "|")
}

func endpointKey(ep observation.Endpoint) string {
	if ep.Port == nil {
		return ep.IP
	}
	return fmt.Sprintf("%s:%d", ep.IP, *ep.Port)
}

// DeduplicationKey identifies the trigger window a capture answers.
//
// It covers the tap, the canonical flow, and the cooldown bucket the event
// falls in - and deliberately not the policy that matched. Two policies that
// match the same traffic under the same cooldown want the same packets, and the
// spec collapses equivalent requests rather than capturing the same
// conversation twice (spec.md, "Several policies may match one event").
//
// Bucketing rather than "within cooldown of the last capture" is what makes the
// key derivable from the event alone. No worker has to have seen the previous
// capture to agree on it, so two workers racing, or one worker after a restart,
// reach the same key and the create-or-get collapses them. The cost is a
// boundary: two events a second apart can straddle a bucket edge and produce
// two captures. That is the honest trade - a bounded, visible duplicate at the
// edge, against a key that needs no shared state to be correct.
func DeduplicationKey(tapUID string, flow *observation.Flow, at time.Time, cooldown time.Duration) string {
	bucket := at.UTC().Truncate(cooldown).Unix()

	// Hashed rather than rendered. The key lands on CaptureJob.spec, readable
	// by anyone who can read CaptureJobs - a wider audience than the one
	// authorized to download the capture - so addresses and ports in clear
	// would disclose who talked to whom to a viewer who may not see the pcap.
	sum := sha256.Sum256(fmt.Appendf(nil, "%s\x00%s\x00%d", tapUID, FlowKey(flow), bucket))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// CaptureJobName is the object name a capture for this key must take.
//
// Deterministic because the name is what performs the deduplication: two
// workers racing on one event propose the same name, the second create fails
// with AlreadyExists, and that worker adopts the existing job instead of
// starting a second capture of the same traffic.
func CaptureJobName(deduplicationKey string) string {
	digest := strings.TrimPrefix(deduplicationKey, "sha256:")
	// Truncated to keep the name inside the 63-character label limit that
	// applies to the objects derived from it downstream. 32 hex characters is
	// 128 bits, which is not a collision anyone reaches by accident.
	if len(digest) > 32 {
		digest = digest[:32]
	}
	return "trawl-policy-" + digest
}
