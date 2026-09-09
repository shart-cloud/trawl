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
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"

	"trawl.cloud/trawl/internal/observation"
	"trawl.cloud/trawl/internal/policy"
)

func TestTheFlowKeyIsTheSameInEitherDirection(t *testing.T) {
	// One conversation, two records: the analyzer reports the client's packets
	// and the server's reply as separate flows with the endpoints swapped. A
	// direction-sensitive key would treat them as two conversations and capture
	// the same traffic twice, which is exactly the duplication the key exists
	// to collapse.
	port := func(v int32) *int32 { return &v }
	forward := &observation.Flow{
		Protocol:    "tcp",
		Source:      observation.Endpoint{IP: "10.0.0.1", Port: port(41022)},
		Destination: observation.Endpoint{IP: "10.0.0.2", Port: port(5432)},
	}
	reverse := &observation.Flow{
		Protocol:    "tcp",
		Source:      observation.Endpoint{IP: "10.0.0.2", Port: port(5432)},
		Destination: observation.Endpoint{IP: "10.0.0.1", Port: port(41022)},
	}

	if got, want := policy.FlowKey(reverse), policy.FlowKey(forward); got != want {
		t.Errorf("reversed flow keyed %q, want %q", got, want)
	}
}

func TestEquivalentTrafficInOneCooldownBucketSharesAKey(t *testing.T) {
	// The key is what makes "at most one capture for the equivalent source and
	// traffic within the cooldown window" (FR-031) enforceable without holding
	// state: two workers, or one worker across a restart, derive the same key
	// from the same event and the create-or-get collapses to one job.
	cooldown := 5 * time.Minute
	at := time.Date(2026, 9, 9, 14, 2, 0, 0, time.UTC)
	flow := drop().Flow

	first := policy.DeduplicationKey("tap-uid", flow, at, cooldown)
	later := policy.DeduplicationKey("tap-uid", flow, at.Add(90*time.Second), cooldown)
	if first != later {
		t.Errorf("two events 90s apart in a 5m cooldown keyed differently:\n %s\n %s", first, later)
	}

	next := policy.DeduplicationKey("tap-uid", flow, at.Add(10*time.Minute), cooldown)
	if first == next {
		t.Error("an event two cooldowns later shared the first event's key")
	}

	otherTap := policy.DeduplicationKey("other-tap", flow, at, cooldown)
	if first == otherTap {
		t.Error("the same traffic on a different tap shared a key; each tap captures its own")
	}
}

func TestTheDeduplicationKeyIsAHashAndNotTheTrafficItself(t *testing.T) {
	// The key is written to CaptureJob.spec.deduplicationKey, which is readable
	// by anyone who can read CaptureJobs - a wider audience than the one
	// authorized to download the capture. Addresses and ports in clear would
	// disclose who talked to whom to a viewer who may not download the pcap.
	flow := drop().Flow
	key := policy.DeduplicationKey("tap-uid", flow, time.Now(), time.Minute)

	if !strings.HasPrefix(key, "sha256:") {
		t.Errorf("key %q is not a sha256 digest", key)
	}
	for _, leaked := range []string{"10.244.0.11", "10.244.0.42", "41022", "5432", "tap-uid"} {
		if strings.Contains(key, leaked) {
			t.Errorf("key %q contains %q in clear", key, leaked)
		}
	}
}

func TestTheCaptureJobNameIsDeterministicAndAValidObjectName(t *testing.T) {
	// Two workers racing on the same event must propose the same name, because
	// the name is what makes the create-or-get collapse: the second create
	// fails with AlreadyExists and the worker adopts the existing job. A name
	// the API server rejects would turn that collapse into a failed capture.
	key := policy.DeduplicationKey("tap-uid", drop().Flow, time.Now(), time.Minute)

	name := policy.CaptureJobName(key)
	if name != policy.CaptureJobName(key) {
		t.Error("the same key produced two different names")
	}
	if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
		t.Errorf("name %q is not a valid object name: %v", name, errs)
	}
	if len(name) > 63 {
		t.Errorf("name %q is %d characters; label-length limits apply downstream", name, len(name))
	}
	if other := policy.CaptureJobName(policy.DeduplicationKey("tap-uid", drop().Flow, time.Now().Add(time.Hour), time.Minute)); other == name {
		t.Error("different keys produced the same name")
	}
}
