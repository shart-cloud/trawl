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

// Package traffic builds the synthetic traffic fixtures the NetworkTap
// acceptance suite observes (T050).
//
// SC-001 is the constraint that shapes everything here: an operator must see a
// structured record of test traffic "without logging into or modifying a
// cluster host". So a fixture may not install a generator on the node and may
// not touch the packet path — no mirror, no tee, no injected duplicate. What it
// may do is run an ordinary pod that makes ordinary requests, and let the tap
// observe them the same way it observes everything else.
//
// The traffic goes to the node's loopback interface because that is the
// interface the acceptance taps bind (see the suite's package comment). A pod
// in the host network namespace can reach it without any privilege beyond
// hostNetwork, which is the same access the sensor DaemonSet already has.
//
// Every fixture stamps a unique User-Agent. Loopback is not idle — the kubelet
// health-checks itself over it continuously — so a spec that counted every
// record on the interface would be measuring the cluster's background chatter
// and not its own traffic. Zeek records the User-Agent on each http record,
// which makes the test's own requests exactly identifiable.
package traffic

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// Image is the traffic generator, pinned like every other image the tests
	// run. It is the image the suite already uses for probe pods.
	Image = "docker.io/curlimages/curl:8.11.1"

	// DefaultTarget is what the fixtures request.
	//
	// The kubelet's health endpoint is used because it is reachable on the
	// loopback address of every Kubernetes node by definition, needs no
	// credentials, and returns a small fixed body — so the fixture adds no
	// listener of its own and cannot collide with a port somebody is using.
	// A fixture fails loudly if it does not get HTTP 200 from it, rather than
	// leaving a spec to conclude from silence that the tap saw nothing.
	DefaultTarget = "http://127.0.0.1:10248/healthz"

	// userAgentPrefix marks traffic as belonging to this suite. The run ID and
	// the fixture kind follow, so two fixtures in one run stay distinguishable
	// and a leaked pod from an earlier run cannot be counted as this one's.
	userAgentPrefix = "trawl-acceptance"
)

// Fixture is one traffic generator: a pod to run, and what the tap should be
// able to say about the traffic it produces.
type Fixture struct {
	// Pod is the generator, ready to apply.
	Pod *corev1.Pod

	// UserAgent identifies this fixture's requests in the observation stream.
	UserAgent string

	// Requests is how many HTTP transactions the pod performs. Zeek emits one
	// http record per transaction, so this is also the number of records the
	// fixture expects to find — the count that proves nothing was dropped.
	Requests int
}

// Baseline generates ordinary, unrelated HTTP requests.
//
// Each request opens its own connection, so every transaction carries a
// distinct source port and therefore a distinct duplicate fingerprint. This is
// the fixture for "a tap observes real traffic and describes it correctly": its
// records should all come back NotDetected, and a Suspected among them would
// mean the duplicate heuristic fires on traffic that is plainly not duplicated.
func Baseline(namespace, node, runID string) Fixture {
	const requests = 12
	agent := userAgent(runID, "baseline")

	// --no-keepalive forces a fresh connection per request. Without it curl
	// reuses the socket and the records collapse onto one tuple, which is the
	// duplicate fixture's shape, not this one's.
	script := fmt.Sprintf(`set -e
for i in $(seq 1 %d); do
  code=$(curl -s --no-keepalive -o /dev/null -w '%%{http_code}' -A '%s' '%s')
  echo "$code"
  [ "$code" = "200" ] || { echo "unexpected status $code from %s" >&2; exit 1; }
  sleep 0.2
done
echo generated=%d`, requests, agent, target(), target(), requests)

	return Fixture{
		Pod:       pod(namespace, node, name(runID, "baseline"), script),
		UserAgent: agent,
		Requests:  requests,
	}
}

// Duplicate generates traffic the duplicate heuristic must mark.
//
// The heuristic fingerprints a record by its tap, target, source kind,
// observation type, protocol, normalized endpoints and Community ID, bucketed
// to the millisecond of the event. Genuinely duplicated packets — the mirrored
// and overlay traffic the design is for — collide on all of those. So does a
// burst of HTTP transactions pipelined down one kept-alive connection: one
// tuple, one Community ID, many transactions inside the same millisecond.
//
// That is deliberately a fixture for the *shape* the heuristic keys on rather
// than for literally duplicated packets, and the distinction is worth being
// plain about. Duplicating packets on the wire would mean mutating the packet
// path, which SC-001 forbids. What this fixture can prove is the property that
// actually matters and that no unit test can reach: in a deployed sensor, a
// record the heuristic suspects is still emitted, still valid, and counted —
// marking never discards evidence. Whether a given mark is *correct* is the
// judgement the design explicitly leaves to an analyst (see internal/sensor's
// DuplicateCache), which is why this asserts visibility and not accuracy.
func Duplicate(namespace, node, runID string) Fixture {
	const requests = 40
	agent := userAgent(runID, "duplicate")

	// One curl invocation given the URL many times reuses a single connection
	// and issues the requests back to back with no pause between them.
	script := fmt.Sprintf(`set -e
urls=""
i=0
while [ $i -lt %d ]; do urls="$urls %s"; i=$((i+1)); done
curl -s -o /dev/null -A '%s' $urls
echo generated=%d`, requests, target(), agent, requests)

	return Fixture{
		Pod:       pod(namespace, node, name(runID, "duplicate"), script),
		UserAgent: agent,
		Requests:  requests,
	}
}

func target() string { return DefaultTarget }

func userAgent(runID, kind string) string {
	return fmt.Sprintf("%s/%s/%s", userAgentPrefix, kind, runID)
}

func name(runID, kind string) string {
	return fmt.Sprintf("trawl-traffic-%s-%s", kind, runID)
}

// pod renders the generator.
//
// Built from the API types rather than a YAML template for the same reason the
// suite builds its taps that way: a field renamed in the API should fail to
// compile, not keep applying and silently start testing a default.
func pod(namespace, node, podName, script string) *corev1.Pod {
	return &corev1.Pod{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
			Labels:    map[string]string{"trawl.cloud/acceptance-traffic": "true"},
		},
		Spec: corev1.PodSpec{
			// The traffic has to appear on the node's loopback interface, which
			// is the interface the tap binds. A pod in its own network
			// namespace has its own loopback and the tap would never see it.
			HostNetwork:   true,
			NodeName:      node,
			RestartPolicy: corev1.RestartPolicyNever,
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   ptr(true),
				RunAsUser:      ptr(int64(65534)),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{{
				Name:    "traffic",
				Image:   Image,
				Command: []string{"sh", "-c"},
				Args:    []string{script},
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: ptr(false),
					Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
				},
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("10m"),
						corev1.ResourceMemory: resource.MustParse("32Mi"),
					},
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("200m"),
						corev1.ResourceMemory: resource.MustParse("64Mi"),
					},
				},
			}},
		},
	}
}

func ptr[T any](v T) *T { return &v }
