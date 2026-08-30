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

package contract

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	"sigs.k8s.io/yaml"
)

// A workload's replica count and its readiness contract have to agree. When
// they do not, Kubernetes reports the disagreement as a Deployment that never
// becomes available and a rollout that never finishes - never as an error - so
// nothing draws attention to it until someone reads the Deployment's status.

func readDeployment(t *testing.T, path string) *appsv1.Deployment {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), path))
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var deploy appsv1.Deployment
	if err := yaml.Unmarshal(data, &deploy); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	if deploy.Kind != "Deployment" {
		t.Fatalf("%s is a %s, not a Deployment", path, deploy.Kind)
	}
	return &deploy
}

func TestEventWorkerIsADeployableSingleton(t *testing.T) {
	// The event worker's readiness check requires a connected Hubble flow
	// stream, and only the leader connects: the stream is opened from
	// OnStartedLeading. That is the right readiness contract - a worker that
	// reported ready while disconnected would hide the fact that denied-flow
	// evidence is not being collected - but it means a standby replica can
	// never become ready.
	//
	// Two consequences follow, and both were observed on a live cluster before
	// this test existed. With more than one replica the Deployment is
	// permanently Available=False, because the second pod cannot satisfy the
	// probe. And under RollingUpdate any upgrade deadlocks: the incoming pod
	// waits for a lease the outgoing leader still holds, the outgoing leader is
	// never removed because the incoming pod is not ready, and the Deployment
	// sits at ProgressDeadlineExceeded while continuing to serve from the image
	// it booted with hours earlier.
	//
	// Recreate is what breaks that cycle. The old pod terminates first, which
	// releases the lease (ReleaseOnCancel), and the new pod then acquires it
	// and connects. The cost is a brief gap in cluster-flow collection during
	// an upgrade, which is visible in the record stream rather than hidden.
	main, err := os.ReadFile(filepath.Join(repoRoot(t), "cmd/event-worker/main.go"))
	if err != nil {
		t.Fatalf("reading event-worker main: %v", err)
	}
	if !strings.Contains(string(main), "client.Connected()") {
		t.Skip("event-worker readiness no longer depends on the flow stream; " +
			"re-derive the replica constraint before deleting this test")
	}

	deploy := readDeployment(t, "config/manager/event-worker.yaml")

	if deploy.Spec.Replicas == nil || *deploy.Spec.Replicas != 1 {
		got := "unset"
		if deploy.Spec.Replicas != nil {
			got = strconv.Itoa(int(*deploy.Spec.Replicas))
		}
		t.Errorf("event-worker declares %s replicas; readiness is gated on leadership, "+
			"so any replica beyond the leader keeps the Deployment permanently unavailable", got)
	}

	if deploy.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType {
		t.Errorf("event-worker uses the %q update strategy; a leader-elected singleton "+
			"whose readiness needs the lease can only be rolled with Recreate, "+
			"or the incoming pod waits for a lease the outgoing pod never releases",
			deploy.Spec.Strategy.Type)
	}
}
