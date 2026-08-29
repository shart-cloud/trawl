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
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"trawl.cloud/trawl/internal/audit"
	"trawl.cloud/trawl/internal/status"
	"trawl.cloud/trawl/internal/telemetry"
)

func newRegistry(t *testing.T, m *telemetry.Metrics) *prometheus.Registry {
	t.Helper()
	reg := prometheus.NewRegistry()
	if err := m.Register(reg); err != nil {
		t.Fatalf("registering metrics: %v", err)
	}
	return reg
}

// auditActions mirrors the implemented action enum.
func auditActions() []string {
	return []string{
		audit.ActionNetworkTapCreate, audit.ActionNetworkTapUpdate, audit.ActionNetworkTapDelete,
		audit.ActionCapturePolicyCreate, audit.ActionCapturePolicyUpdate, audit.ActionCapturePolicyDelete,
		audit.ActionCapturePolicyArm, audit.ActionCapturePolicyDisarm,
		audit.ActionCaptureJobManualCreate, audit.ActionCaptureJobPolicyCreate,
		audit.ActionCaptureJobTransition,
		audit.ActionArtifactDownload, audit.ActionRetentionChange, audit.ActionArtifactExpire,
	}
}

// conditionTypes mirrors the implemented condition-type set.
func conditionTypes() []string {
	return []string{
		status.TypeAccepted, status.TypeTargetsResolved, status.TypeWorkloadReady,
		status.TypeAnalyzersHealthy, status.TypePacketsObserved,
		status.TypeTapResolved, status.TypeSourceConnected, status.TypeWithinRateLimit,
		status.TypeReady,
		status.TypeTargetReady, status.TypeFilterValid, status.TypeCaptureStarted,
		status.TypeArtifactVerified, status.TypeDownloadable, status.TypeRetentionEnforced,
	}
}
