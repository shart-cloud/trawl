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

package audit

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"trawl.cloud/trawl/internal/storage"
	"trawl.cloud/trawl/internal/telemetry"
)

func TestObservedCommitterCountsEveryCallerVisibleResultExactlyOnce(t *testing.T) {
	for _, transport := range []string{"local", "remote"} {
		for _, decision := range []string{DecisionAllowed, DecisionDenied} {
			for _, wantResult := range []string{ResultSuccess, ResultRetry, ResultUnavailable, ResultConflict} {
				name := fmt.Sprintf("%s/%s/%s", transport, decision, wantResult)
				t.Run(name, func(t *testing.T) {
					var raw Committer
					var store *storage.Fake
					switch transport {
					case "local":
						store = storage.NewFake()
						raw = newTestSink(t, store)
					case "remote":
						const identity = "trawl-event-worker.trawl-system.svc"
						ca := newCertAuthority(t)
						endpoint, remoteStore := startSink(t, ca, []string{identity})
						store = remoteStore
						raw = clientFor(t, ca, endpoint, "event-worker", identity)
					}

					rec := testRecord()
					rec.Decision = decision
					rec.StableKey = "observed/" + name
					switch wantResult {
					case ResultUnavailable:
						store.FailPut(errors.New("ledger unavailable"))
					case ResultRetry:
						if _, err := raw.Commit(context.Background(), rec); err != nil {
							t.Fatalf("retry fixture: %v", err)
						}
					case ResultConflict:
						if _, err := raw.Commit(context.Background(), rec); err != nil {
							t.Fatalf("conflict fixture: %v", err)
						}
						rec.Reason = "different content under the same stable key"
					}

					metrics := telemetry.NewMetrics()
					observed := ObserveCommitter(raw, metrics)
					res, err := observed.Commit(context.Background(), rec)
					if res.Result != wantResult {
						t.Errorf("result = %q, want %q", res.Result, wantResult)
					}
					wantError := wantResult == ResultUnavailable || wantResult == ResultConflict
					if !wantError && err != nil {
						t.Errorf("%s commit returned %v", wantResult, err)
					}
					if wantError && err == nil {
						t.Errorf("%s commit returned no error", wantResult)
					}

					if got := testutil.ToFloat64(metrics.AuditCommitTotal.WithLabelValues(decision, wantResult)); got != 1 {
						t.Errorf("commit counter = %v, want exactly 1", got)
					}
					wantConflicts := 0.0
					if wantResult == ResultConflict {
						wantConflicts = 1
					}
					if got := testutil.ToFloat64(metrics.AuditConflictTotal); got != wantConflicts {
						t.Errorf("conflict counter = %v, want %v", got, wantConflicts)
					}
				})
			}
		}
	}
}
