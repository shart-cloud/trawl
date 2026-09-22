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

	"trawl.cloud/trawl/internal/telemetry"
)

// Committer is the subset of the sink that writers depend on: the admission
// gate, the capture controller, and the retention sweeper all commit records
// and read the result, and none of them replay or backlog.
//
// Both Sink and Client satisfy it, so a component can hold ledger credentials
// directly or commit through the mTLS sink without knowing which.
type Committer interface {
	Commit(ctx context.Context, rec Record) (CommitResult, error)
}

type observedCommitter struct {
	next    Committer
	metrics *telemetry.Metrics
}

// ObserveCommitter counts one caller-visible result for every commit attempt.
//
// This wrapper belongs at the caller's composition root. In particular, the
// manager's mTLS sink server receives the raw Sink: a remote commit is observed
// by the gateway or worker that made the call, not counted again when the
// server receives the same operation.
func ObserveCommitter(next Committer, metrics *telemetry.Metrics) Committer {
	if metrics == nil {
		return next
	}
	return &observedCommitter{next: next, metrics: metrics}
}

func (c *observedCommitter) Commit(ctx context.Context, rec Record) (CommitResult, error) {
	res, err := c.next.Commit(ctx, rec)
	result := res.Result
	if result == "" {
		result = ResultUnavailable
	}
	c.metrics.AuditCommitTotal.WithLabelValues(rec.Decision, result).Inc()
	if result == ResultConflict {
		c.metrics.AuditConflictTotal.Inc()
	}
	return res, err
}
