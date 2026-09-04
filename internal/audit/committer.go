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

import "context"

// Committer is the subset of the sink that writers depend on: the admission
// gate, the capture controller, and the retention sweeper all commit records
// and read the result, and none of them replay or backlog.
//
// Both Sink and Client satisfy it, so a component can hold ledger credentials
// directly or commit through the mTLS sink without knowing which.
type Committer interface {
	Commit(ctx context.Context, rec Record) (CommitResult, error)
}
