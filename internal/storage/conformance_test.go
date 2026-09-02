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

package storage_test

import (
	"testing"

	"trawl.cloud/trawl/internal/storage"
	"trawl.cloud/trawl/internal/storage/storagetest"
)

// The Fake stands in for a real object store in every unit test in this repo.
// It is only as useful as it is faithful, so it answers the same contract.
func TestFakeSatisfiesTheStoreContract(t *testing.T) {
	storagetest.RunConformance(t, func(*testing.T) (storage.Store, string) {
		return storage.NewFake(), "audit/v1/"
	})
}
