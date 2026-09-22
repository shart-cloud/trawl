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

package storage

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func TestS3HeadPerformsOneMetadataOperation(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodHead {
			t.Errorf("metadata request method = %s, want HEAD only", r.Method)
		}
		w.Header().Set("ETag", `"abc123"`)
		w.Header().Set("Last-Modified", time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC).Format(http.TimeFormat))
		w.Header().Set("Content-Length", "7")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	client, err := minio.New(strings.TrimPrefix(server.URL, "http://"), &minio.Options{
		Creds:  credentials.NewStaticV4("access", "secret", ""),
		Secure: false,
		Region: "us-east-1",
	})
	if err != nil {
		t.Fatalf("minio.New: %v", err)
	}
	store := &S3Store{client: client, bucket: "artifacts", timeout: time.Second}
	if _, err := store.Head(t.Context(), "captures/job.pcap"); err != nil {
		t.Fatalf("Head: %v", err)
	}
	if got := requests.Load(); got != 1 {
		t.Errorf("backend metadata operations = %d, want 1", got)
	}
}
