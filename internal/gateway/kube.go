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

package gateway

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/sanitize"
)

// KubeJobs reads CaptureJobs from the API server.
type KubeJobs struct {
	client client.Client
}

// NewKubeJobs returns a CaptureJobGetter backed by c.
func NewKubeJobs(c client.Client) *KubeJobs { return &KubeJobs{client: c} }

// GetCaptureJob implements CaptureJobGetter.
//
// Reads are unconditionally live rather than served from an informer cache. A
// cache would answer from a snapshot taken before a retention change or an
// expiry, which is precisely the window in which a download must start being
// refused. The gateway is not on a hot path — one read per download — so the
// cost of being right is a single API call.
func (k *KubeJobs) GetCaptureJob(ctx context.Context, namespace, name string) (*trawlv1alpha1.CaptureJob, error) {
	var job trawlv1alpha1.CaptureJob
	err := k.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &job)
	switch {
	case apierrors.IsNotFound(err):
		return nil, ErrJobNotFound
	case err != nil:
		return nil, sanitize.Errorf("reading capturejob: %v", err)
	}
	return &job, nil
}
