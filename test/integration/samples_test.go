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

package integration

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/admission"
)

// A sample that does not apply is worse than no sample: it is the first thing
// an operator copies, and the second thing they blame themselves for. Nothing
// checked these until now - the reference configuration had the same gap and
// the same fix (TestDevConfigMapValidates).
//
// Only config/samples is checked here. config/samples/invalid is a mix: some of
// those are refused by the schema, and some - the off-namespace tap - only by
// the admission webhook, which is not running in envtest. Asserting "all of
// them are rejected" would pass for the wrong reason on half the directory. The
// webhook's own rules are tested directly in internal/admission, and the one
// invalid sample that the schema refuses is asserted below by name.

func TestEverySampleApplies(t *testing.T) {
	ns := NewNamespace(t)
	ctx := context.Background()

	dir := filepath.Join("..", "..", "config", "samples")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading the samples directory: %v", err)
	}

	var checked int
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			obj := loadSample(t, filepath.Join(dir, entry.Name()))
			// Re-namespaced into this test's namespace. The samples name
			// trawl-system, which is the right thing for them to say and does
			// not exist here.
			obj.SetNamespace(ns)
			if err := Client().Create(ctx, obj); err != nil {
				t.Errorf("the sample does not apply: %v", err)
			}
		})
		checked++
	}

	// A directory that quietly became empty would otherwise pass.
	if checked == 0 {
		t.Fatal("no samples were checked")
	}
}

func TestThePolicySamplesSatisfyTheWebhookToo(t *testing.T) {
	// The schema admitting a sample is only half the answer. The filter
	// template's placeholders are a contract between the API type and
	// internal/policy that no schema rule can express, so the webhook is what
	// refuses a template naming something the renderer cannot resolve - and a
	// sample carrying one would apply cleanly in envtest and be rejected by the
	// first real cluster an operator tried it on.
	dir := filepath.Join("..", "..", "config", "samples")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading the samples directory: %v", err)
	}

	var checked int
	for _, entry := range entries {
		if !strings.Contains(entry.Name(), "capturepolicy") {
			continue
		}
		checked++
		t.Run(entry.Name(), func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Fatalf("reading the sample: %v", err)
			}
			var p trawlv1alpha1.CapturePolicy
			if err := yaml.Unmarshal(raw, &p); err != nil {
				t.Fatalf("decoding the sample: %v", err)
			}
			// The contract maximum, so a sample is not judged against one
			// installation's tighter ceiling.
			if errs := admission.ValidateCapturePolicySpec(&p.Spec, 30*24*time.Hour); len(errs) > 0 {
				t.Errorf("the webhook would reject this sample: %v", errs.ToAggregate())
			}
		})
	}
	if checked == 0 {
		t.Fatal("no capture policy samples were checked")
	}
}

func TestTheTwoTriggerPolicySampleIsRefusedByTheSchema(t *testing.T) {
	// This one is refused by CEL on the CRD rather than by the webhook, which
	// is what its comment claims - the union stays closed even when admission
	// is unavailable. If that ever stops being true the sample's explanation is
	// wrong, and an operator reading it would draw the wrong conclusion about
	// where the boundary is.
	ns := NewNamespace(t)

	obj := loadSample(t, filepath.Join("..", "..", "config", "samples", "invalid",
		"trawl_v1alpha1_capturepolicy_two_triggers.yaml"))
	obj.SetNamespace(ns)

	err := Client().Create(context.Background(), obj)
	if err == nil {
		t.Fatal("a policy carrying both trigger bodies was admitted")
	}
	if !strings.Contains(err.Error(), "hubbleDrop is only allowed when trigger type is HubbleDrop") {
		t.Errorf("rejected with %v, want the union's exclusivity rule", err)
	}
}

// loadSample decodes one single-document sample manifest.
func loadSample(t *testing.T, path string) *unstructured.Unstructured {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	obj := &unstructured.Unstructured{}
	if err := yaml.Unmarshal(raw, obj); err != nil {
		t.Fatalf("decoding %s: %v", path, err)
	}
	return obj
}
