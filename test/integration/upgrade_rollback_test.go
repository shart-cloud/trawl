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

// T122: what an upgrade and a rollback may not do to objects already stored.
//
// The API-shape tests beside this file ask whether the schema accepts the right
// objects today. These ask a different question: whether the objects a previous
// release already wrote survive the schema this release ships, and whether an
// operator who rolls back gets their cluster rather than a pile of unreadable
// custom resources.
//
// That failure is silent in the worst way. Nothing breaks at upgrade time - the
// CRD applies, the controller starts - and the damage only appears when someone
// tries to change a resource written months earlier and cannot, or when a field
// an older controller depended on has quietly been pruned out of every stored
// object.
//
// US4 already produced one live instance of the class, recorded in tasks.md: a
// CapturePolicy whose threshold window exceeds fifteen minutes becomes
// un-updatable on a cluster without CRD validation ratcheting - including
// un-disarmable, which is the one change an operator most needs to make to a
// policy that is misbehaving.
package integration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
)

// schemaSurfaceGolden records the stored schema surface a previous release
// shipped. See TestTheStoredSchemaSurfaceOnlyGrows.
const schemaSurfaceGolden = "testdata/v1alpha1-schema-surface.json"

// loadCRDs reads the generated CRDs the installer applies.
func loadCRDs(t *testing.T) []apiextensionsv1.CustomResourceDefinition {
	t.Helper()
	dir := filepath.Join("..", "..", "config", "crd", "bases")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}

	var out []apiextensionsv1.CustomResourceDefinition
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		raw, readErr := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // G304: a generated file in the repository.
		if readErr != nil {
			t.Fatalf("reading %s: %v", e.Name(), readErr)
		}
		var crd apiextensionsv1.CustomResourceDefinition
		if err := yaml.Unmarshal(raw, &crd); err != nil {
			t.Fatalf("decoding %s: %v", e.Name(), err)
		}
		out = append(out, crd)
	}
	if len(out) == 0 {
		t.Fatalf("no CRDs found under %s, so every check in this file would assert nothing", dir)
	}
	return out
}

func TestExactlyOneStorageVersionPerTrawlCRD(t *testing.T) {
	// Kubernetes requires exactly one version per CRD to be the storage
	// version, and it is the version etcd holds. Two would be rejected by the
	// API server, but zero is the interesting mistake: a CRD whose only version
	// is marked served-but-not-stored applies cleanly and then cannot persist
	// anything.
	//
	// It is asserted here rather than left to the API server because this is
	// also the anchor for the whole file: every other check below is about
	// v1alpha1 specifically, and they would all quietly change meaning if a
	// second version appeared without anyone deciding what upgrade means.
	for _, crd := range loadCRDs(t) {
		var stored []string
		for _, v := range crd.Spec.Versions {
			if v.Storage {
				stored = append(stored, v.Name)
			}
			if !v.Served {
				t.Errorf("%s: version %s is not served, so no client can read objects stored in it",
					crd.Name, v.Name)
			}
		}
		if len(stored) != 1 {
			t.Errorf("%s: %d storage versions %v, want exactly 1", crd.Name, len(stored), stored)
			continue
		}
		if stored[0] != trawlv1alpha1.GroupVersion.Version {
			t.Errorf("%s: storage version is %s, but this file's compatibility checks are written "+
				"against %s; a new storage version needs a conversion story before it needs a test",
				crd.Name, stored[0], trawlv1alpha1.GroupVersion.Version)
		}
	}
}

// schemaSurface is the compatibility-relevant shape of one CRD: which property
// paths exist, and which of them a client is obliged to set.
type schemaSurface struct {
	Properties []string `json:"properties"`
	Required   []string `json:"required"`
}

// walkSchema collects every property path and every required path.
func walkSchema(prefix string, s *apiextensionsv1.JSONSchemaProps, props, required *[]string) {
	if s == nil {
		return
	}
	for _, r := range s.Required {
		*required = append(*required, join(prefix, r))
	}
	for name, sub := range s.Properties {
		path := join(prefix, name)
		*props = append(*props, path)
		walkSchema(path, &sub, props, required)
	}
	if s.Items != nil && s.Items.Schema != nil {
		walkSchema(prefix+"[]", s.Items.Schema, props, required)
	}
}

func join(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "." + name
}

// currentSurface renders the surface of every CRD, keyed by CRD name.
func currentSurface(t *testing.T) map[string]schemaSurface {
	t.Helper()
	out := map[string]schemaSurface{}
	for _, crd := range loadCRDs(t) {
		for _, v := range crd.Spec.Versions {
			if !v.Storage || v.Schema == nil || v.Schema.OpenAPIV3Schema == nil {
				continue
			}
			var props, required []string
			walkSchema("", v.Schema.OpenAPIV3Schema, &props, &required)
			sort.Strings(props)
			sort.Strings(required)
			out[crd.Name] = schemaSurface{Properties: props, Required: required}
		}
	}
	return out
}

func TestTheStoredSchemaSurfaceOnlyGrows(t *testing.T) {
	// The compatibility contract for a single stored version, in two halves.
	//
	// A property that disappears is data loss on the next write: the API server
	// prunes what the structural schema does not describe, so an object written
	// before the removal comes back without it, and an operator who rolls back
	// to a controller that still reads it finds it empty. Renaming a field is
	// the same event wearing a friendlier name.
	//
	// A property that becomes required is worse, because it strands objects
	// rather than thinning them. Every stored object that omitted it is now
	// invalid, and on a cluster without validation ratcheting the API server
	// refuses every update to it - including the disarm or the delete an
	// operator reaches for when something is wrong.
	//
	// The golden is regenerated deliberately, never automatically: adding a
	// field updates it as a reviewed line in a diff, and removing one has to be
	// argued for in the same diff.
	current := currentSurface(t)
	if len(current) == 0 {
		t.Fatal("no storage-version schemas were found, so this check asserts nothing")
	}

	// Regeneration is an explicit, separate act. It is env-gated rather than
	// automatic because the whole value of the golden is that removing a field
	// has to appear in a diff somebody reads: a test that rewrote its own
	// expectations would record the breakage instead of catching it.
	if os.Getenv("TRAWL_UPDATE_SCHEMA_SURFACE") == "1" {
		encoded, encErr := json.MarshalIndent(current, "", "  ")
		if encErr != nil {
			t.Fatalf("encoding the schema surface: %v", encErr)
		}
		if mkErr := os.MkdirAll(filepath.Dir(schemaSurfaceGolden), 0o755); mkErr != nil {
			t.Fatalf("creating the golden directory: %v", mkErr)
		}
		if wErr := os.WriteFile(schemaSurfaceGolden, append(encoded, '\n'), 0o600); wErr != nil {
			t.Fatalf("writing %s: %v", schemaSurfaceGolden, wErr)
		}
		t.Logf("rewrote %s; review the diff before committing it", schemaSurfaceGolden)
		return
	}

	raw, err := os.ReadFile(schemaSurfaceGolden)
	if err != nil {
		t.Fatalf("reading %s: %v\nhint: regenerate with `TRAWL_UPDATE_SCHEMA_SURFACE=1 go test ./test/integration/ -run TestTheStoredSchemaSurfaceOnlyGrows`",
			schemaSurfaceGolden, err)
	}
	var golden map[string]schemaSurface
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatalf("decoding %s: %v", schemaSurfaceGolden, err)
	}

	for name, was := range golden {
		now, ok := current[name]
		if !ok {
			t.Errorf("%s was shipped and is now absent; every object stored under it becomes unreadable", name)
			continue
		}

		have := map[string]bool{}
		for _, p := range now.Properties {
			have[p] = true
		}
		for _, p := range was.Properties {
			if !have[p] {
				t.Errorf("%s: property %q was shipped and has been removed or renamed. The API server "+
					"prunes what the schema does not describe, so stored objects lose it on their next "+
					"write and a rolled-back controller reads it empty.", name, p)
			}
		}

		wasRequired := map[string]bool{}
		for _, r := range was.Required {
			wasRequired[r] = true
		}
		for _, r := range now.Required {
			if !wasRequired[r] {
				t.Errorf("%s: property %q is newly required. Every stored object that omitted it is now "+
					"invalid, and without CRD validation ratcheting the API server refuses every update "+
					"to those objects - including disarming or correcting them.", name, r)
			}
		}
	}

	for name := range current {
		if _, ok := golden[name]; !ok {
			t.Logf("%s is new since the golden was taken; regenerate %s to adopt it", name, schemaSurfaceGolden)
		}
	}
}

func TestAStoredObjectRoundTripsThroughTheAPIWithoutLoss(t *testing.T) {
	// Create a fully populated object of every kind, read it back, and compare
	// the spec byte for byte.
	//
	// This is the check that catches pruning. A field the Go type still carries
	// but the generated CRD no longer describes is invisible in every unit test
	// - the struct round-trips through encoding/json perfectly well - and is
	// silently dropped by the API server. Only a real apiserver shows it.
	ns := NewNamespace(t)
	ctx := context.Background()

	t.Run("NetworkTap", func(t *testing.T) {
		want := mirrorTap(ns, "roundtrip-tap")
		sent, err := json.Marshal(want.Spec)
		if err != nil {
			t.Fatalf("encoding the sent spec: %v", err)
		}
		if err := Client().Create(ctx, want); err != nil {
			t.Fatalf("creating: %v", err)
		}
		var got trawlv1alpha1.NetworkTap
		if err := Client().Get(ctx, client.ObjectKeyFromObject(want), &got); err != nil {
			t.Fatalf("reading back: %v", err)
		}
		assertNoFieldLost(t, sent, got.Spec)
	})

	t.Run("CaptureJob", func(t *testing.T) {
		want := manualCapture(ns, "roundtrip-capture")
		sent, err := json.Marshal(want.Spec)
		if err != nil {
			t.Fatalf("encoding the sent spec: %v", err)
		}
		if err := Client().Create(ctx, want); err != nil {
			t.Fatalf("creating: %v", err)
		}
		var got trawlv1alpha1.CaptureJob
		if err := Client().Get(ctx, client.ObjectKeyFromObject(want), &got); err != nil {
			t.Fatalf("reading back: %v", err)
		}
		assertNoFieldLost(t, sent, got.Spec)
	})

	t.Run("CapturePolicy", func(t *testing.T) {
		want := newPolicy(t, ns, "roundtrip-policy")
		sent, err := json.Marshal(want.Spec)
		if err != nil {
			t.Fatalf("encoding the sent spec: %v", err)
		}
		if err := Client().Create(ctx, want); err != nil {
			t.Fatalf("creating: %v", err)
		}
		var got trawlv1alpha1.CapturePolicy
		if err := Client().Get(ctx, client.ObjectKeyFromObject(want), &got); err != nil {
			t.Fatalf("reading back: %v", err)
		}
		assertNoFieldLost(t, sent, got.Spec)
	})
}

// assertNoFieldLost reports any field present in the sent spec and absent or
// changed in the stored one.
//
// Defaulting means the stored object may carry *more* than was sent, so this is
// deliberately one-directional: extra keys are fine, missing or altered ones
// are not.
func assertNoFieldLost(t *testing.T, sent []byte, stored any) {
	t.Helper()

	var was map[string]any
	if err := json.Unmarshal(sent, &was); err != nil {
		t.Fatalf("decoding the sent spec: %v", err)
	}
	raw, err := json.Marshal(stored)
	if err != nil {
		t.Fatalf("encoding the stored spec: %v", err)
	}
	var now map[string]any
	if err := json.Unmarshal(raw, &now); err != nil {
		t.Fatalf("decoding the stored spec: %v", err)
	}
	compareTree(t, "", was, now)
}

func compareTree(t *testing.T, prefix string, was, now map[string]any) {
	t.Helper()
	for k, wantVal := range was {
		path := join(prefix, k)
		gotVal, ok := now[k]
		if !ok {
			t.Errorf("field %q was sent and is not in the stored object; the CRD does not describe it, "+
				"so the API server pruned it", path)
			continue
		}
		wantMap, wantIsMap := wantVal.(map[string]any)
		gotMap, gotIsMap := gotVal.(map[string]any)
		if wantIsMap && gotIsMap {
			compareTree(t, path, wantMap, gotMap)
			continue
		}
		wantJSON, _ := json.Marshal(wantVal)
		gotJSON, _ := json.Marshal(gotVal)
		if string(wantJSON) != string(gotJSON) {
			t.Errorf("field %q was sent as %s and stored as %s", path, wantJSON, gotJSON)
		}
	}
}

func TestDisarmingAPolicyIsAvailableAtEveryAcceptedBound(t *testing.T) {
	// Disarming is the safety valve. Whatever else is wrong with a policy - it
	// is capturing too much, it is pointed at the wrong tap, its threshold was
	// mistyped - setting armed to false is the change an operator reaches for
	// first, and it has to be available on every object the API accepted.
	//
	// The way that breaks is a validation rule written against `self` rather
	// than a create-time or transition condition: it re-validates the whole
	// object on every update, so an object at an awkward corner of the accepted
	// space can be created and then never changed. tasks.md records a live one
	// - a threshold window past fifteen minutes, reachable on a cluster whose
	// stored objects predate the rule - and this is the regression test for
	// adding another.
	//
	// So: build a policy at each boundary the schema allows, and disarm it.
	ctx := context.Background()

	corners := []struct {
		name   string
		mutate func(*trawlv1alpha1.CapturePolicySpec)
	}{
		{"shortest-threshold-window", func(s *trawlv1alpha1.CapturePolicySpec) {
			s.Trigger = dropTrigger(1, "1s")
		}},
		{"longest-threshold-window", func(s *trawlv1alpha1.CapturePolicySpec) {
			s.Trigger = dropTrigger(1, "15m")
		}},
		{"largest-threshold-count", func(s *trawlv1alpha1.CapturePolicySpec) {
			s.Trigger = dropTrigger(10000, "15m")
		}},
		{"shortest-capture", func(s *trawlv1alpha1.CapturePolicySpec) {
			s.Capture.Duration = "1s"
		}},
		{"longest-capture", func(s *trawlv1alpha1.CapturePolicySpec) {
			s.Capture.Duration = "1h"
		}},
		{"smallest-capture-size", func(s *trawlv1alpha1.CapturePolicySpec) {
			s.Capture.MaxSize = resource.MustParse("1Mi")
		}},
		{"largest-capture-size", func(s *trawlv1alpha1.CapturePolicySpec) {
			s.Capture.MaxSize = resource.MustParse("1Gi")
		}},
	}

	for _, corner := range corners {
		t.Run(corner.name, func(t *testing.T) {
			ns := NewNamespace(t)
			policy := newPolicy(t, ns, "corner", corner.mutate)
			policy.Spec.Armed = true

			if err := Client().Create(ctx, policy); err != nil {
				// Not a failure of this test: the corner is outside the
				// accepted space, so there is no stored object to strand.
				t.Skipf("the schema does not accept this corner, so nothing can be stored at it: %v", err)
			}

			var stored trawlv1alpha1.CapturePolicy
			if err := Client().Get(ctx, client.ObjectKeyFromObject(policy), &stored); err != nil {
				t.Fatalf("reading back: %v", err)
			}
			stored.Spec.Armed = false
			if err := Client().Update(ctx, &stored); err != nil {
				t.Fatalf("a policy the API accepted cannot be disarmed: %v\n"+
					"An operator holding this object has no way to stop it capturing short of deleting it.", err)
			}
		})
	}
}

// dropTrigger builds a denied-flow trigger with a threshold.
func dropTrigger(count int32, window string) trawlv1alpha1.CapturePolicyTrigger {
	d, _ := time.ParseDuration(window)
	return trawlv1alpha1.CapturePolicyTrigger{
		Type: trawlv1alpha1.CaptureTriggerHubbleDrop,
		HubbleDrop: &trawlv1alpha1.HubbleDropTrigger{
			Reasons: []string{"POLICY_DENIED"},
			Threshold: &trawlv1alpha1.DropThreshold{
				Count:  count,
				Window: metav1.Duration{Duration: d},
			},
		},
	}
}

func TestUninstallingTheOperatorLeavesTheEvidenceBehind(t *testing.T) {
	// `make undeploy` removes the Deployments, the RBAC and the ServiceAccounts.
	// It must not remove captures, because the reason an installation holds
	// captures is that somebody may need them after the thing that collected
	// them is gone.
	//
	// Kubernetes garbage collection is the mechanism that would do it: an owner
	// reference from a CaptureJob to anything the uninstall deletes makes the
	// capture a dependent, and the collector removes dependents without asking.
	// US4 already decided the policy case deliberately - a policy-created
	// CaptureJob carries no owner reference, so deleting the rule does not
	// collect back what it collected - and this asserts the same property
	// against the API rather than against the engine that builds the object.
	ns := NewNamespace(t)
	ctx := context.Background()

	ref, snapshot, dedup := policyFields()
	job := manualCapture(ns, "survives-uninstall")
	job.Spec.RequestType = trawlv1alpha1.CaptureRequestPolicy
	job.Spec.TargetNode = ""
	job.Spec.PolicyRef = ref
	job.Spec.Trigger = snapshot
	job.Spec.DeduplicationKey = dedup

	if err := Client().Create(ctx, job); err != nil {
		t.Fatalf("creating a policy capture: %v", err)
	}

	var stored trawlv1alpha1.CaptureJob
	if err := Client().Get(ctx, client.ObjectKeyFromObject(job), &stored); err != nil {
		t.Fatalf("reading back: %v", err)
	}
	// The other half of the same property: nothing about the capture depends on
	// the policy still existing to be readable. The snapshot is what makes the
	// capture self-explaining after the rule is gone (FR-032).
	if stored.Spec.Trigger == nil {
		t.Error("the stored capture carries no trigger snapshot, so once its policy is deleted nothing " +
			"records why the capture was taken")
	}
	if stored.Spec.PolicyRef == nil || stored.Spec.PolicyRef.UID == "" {
		t.Error("the stored capture does not pin the policy UID, so a policy deleted and recreated under " +
			"the same name would be read as the one that made this capture")
	}
}

func TestUndeployingDoesNotTakeTheCustomResourceDefinitionsWithIt(t *testing.T) {
	// The uninstall half of T122, and the one that actually bites.
	//
	// Deleting a CustomResourceDefinition deletes every object of that kind.
	// So a `make undeploy` that renders config/default and pipes the whole
	// thing to `kubectl delete` does not remove the operator - it removes the
	// operator and every capture record the installation ever made: the trigger
	// snapshot that says why a capture was taken, the retention deadline, and
	// the artifact key that says where the packets are. The pcap survives in
	// the bucket, with nothing left in the cluster that knows it exists or what
	// it was collected for.
	//
	// It is the worst shape of failure this project guards against: quiet,
	// total, and indistinguishable at the terminal from a tidy uninstall.
	//
	// Removing the CRDs has to stay possible - `make uninstall` is exactly that
	// - but it has to be the deliberate act rather than the side effect.
	root := filepath.Join("..", "..")
	script := filepath.Join(root, "hack", "undeploy-manifests.sh")
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("%s is missing, so `make undeploy` renders config/default unfiltered and "+
			"cascade-deletes every stored capture: %v", script, err)
	}

	//nolint:gosec // G204: the path is derived from the repository root, not from input.
	out, err := exec.CommandContext(t.Context(), script).Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("running %s: %v: %s", script, err, exitErr.Stderr)
		}
		t.Fatalf("running %s: %v", script, err)
	}

	var crds, workloads int
	for _, doc := range strings.Split(string(out), "\n---\n") {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		var head struct {
			Kind string `json:"kind"`
		}
		if err := yaml.Unmarshal([]byte(doc), &head); err != nil {
			continue
		}
		switch head.Kind {
		case "CustomResourceDefinition":
			crds++
		case "Deployment", "ServiceAccount", "ClusterRole", "Role":
			workloads++
		}
	}

	if crds != 0 {
		t.Errorf("the undeploy manifest set still contains %d CustomResourceDefinitions; deleting them "+
			"cascade-deletes every CaptureJob, NetworkTap and CapturePolicy in the installation", crds)
	}
	// Without this the check passes on a script that emits nothing at all,
	// which would be an undeploy that removes nothing.
	if workloads == 0 {
		t.Error("the undeploy manifest set contains no Deployment, ServiceAccount or role; it would " +
			"leave the operator running")
	}
}
