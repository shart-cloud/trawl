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

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/yaml"

	"trawl.cloud/trawl/internal/controller"
	"trawl.cloud/trawl/internal/events/loki"
)

// T116. envtest runs the API server with --authorization-mode=RBAC, so the Role
// in config/rbac can be exercised rather than read. That matters more here than
// for any other component: the worker is the one thing in Trawl that creates
// evidence without a human asking, and a Role that is merely valid is the
// failure this project keeps producing - a manifest that looks right, applies
// cleanly, and denies the one call the code actually makes.
//
// The positive tests run the real engine and status tracker through an
// impersonating client, so they assert the grants match what the code does
// rather than what the manifest's comments claim. The negative tests assert the
// limits those comments claim: no editing a policy's spec, no altering or
// deleting a capture once created, no reading Secrets.

const workerIdentity = "system:serviceaccount:trawl-system:event-worker"

// grantWorkerRole applies config/rbac/event-worker-role.yaml into ns and
// returns a client acting as the worker's service account.
func grantWorkerRole(t *testing.T, ns string) client.Client {
	t.Helper()
	ctx := context.Background()

	raw, err := os.ReadFile(filepath.Join("..", "..", "config", "rbac", "event-worker-role.yaml"))
	if err != nil {
		t.Fatalf("reading the event worker role: %v", err)
	}

	// The Role is taken from the manifest verbatim. Restating its rules here
	// would test this file against itself and pass however wrong the manifest
	// was.
	var role *rbacv1.Role
	for doc := range strings.SplitSeq(string(raw), "\n---") {
		if !strings.Contains(doc, "kind: Role\n") {
			continue
		}
		var r rbacv1.Role
		if err := yaml.Unmarshal([]byte(doc), &r); err != nil {
			t.Fatalf("decoding the event worker Role: %v", err)
		}
		role = &r
		break
	}
	if role == nil {
		t.Fatal("config/rbac/event-worker-role.yaml contains no Role")
	}

	role.ObjectMeta = metav1.ObjectMeta{Namespace: ns, Name: "event-worker"}
	if err := Client().Create(ctx, role); err != nil {
		t.Fatalf("applying the event worker Role: %v", err)
	}
	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "event-worker"},
		Subjects:   []rbacv1.Subject{{Kind: "User", Name: workerIdentity}},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "event-worker"},
	}
	if err := Client().Create(ctx, binding); err != nil {
		t.Fatalf("binding the event worker Role: %v", err)
	}

	cfg := rest.CopyConfig(RESTConfig())
	cfg.Impersonate = rest.ImpersonationConfig{UserName: workerIdentity}
	c, err := client.New(cfg, client.Options{Scheme: Scheme()})
	if err != nil {
		t.Fatalf("creating the impersonating client: %v", err)
	}
	return c
}

func TestTheWorkersRoleAllowsEverythingTheEngineDoes(t *testing.T) {
	// The engine, unmodified, against an API server that will refuse anything
	// the Role does not grant. Each call it makes - listing policies, reading
	// the tap, looking for an existing capture, counting the hour's captures,
	// creating the job - has to be covered, and a missing verb surfaces here as
	// the forbidden error it would be in the cluster.
	f := newWorkerFixture(t)
	f.armPolicy(t, "ssh-scan")
	f.engine.Client = grantWorkerRole(t, f.namespace)

	results := f.evaluate(t, f.alertOn("1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"))

	if len(results) != 1 {
		t.Fatalf("got %d results, want one: %+v", len(results), results)
	}
	if results[0].Outcome != controller.OutcomeCreated {
		t.Fatalf("outcome = %s (%v), want Created - the Role refused a call the engine makes",
			results[0].Outcome, results[0].Err)
	}
	if jobs := f.captures(t); len(jobs) != 1 {
		t.Errorf("got %d captures, want 1", len(jobs))
	}
}

func TestTheWorkersRoleAllowsTheStatusWriteAndTheCursor(t *testing.T) {
	// The other two things the worker writes. Both are easy to leave out of a
	// Role and neither fails loudly: an unwritable status leaves policies
	// looking un-evaluated, and an unwritable cursor makes every restart
	// re-read the whole lookback.
	f := newWorkerFixture(t)
	f.armPolicy(t, "ssh-scan")
	workerClient := grantWorkerRole(t, f.namespace)
	f.engine.Client = workerClient
	f.tracker.Client = workerClient
	ctx := context.Background()

	for _, r := range f.evaluate(t, f.alertOn("2a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d")) {
		f.tracker.Record(r)
	}
	if err := f.tracker.Flush(ctx, healthySources()); err != nil {
		t.Fatalf("the Role refused the status write: %v", err)
	}
	if got := f.readPolicy(t, "ssh-scan").Status.Decisions.Matched; got != 1 {
		t.Errorf("matched = %d, want 1", got)
	}

	store := &loki.ConfigMapStore{Client: workerClient, Namespace: f.namespace}
	var cursor loki.Cursor
	cursor.Advance(f.now, "some-alert")
	if err := store.Save(ctx, cursor); err != nil {
		t.Fatalf("the Role refused creating the alert cursor: %v", err)
	}
	// And again, which is the update path rather than the create path.
	cursor.Advance(f.now, "another-alert")
	if err := store.Save(ctx, cursor); err != nil {
		t.Fatalf("the Role refused updating the alert cursor: %v", err)
	}
}

func TestTheWorkerCannotRewriteTheRuleItIsActingUnder(t *testing.T) {
	// The grant is on capturepolicies/status, not capturepolicies. A worker
	// that could arm a policy, widen its trigger or raise its hourly limit
	// would be able to author the evidence it then collects.
	f := newWorkerFixture(t)
	policy := f.armPolicy(t, "ssh-scan")
	workerClient := grantWorkerRole(t, f.namespace)

	policy.Spec.RateLimit.MaxCapturesPerHour = 100
	err := workerClient.Update(context.Background(), policy)

	if !apierrors.IsForbidden(err) {
		t.Errorf("updating a policy spec returned %v, want a forbidden error", err)
	}
}

func TestTheWorkerCannotAlterOrRemoveTheEvidenceItCollected(t *testing.T) {
	// A capture is evidence. The worker's job ends when it has asked for one;
	// everything after that belongs to the capture controller. Without this
	// limit a compromised worker could delete what it had collected.
	f := newWorkerFixture(t)
	f.armPolicy(t, "ssh-scan")
	workerClient := grantWorkerRole(t, f.namespace)
	f.engine.Client = workerClient
	ctx := context.Background()

	f.evaluate(t, f.alertOn("3a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"))
	jobs := f.captures(t)
	if len(jobs) != 1 {
		t.Fatalf("got %d captures, want 1", len(jobs))
	}

	job := jobs[0]
	job.Spec.Retention = "1h"
	if err := workerClient.Update(ctx, &job); !apierrors.IsForbidden(err) {
		t.Errorf("updating a capture returned %v, want a forbidden error", err)
	}
	if err := workerClient.Delete(ctx, &jobs[0]); !apierrors.IsForbidden(err) {
		t.Errorf("deleting a capture returned %v, want a forbidden error", err)
	}
}

func TestTheWorkerCannotReadSecretsOrOtherConfiguration(t *testing.T) {
	// Its own credentials arrive as a mounted volume, so it needs no Secret
	// access at all - and the ConfigMap grant is named, because an
	// unrestricted one would include trawl-config and every other
	// configuration object in the namespace.
	f := newWorkerFixture(t)
	workerClient := grantWorkerRole(t, f.namespace)
	ctx := context.Background()

	var secret corev1.Secret
	err := workerClient.Get(ctx, types.NamespacedName{Namespace: f.namespace, Name: "any-secret"}, &secret)
	if !apierrors.IsForbidden(err) {
		t.Errorf("reading a Secret returned %v, want a forbidden error", err)
	}

	var cm corev1.ConfigMap
	err = workerClient.Get(ctx, types.NamespacedName{Namespace: f.namespace, Name: "trawl-config"}, &cm)
	if !apierrors.IsForbidden(err) {
		t.Errorf("reading trawl-config returned %v, want a forbidden error", err)
	}
}

// The worker does not use a direct client. It uses the manager's, which reads
// through a cache, and the difference is not a detail: a cached read starts an
// informer that LISTs and WATCHes the whole type in the namespace, so a Role
// scoped to one object by name is refused at the reflector rather than at the
// call. The reflector retries forever, the informer never syncs, and the Get
// blocks - no error, no log, just a poll loop that never reaches its first tick.
//
// Every test above builds a direct client and would pass with that wiring
// broken, which is how it reached a code review once already. This one builds
// the client the way cmd/event-worker does.
func TestTheWorkersCursorIsReadableThroughTheClientTheWorkerActuallyUses(t *testing.T) {
	ns := NewNamespace(t)
	grantWorkerRole(t, ns)

	cfg := rest.CopyConfig(RESTConfig())
	cfg.Impersonate = rest.ImpersonationConfig{UserName: workerIdentity}

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 Scheme(),
		Cache:                  cache.Options{DefaultNamespaces: map[string]cache.Config{ns: {}}},
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		// The line under test. Without it the cursor read below never returns.
		Client: client.Options{
			Cache: &client.CacheOptions{DisableFor: []client.Object{&corev1.ConfigMap{}}},
		},
	})
	if err != nil {
		t.Fatalf("creating the manager: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		if err := mgr.Start(ctx); err != nil {
			t.Errorf("running the manager: %v", err)
		}
	}()
	if !mgr.GetCache().WaitForCacheSync(ctx) {
		t.Fatal("the manager's cache did not sync")
	}

	store := &loki.ConfigMapStore{Client: mgr.GetClient(), Namespace: ns}

	// Bounded, because the failure this catches is a hang rather than an error.
	// An unbounded call would take the whole package's timeout to report a
	// defect that is decided in milliseconds when the wiring is right.
	done := make(chan error, 1)
	go func() {
		var cursor loki.Cursor
		cursor.Advance(time.Now(), "an-alert")
		if err := store.Save(ctx, cursor); err != nil {
			done <- err
			return
		}
		_, loadErr := store.Load(ctx)
		done <- loadErr
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the cursor could not be read through the worker's client: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("reading the cursor through the worker's client blocked; a cached ConfigMap read " +
			"needs list and watch on every ConfigMap in the namespace, which the worker must not have")
	}
}
