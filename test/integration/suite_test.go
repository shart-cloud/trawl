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

// Package integration runs Trawl's control-plane tests against a real
// Kubernetes API server via envtest.
//
// Constitution V requires reconciliation to be exercised across an actual
// control-plane boundary rather than a fake client. Defaulting, structural
// validation, CEL rules, status subresources, and optimistic concurrency are
// apiserver behaviors — a fake client implements none of them, so a reconciler
// that passes against one can still be wrong in a cluster.
package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var (
	testEnv   *envtest.Environment
	restCfg   *rest.Config
	k8sClient client.Client
	scheme    = runtime.NewScheme()
)

// TestMain starts one apiserver for the whole package. Starting one per test
// would dominate the runtime; isolation comes from a fresh namespace per test
// instead (see NewNamespace).
func TestMain(m *testing.M) {
	logf.SetLogger(zap.New(zap.UseDevMode(true), zap.WriteTo(os.Stderr)))

	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		fmt.Fprintf(os.Stderr, "adding client-go scheme: %v\n", err)
		os.Exit(1)
	}
	// Trawl API types are registered here as api/v1alpha1 lands in US1.

	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: false,
	}

	var err error
	restCfg, err = testEnv.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "starting envtest: %v\n", err)
		fmt.Fprintln(os.Stderr, "hint: run `make setup-envtest` to install control-plane binaries")
		os.Exit(1)
	}

	k8sClient, err = client.New(restCfg, client.Options{Scheme: scheme})
	if err != nil {
		fmt.Fprintf(os.Stderr, "creating client: %v\n", err)
		_ = testEnv.Stop()
		os.Exit(1)
	}

	code := m.Run()

	if err := testEnv.Stop(); err != nil {
		fmt.Fprintf(os.Stderr, "stopping envtest: %v\n", err)
	}
	os.Exit(code)
}

// NewNamespace creates an isolated namespace for one test and deletes it on
// cleanup.
//
// Per-test namespaces are what let these tests run in parallel without one
// test's NetworkTap being observed by another's reconciler.
func NewNamespace(t *testing.T) string {
	t.Helper()

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "trawl-test-"},
	}
	ctx := t.Context()
	if err := k8sClient.Create(ctx, ns); err != nil {
		t.Fatalf("creating test namespace: %v", err)
	}
	t.Cleanup(func() {
		// A detached context: t.Context() is already cancelled during cleanup.
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := k8sClient.Delete(cleanupCtx, ns); err != nil {
			t.Logf("deleting test namespace %s: %v", ns.Name, err)
		}
	})
	return ns.Name
}

// RESTConfig exposes the envtest connection for tests that need a raw client.
func RESTConfig() *rest.Config { return restCfg }

// Client exposes the package-level controller-runtime client.
func Client() client.Client { return k8sClient }

// Scheme exposes the registered scheme.
func Scheme() *runtime.Scheme { return scheme }
