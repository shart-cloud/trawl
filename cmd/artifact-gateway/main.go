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

// Command artifact-gateway serves authorized downloads of capture artifacts.
//
// It is a separate binary from the controller manager for the reason ADR-0003
// gives: this is the one process a human's credential reaches, and it must not
// be the process that holds the audit ledger's credential. It has read-only
// access to the artifact bucket, no ledger access at all, and records every
// download through the manager's mTLS sink.
//
// It is deliberately not leader-elected. Nothing here is a singleton — every
// request is decided from live API server and object store state — so replicas
// are how the download path survives a node.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/audit"
	"trawl.cloud/trawl/internal/authz"
	"trawl.cloud/trawl/internal/config"
	"trawl.cloud/trawl/internal/gateway"
	"trawl.cloud/trawl/internal/sanitize"
	"trawl.cloud/trawl/internal/storage"
	"trawl.cloud/trawl/internal/telemetry"
	"trawl.cloud/trawl/internal/tlsutil"
)

// shutdownGrace bounds the wait for in-flight downloads when stopping. Only the
// redirect is served here — the bytes come from object storage — so every
// request is short.
const shutdownGrace = 10 * time.Second

func newScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(trawlv1alpha1.AddToScheme(s))
	return s
}

func main() {
	var (
		configPath = flag.String("config", "/etc/trawl/config.yaml", "Installation configuration path.")
		probeAddr  = flag.String("probe-addr", ":9110", "Metrics address, plaintext and in-cluster only.")
	)
	flag.Parse()

	//nolint:gosec // configPath is an operator-supplied flag on this process's own command line
	raw, err := os.ReadFile(*configPath)
	if err != nil {
		fatal("reading installation configuration", err)
	}
	cfg, err := config.Load(raw)
	if err != nil {
		fatal("invalid installation configuration", err)
	}

	metrics := telemetry.NewMetrics()
	registry := prometheus.NewRegistry()
	if err := metrics.Register(registry); err != nil {
		fatal("registering metrics", err)
	}

	restCfg, err := ctrl.GetConfig()
	if err != nil {
		fatal("locating the Kubernetes API", err)
	}
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		fatal("building the Kubernetes client", err)
	}
	kubeClient, err := client.New(restCfg, client.Options{Scheme: newScheme()})
	if err != nil {
		fatal("building the CaptureJob client", err)
	}

	reviewer, err := authz.NewKubernetesReviewer(clientset, cfg.Gateway.TokenAudience)
	if err != nil {
		fatal("configuring authorization", err)
	}

	// Read-only credentials for the artifact bucket, and none at all for the
	// ledger: this process must not be able to rewrite the history of what it
	// served.
	artifacts, err := storage.NewS3Store(cfg.Artifacts)
	if err != nil {
		fatal("connecting to artifact storage", err)
	}

	auditClient, err := audit.NewClient(audit.ClientOptions{
		Endpoint:   cfg.Gateway.AuditClient.Endpoint,
		ServerName: cfg.Gateway.AuditClient.ServerName,
		CAFile:     cfg.Gateway.AuditClient.CAFile,
		CertFile:   cfg.Gateway.AuditClient.CertFile,
		KeyFile:    cfg.Gateway.AuditClient.KeyFile,
	})
	if err != nil {
		fatal("configuring the audit client", err)
	}

	handler, err := gateway.New(gateway.Options{
		Reviewer:  reviewer,
		Jobs:      gateway.NewKubeJobs(kubeClient),
		Store:     artifacts,
		Presigner: artifacts,
		Audit:     auditClient,
		Metrics:   metrics,

		DownloadsPerMinute: cfg.Gateway.DownloadsPerMinute,
		DownloadBurst:      cfg.Gateway.DownloadBurst,
	})
	if err != nil {
		fatal("building the gateway", err)
	}

	reloader, err := tlsutil.NewCertReloader("artifact gateway", cfg.Gateway.CertFile, cfg.Gateway.KeyFile)
	if err != nil {
		fatal("loading the serving certificate", err)
	}

	ctx := ctrl.SetupSignalHandler()
	serveMetrics(*probeAddr, registry)

	server := &http.Server{
		Addr:    cfg.Gateway.ListenAddr,
		Handler: handler.Routes(),
		// The client presents a bearer token before anything else happens, so
		// a slow-loris on this listener holds a connection open against the one
		// process that serves packet data.
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			// TLS 1.3 only. Both ends are ours: the supported CLI and a
			// certificate Trawl issues, so there is no legacy client to
			// accommodate.
			MinVersion:     tls.VersionTLS13,
			GetCertificate: reloader.GetCertificate,
		},
	}

	go func() {
		<-ctx.Done()
		// WithoutCancel rather than Background: the shutdown must outlive the
		// cancellation that triggered it, but should keep the parent's values.
		stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
		defer cancel()
		_ = server.Shutdown(stopCtx)
	}()

	// Certificate and key come from TLSConfig.GetCertificate, so they are
	// re-read on renewal rather than pinned at startup.
	if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatal("serving the artifact API", err)
	}
}

// serveMetrics exposes Prometheus metrics on a plaintext in-cluster port.
//
// Liveness and readiness are deliberately not here: the contract puts them on
// the API itself, where they answer "can this serve a download" rather than
// "is a second listener up".
func serveMetrics(addr string, registry *prometheus.Registry) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))

	server := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "metrics server: %v\n", sanitize.Error(err))
		}
	}()
}

func fatal(what string, err error) {
	fmt.Fprintf(os.Stderr, "artifact-gateway: %s: %v\n", what, sanitize.Error(err))
	os.Exit(1)
}
