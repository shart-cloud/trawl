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

package main

import (
	"crypto/tls"
	"flag"
	"net/http"
	"os"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/admission"
	"trawl.cloud/trawl/internal/audit"
	"trawl.cloud/trawl/internal/config"
	"trawl.cloud/trawl/internal/controller"
	"trawl.cloud/trawl/internal/sanitize"
	"trawl.cloud/trawl/internal/storage"
	"trawl.cloud/trawl/internal/telemetry"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	registerSchemes(scheme)
}

// registerSchemes adds every group the manager serves.
//
// Separate from init so a test can assert the result. Trawl's own group was
// missing here: the scaffold registers client-go's types and nothing else, and
// nothing needed NetworkTap until the controller and webhook were wired in. The
// manager then failed at startup with "no kind is registered for the type
// v1alpha1.NetworkTap" - a runtime error for something knowable at build time.
func registerSchemes(s *runtime.Scheme) {
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(trawlv1alpha1.AddToScheme(s))

	// +kubebuilder:scaffold:scheme
}

// nolint:gocyclo
func main() {
	var metricsAddr string
	var metricsCertPath, metricsCertName, metricsCertKey string
	var webhookCertPath, webhookCertName, webhookCertKey string
	var enableLeaderElection bool
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool
	var tlsOpts []func(*tls.Config)
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	var configPath string
	flag.StringVar(&configPath, "config", "/etc/trawl/config.yaml",
		"Path to the Trawl installation configuration file.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&webhookCertPath, "webhook-cert-path", "", "The directory that contains the webhook certificate.")
	flag.StringVar(&webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	flag.StringVar(&webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	flag.StringVar(&metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	flag.StringVar(&metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("Disabling HTTP/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	// Initial webhook TLS options
	webhookTLSOpts := tlsOpts
	webhookServerOptions := webhook.Options{
		TLSOpts: webhookTLSOpts,
	}

	if len(webhookCertPath) > 0 {
		setupLog.Info("Initializing webhook certificate watcher using provided certificates",
			"webhook-cert-path", webhookCertPath, "webhook-cert-name", webhookCertName, "webhook-cert-key", webhookCertKey)

		webhookServerOptions.CertDir = webhookCertPath
		webhookServerOptions.CertName = webhookCertName
		webhookServerOptions.KeyName = webhookCertKey
	}

	webhookServer := webhook.NewServer(webhookServerOptions)

	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
	// More info:
	// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.24.1/pkg/metrics/server
	// - https://book.kubebuilder.io/reference/metrics.html
	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		TLSOpts:       tlsOpts,
	}

	if secureMetrics {
		// FilterProvider is used to protect the metrics endpoint with authn/authz.
		// These configurations ensure that only authorized users and service accounts
		// can access the metrics endpoint. The RBAC are configured in 'config/rbac/kustomization.yaml'. More info:
		// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.24.1/pkg/metrics/filters#WithAuthenticationAndAuthorization
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	// If the certificate is not specified, controller-runtime will automatically
	// generate self-signed certificates for the metrics server. While convenient for development and testing,
	// this setup is not recommended for production.
	//
	// TODO(user): If you enable certManager, uncomment the following lines:
	// - [METRICS-WITH-CERTS] at config/default/kustomization.yaml to generate and use certificates
	// managed by cert-manager for the metrics server.
	// - [PROMETHEUS-WITH-CERTS] at config/prometheus/kustomization.yaml for TLS certification.
	if len(metricsCertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", metricsCertPath, "metrics-cert-name", metricsCertName, "metrics-cert-key", metricsCertKey)

		metricsServerOptions.CertDir = metricsCertPath
		metricsServerOptions.CertName = metricsCertName
		metricsServerOptions.KeyName = metricsCertKey
	}

	// Installation configuration is loaded before the manager starts. Storage
	// endpoints, retention bounds, and image digests are security-relevant, so
	// an invalid or incomplete install must refuse to start rather than run
	// with defaults.
	// gosec G304: configPath is an operator-supplied flag on the manager's own
	// command line, not caller input.
	rawConfig, err := os.ReadFile(configPath) //nolint:gosec
	if err != nil {
		setupLog.Error(sanitize.Error(err), "Failed to read installation configuration")
		os.Exit(1)
	}
	installCfg, err := config.Load(rawConfig)
	if err != nil {
		setupLog.Error(sanitize.Error(err), "Invalid installation configuration")
		os.Exit(1)
	}

	// Trawl's own metric set, registered on the controller-runtime registry so
	// it is served by the same authenticated metrics endpoint.
	trawlMetrics := telemetry.NewMetrics()
	if err := trawlMetrics.Register(metrics.Registry); err != nil {
		setupLog.Error(sanitize.Error(err), "Failed to register Trawl metrics")
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "48b4eaf3.trawl.cloud",
		// The cache is restricted to the configured system namespace. Trawl's
		// CRDs are cluster-scoped in discovery, but reconciling anywhere else
		// would let a namespace-scoped creator elsewhere obtain privileged
		// workloads (FR-001). Restricting the cache means the manager cannot
		// even observe those objects.
		Cache: cache.Options{
			DefaultNamespaces: map[string]cache.Config{
				installCfg.SystemNamespace: {},
			},
		},
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "Failed to start manager")
		os.Exit(1)
	}

	// +kubebuilder:scaffold:builder

	// The audit ledger is addressed with its own bucket and credentials,
	// separate from the artifact store (ADR-0003).
	auditStore, err := storage.NewS3Store(installCfg.AuditLedger)
	if err != nil {
		setupLog.Error(sanitize.Error(err), "Failed to connect to the audit ledger")
		os.Exit(1)
	}
	auditSink, err := audit.NewSink(audit.Options{
		Store:     auditStore,
		Prefix:    audit.DefaultPrefix,
		Retention: installCfg.AuditRetention.Duration(),
	})
	if err != nil {
		setupLog.Error(sanitize.Error(err), "Failed to create the audit sink")
		os.Exit(1)
	}

	// Nothing above this point serves a request. The manager started, took
	// leadership and reported healthy while reconciling no taps at all, and
	// because both webhook configurations are failurePolicy: Fail, every
	// NetworkTap create was rejected by an admission server that was never
	// listening. The reconciler and the webhook were both implemented and unit
	// tested; only this registration was missing.
	if err := (&controller.NetworkTapReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Config:   installCfg,
		Renderer: &controller.WorkloadRenderer{Config: installCfg},
		Metrics:  trawlMetrics,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to set up the NetworkTap controller")
		os.Exit(1)
	}

	// The gate holds the audit sink because FR-036 makes a durable audit commit
	// a precondition of admission, not a side effect of it.
	if err := (&admission.NetworkTapWebhook{
		Gate: &admission.Gate{
			SystemNamespace: installCfg.SystemNamespace,
			Audit:           auditSink,
			Metrics:         trawlMetrics,
		},
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to set up the NetworkTap webhook")
		os.Exit(1)
	}

	// The ledger is durable but not searchable. This runnable is what forwards
	// committed records to stdout, where Alloy collects them into Loki
	// (config/alloy/trawl-audit.alloy). Without it the pipeline is well-formed
	// and collects nothing, so an audit query returns an empty result rather
	// than an error - which is how it went unnoticed that the producer was
	// never wired at all.
	auditReplayer, err := audit.NewReplayer(audit.ReplayOptions{
		Sink: auditSink,
		Cursor: &audit.ConfigMapCursor{
			Client:    mgr.GetClient(),
			Namespace: installCfg.SystemNamespace,
		},
		// Stdout, while the manager's logs go to stderr. Both are collected
		// from the same container, which is why the audit pipeline drops every
		// line that does not carry the audit schema version.
		Out:     os.Stdout,
		Metrics: trawlMetrics,
	})
	if err != nil {
		setupLog.Error(err, "Failed to create the audit replayer")
		os.Exit(1)
	}
	if err := mgr.Add(auditReplayer); err != nil {
		setupLog.Error(err, "Failed to set up audit replay")
		os.Exit(1)
	}

	// healthz stays process liveness only. If it consulted the ledger, a MinIO
	// outage would restart otherwise-healthy pods and turn a storage blip into
	// a monitoring outage.
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up health check")
		os.Exit(1)
	}
	// readyz does consult it: without a committable ledger every user mutation
	// fails closed (FR-036), so reporting ready would be a lie.
	if err := mgr.AddReadyzCheck("audit-ledger", func(req *http.Request) error {
		_, _, err := auditSink.Backlog(req.Context(), "")
		return sanitize.Error(err)
	}); err != nil {
		setupLog.Error(err, "Failed to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("Trawl configuration loaded",
		"systemNamespace", installCfg.SystemNamespace,
		"cluster", installCfg.ClusterID,
		"auditRetention", installCfg.AuditRetention.Duration().String(),
		"captureRetentionCeiling", installCfg.CaptureRetentionCeiling.Duration().String())

	setupLog.Info("Starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "Failed to run manager")
		os.Exit(1)
	}
}
