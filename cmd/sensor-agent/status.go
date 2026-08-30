package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/sanitize"
	"trawl.cloud/trawl/internal/sensor"
)

// statusInterval is how often the sensor republishes its target status.
//
// Short enough that an operator watching a tap sees a stalled analyzer within a
// reasonable time, long enough that a large DaemonSet does not turn status
// reporting into API load. The reporter carries its own timestamps, so a
// consumer can tell a stale report from a current one regardless.
const statusInterval = 30 * time.Second

// fieldOwner scopes server-side apply to this sensor.
//
// status.targets is a map list keyed by nodeName, so each sensor owns its own
// entry and concurrent reporters merge rather than overwrite. A shared owner
// would make the last writer delete every other node's entry.
const fieldOwner = client.FieldOwner("trawl-sensor")

// publishStatus reports this sensor's observed state to its NetworkTap until
// the context ends.
//
// Nothing did this. StatusReporter built a TargetStatus and no caller ever sent
// it, so a tap reported "no sensor has reported yet" indefinitely while the
// sensor beside it was reading records normally. The RBAC for this - scoped by
// resourceNames to the one tap - was already rendered by the controller and
// bound to the sensor's ServiceAccount.
func publishStatus(ctx context.Context, r *sensor.StatusReporter, namespace, name, tokenDir string) error {
	scheme := runtime.NewScheme()
	utilruntime.Must(trawlv1alpha1.AddToScheme(scheme))

	cfg, err := restConfig(tokenDir)
	if err != nil {
		return err
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return sanitize.Errorf("building API client: %v", err)
	}

	ticker := time.NewTicker(statusInterval)
	defer ticker.Stop()

	for {
		if err := applyStatus(ctx, c, r, namespace, name); err != nil {
			// A failed report is not a reason to stop observing. The sensor's
			// job is to produce records; status is how it describes itself,
			// and losing the description must not cost the observations.
			fmt.Fprintf(os.Stderr, "reporting tap status: %v\n", sanitize.Error(err))
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// restConfig builds an API client configuration from the sensor's own projected
// token.
//
// rest.InClusterConfig, which ctrl.GetConfig falls back to, reads the token and
// CA from /var/run/secrets/kubernetes.io/serviceaccount. The sensor pod sets
// automountServiceAccountToken: false and projects a short-lived token
// elsewhere on purpose, so that directory does not exist and the client failed
// with "no configuration has been provided" - correct behaviour by a helper
// asked the wrong question.
//
// BearerTokenFile rather than a read token: the projection is short-lived and
// rotated in place, and a token read once would stop working part-way through
// the sensor's life.
func restConfig(tokenDir string) (*rest.Config, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, sanitize.Errorf(
			"KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT are not set; this is not running in a cluster")
	}

	return &rest.Config{
		Host:            "https://" + net.JoinHostPort(host, port),
		BearerTokenFile: filepath.Join(tokenDir, "token"),
		TLSClientConfig: rest.TLSClientConfig{
			CAFile: filepath.Join(tokenDir, "ca.crt"),
		},
	}, nil
}

func applyStatus(ctx context.Context, c client.Client, r *sensor.StatusReporter, namespace, name string) error {
	target, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&struct {
		Targets []trawlv1alpha1.TargetStatus `json:"targets"`
	}{Targets: []trawlv1alpha1.TargetStatus{r.Build()}})
	if err != nil {
		return sanitize.Errorf("encoding target status: %v", err)
	}

	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": trawlv1alpha1.GroupVersion.String(),
		"kind":       "NetworkTap",
		"metadata": map[string]any{
			"namespace": namespace,
			"name":      name,
		},
		"status": target,
	}}

	// Apply rather than update: the sensor sends only its own target entry and
	// must not read, merge and write back a list that other sensors are editing
	// at the same time.
	return c.Status().Apply(ctx, client.ApplyConfigurationFromUnstructured(u),
		fieldOwner, client.ForceOwnership)
}
