package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
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
func publishStatus(ctx context.Context, r *sensor.StatusReporter, namespace, name string) error {
	scheme := runtime.NewScheme()
	utilruntime.Must(trawlv1alpha1.AddToScheme(scheme))

	cfg, err := ctrl.GetConfig()
	if err != nil {
		return sanitize.Errorf("loading in-cluster configuration: %v", err)
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
