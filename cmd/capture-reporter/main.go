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

// Command capture-reporter relays a capture runner's progress into the
// CaptureJob's status.
//
// It runs as a sidecar beside the runner (US3, T081). The runner holds
// CAP_NET_RAW and no API token; this process holds a token scoped by
// resourceNames to one CaptureJob's status subresource and no capture
// privilege. Splitting them is what keeps a compromise of the packet-
// handling process from becoming an API credential.
//
// Everything it writes comes from the records in --progress-dir, which the
// runner writes and internal/capture reads back bounded and sanitized.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/capture"
	"trawl.cloud/trawl/internal/capture/reporter"
	"trawl.cloud/trawl/internal/sanitize"
)

// version and commit are set at build time.
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	var (
		namespace   = flag.String("namespace", "", "CaptureJob namespace.")
		name        = flag.String("name", "", "CaptureJob name.")
		uid         = flag.String("uid", "", "CaptureJob UID; records for any other UID are ignored.")
		generation  = flag.Int64("generation", 0, "CaptureJob generation the runner Job was created for.")
		progressDir = flag.String("progress-dir", capture.DefaultProgressDir, "Directory the runner writes records to.")
		tokenDir    = flag.String("token-dir", "/var/run/secrets/trawl", "Directory holding the projected API token and CA.")
		interval    = flag.Duration("interval", reporter.DefaultInterval, "How often the progress directory is read.")
	)
	flag.Parse()

	logf := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "capture-reporter: "+format+"\n", args...)
	}
	logf("version=%s commit=%s", version, commit)

	if *namespace == "" || *name == "" || *uid == "" || *generation <= 0 {
		logf("--namespace, --name, --uid and --generation are required")
		os.Exit(2)
	}

	cfg, err := restConfig(*tokenDir)
	if err != nil {
		logf("%s", sanitize.Error(err))
		os.Exit(2)
	}
	scheme := runtime.NewScheme()
	utilruntime.Must(trawlv1alpha1.AddToScheme(scheme))
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		logf("building API client: %s", sanitize.Error(err))
		os.Exit(2)
	}

	// SIGTERM arrives when the runner container has exited and the pod is
	// being torn down. Run makes one final bounded read-and-apply on
	// cancellation, so a result record that landed just before is not lost.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	r := &reporter.Reporter{
		Client:        c,
		Namespace:     *namespace,
		Name:          *name,
		CaptureJobUID: *uid,
		Generation:    *generation,
		ProgressDir:   *progressDir,
		Interval:      *interval,
		Logf:          logf,
	}
	if err := r.Run(ctx); err != nil {
		logf("%s", sanitize.Error(err))
		os.Exit(1)
	}

	// The result has been applied. A native sidecar with restartPolicy
	// Always would be restarted if it exited now, so wait for the kubelet
	// to stop the pod once the runner has exited.
	<-ctx.Done()
}

// restConfig builds an API client configuration from the projected token,
// the same way the sensor does: the pod does not automount a token, so
// rest.InClusterConfig has nothing to read.
func restConfig(tokenDir string) (*rest.Config, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, sanitize.Errorf(
			"KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT are not set; this is not running in a cluster")
	}
	return &rest.Config{
		Host:            "https://" + net.JoinHostPort(host, port),
		BearerTokenFile: filepath.Join(tokenDir, "token"),
		TLSClientConfig: rest.TLSClientConfig{CAFile: filepath.Join(tokenDir, "ca.crt")},
	}, nil
}
