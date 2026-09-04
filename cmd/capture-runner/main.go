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

// Command capture-runner collects one bounded packet capture (US3, T080).
//
// It is the one privileged data-plane binary: it runs dumpcap with
// CAP_NET_RAW on the node's interface, verifies and uploads the result, and
// exits with a code that names the outcome (internal/capture.ExitCodeFor).
// It holds no Kubernetes API credentials; progress reaches the CaptureJob
// through records in --progress-dir that the reporter sidecar relays.
//
// The spec is passed as flags rather than read from the API so that the
// runner cannot be pointed at a different object than the one the controller
// scheduled, and so a compromised runner learns nothing about the cluster.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"k8s.io/apimachinery/pkg/api/resource"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/capture"
	"trawl.cloud/trawl/internal/config"
	"trawl.cloud/trawl/internal/sanitize"
	"trawl.cloud/trawl/internal/storage"
)

// version and commit are set at build time and recorded in the manifest.
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	os.Exit(run())
}

func run() int {
	var (
		namespace   = flag.String("namespace", "", "CaptureJob namespace.")
		name        = flag.String("name", "", "CaptureJob name.")
		uid         = flag.String("uid", "", "CaptureJob UID; keys the artifact and the progress records.")
		iface       = flag.String("interface", "", "Interface to capture on, as resolved from the tap.")
		filter      = flag.String("filter", "", "BPF filter expression; empty captures everything.")
		duration    = flag.String("duration", "", "Capture duration bound, for example 60s.")
		maxSize     = flag.String("max-size", "", "Capture size bound as a Kubernetes quantity, for example 64Mi.")
		snaplen     = flag.Int("snaplen", 0, "Bytes captured per packet; 0 is dumpcap's default.")
		workDir     = flag.String("work-dir", "/var/lib/trawl/capture", "Writable directory for the capture file.")
		progressDir = flag.String("progress-dir", capture.DefaultProgressDir, "Directory to write progress records to.")
		dumpcap     = flag.String("dumpcap", "/usr/bin/dumpcap", "dumpcap executable.")
		endpoint    = flag.String("artifact-endpoint", "", "Object store endpoint, host:port.")
		bucket      = flag.String("artifact-bucket", "", "Object store bucket for artifacts.")
		region      = flag.String("artifact-region", "", "Object store region, if the endpoint needs one.")
		useTLS      = flag.Bool("artifact-tls", true, "Use TLS to the object store.")
		credsDir    = flag.String("artifact-credentials-dir", "/var/run/secrets/trawl-artifacts",
			"Directory holding accessKeyID and secretAccessKey.")
	)
	flag.Parse()

	logf := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "capture-runner: "+format+"\n", args...)
	}
	logf("version=%s commit=%s", version, commit)

	if *namespace == "" || *name == "" || *uid == "" || *iface == "" || *endpoint == "" || *bucket == "" {
		logf("--namespace, --name, --uid, --interface, --artifact-endpoint and --artifact-bucket are required")
		return capture.ExitInvalidBounds
	}
	size, err := resource.ParseQuantity(*maxSize)
	if err != nil {
		logf("--max-size is not a quantity")
		return capture.ExitInvalidBounds
	}
	spec := trawlv1alpha1.CaptureJobSpec{
		Filter:   *filter,
		Duration: *duration,
		MaxSize:  size,
		Snaplen:  int32(*snaplen), //nolint:gosec // ParseBounds rejects anything outside [64, 262144].
	}

	// The records directory is written before anything else is attempted
	// so that even a credential failure leaves a result record for the
	// reporter to relay.
	records := &capture.RecordWriter{Dir: *progressDir, CaptureJobUID: *uid, RunnerInstance: runnerInstance()}

	store, err := storage.NewS3Store(config.BucketConfig{
		Endpoint: *endpoint, Bucket: *bucket, Region: *region, CredentialsPath: *credsDir, UseTLS: *useTLS,
	})
	if err != nil {
		logf("artifact store: %s", sanitize.Error(err))
		code := int32(capture.ExitInternalError)
		_ = records.Write(capture.RecordResult, capture.Fields{
			Outcome: trawlv1alpha1.RunnerOutcomeFailed, Reason: trawlv1alpha1.FailureInternalError,
			ExitCode: &code, Message: "the artifact store could not be configured",
		})
		return int(code)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	r := &capture.Runner{
		Spec:           spec,
		CaptureJobUID:  *uid,
		Namespace:      *namespace,
		Name:           *name,
		Interface:      *iface,
		WorkDir:        *workDir,
		Records:        records,
		Uploader:       store,
		DumpcapCommand: []string{*dumpcap},
		DumpcapVersion: dumpcapVersion(ctx, *dumpcap),
		RunnerVersion:  version + "+" + commit,
		Logf:           logf,
	}
	res := r.Run(ctx)
	logf("outcome=%s reason=%s stop=%s packets=%d bytes=%d exit=%d",
		res.Outcome, res.Reason, res.StopReason, res.PacketCount, res.SizeBytes, res.ExitCode)
	return int(res.ExitCode)
}

// runnerInstance identifies this process in the records so a reporter can
// tell a retried runner's records from the first attempt's. The pod name
// is what Kubernetes exposes; the hostname is the pod name in a pod.
func runnerInstance() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "unknown"
}

// dumpcapVersion is recorded in the manifest. It is informational: a
// failure to read it does not stop the capture.
func dumpcapVersion(ctx context.Context, path string) string {
	v, err := capture.DumpcapVersion(ctx, path)
	if err != nil {
		return "unknown"
	}
	return v
}
