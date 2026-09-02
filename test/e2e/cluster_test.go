//go:build investigation || acceptance

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

// Helpers shared by the suites that run against a deployed Trawl.
//
// Both tagged suites talk to the same cluster the same way, and neither builds
// without the other's tag, so a helper defined in one file is invisible to the
// other. This file carries both tags rather than either suite carrying a second
// copy - two copies of "how we call kubectl" is how the two suites start
// disagreeing about what a failure looks like.
package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"trawl.cloud/trawl/test/integration/harness"
)

// kubectl runs a kubectl command, discarding its output.
func kubectl(args ...string) error {
	_, err := kubectlOut(args...)
	return err
}

// kubectlOut runs a kubectl command and returns its combined output.
//
// #nosec G204 -- callers pass constants and this run's identifier; nothing
// reaches the command line from the environment or from observed traffic.
func kubectlOut(args ...string) (string, error) {
	out, err := exec.Command("kubectl", args...).CombinedOutput()
	return string(out), err
}

// envOr reads an environment variable with a fallback.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// portForwardLoki opens a tunnel to the cluster's Loki for the whole run.
//
// The forward is deliberately not torn down per test: every spec sharing it
// runs in one binary, and Go gives a package-level fixture no cleanup hook. The
// process dies with the test binary.
func portForwardLoki() (string, error) {
	const localPort = 31000
	// #nosec G204 -- every argument is a constant of this file; nothing here
	// comes from the environment or from evidence.
	cmd := exec.Command("kubectl", "port-forward", "-n", "monitoring",
		"svc/loki", fmt.Sprintf("%d:3100", localPort))
	cmd.Stdout, cmd.Stderr = nil, nil
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("starting kubectl port-forward: %w", err)
	}

	url := fmt.Sprintf("http://127.0.0.1:%d", localPort)
	loki := harness.AttachLoki(url)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		now := time.Now()
		if _, err := loki.Query(context.Background(), `{service_name="trawl-observation"}`,
			now.Add(-time.Minute), now); err == nil {
			return url, nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	return "", fmt.Errorf("Loki did not answer on %s within 30s", url)
}
