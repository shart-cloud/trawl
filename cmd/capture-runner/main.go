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

// Command capture-runner will collect one bounded packet capture (US3, T080).
//
// It is a stub. The installation configuration requires a digest-pinned
// reference for every image the operator can render, including this one, and
// validation runs before anything looks at whether captures are in use. So
// installing US1 and US2 - passive monitoring and investigation, neither of
// which captures a packet - requires an image for a component that does not
// exist yet.
//
// The alternative was to name some other image's digest in the configuration
// and rely on nothing dereferencing it. That would put a reference in a real
// cluster's config that says one thing and points at another, which is the
// same shape as the defects that made the analyzers silently unable to start.
// A stub that resolves, runs, and refuses to pretend it captured anything is
// honest about what is installed.
//
// It exits non-zero on every invocation. A CaptureJob cannot reach it before
// US3 renders one; if the wiring is ever wrong, this fails loudly rather than
// reporting a capture that never happened - the one outcome an evidence
// collection tool must never produce.
package main

import (
	"fmt"
	"os"
)

// version and commit are set at build time and reported here so an operator
// inspecting a running cluster can tell which build the stub came from.
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	fmt.Fprintf(os.Stderr,
		"capture-runner %s (%s) is not implemented: bounded packet capture arrives with US3 (T080).\n"+
			"This image exists so an installation that uses only passive monitoring and\n"+
			"investigation can satisfy the digest-pinned image configuration without naming\n"+
			"an image that does something else. No capture was started and no artifact was\n"+
			"written.\n",
		version, commit)

	// Distinct from the 1 a real runner uses for a capture that failed, and
	// from the 2 the analyzer entrypoints use for a bad argument, so "not
	// built yet" is never mistaken for "tried and failed".
	os.Exit(3)
}
