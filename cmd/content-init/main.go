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

// Command content-init resolves analyzer detection content before an analyzer
// starts (ADR-0005).
//
// It runs as an init container and holds no Kubernetes credentials: it fetches
// over the network and writes a volume, and an API client would be reach it has
// no use for.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"trawl.cloud/trawl/internal/content"
	"trawl.cloud/trawl/internal/sanitize"
)

// fetchTimeout bounds an upstream fetch. A hung feed must not hold a pod in
// init indefinitely, where it is far less visible than a failure.
const fetchTimeout = 5 * time.Minute

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "fetch-upstream":
		err = fetchUpstream(ctx, os.Args[2:])
	case "overlay-custom":
		err = overlayCustom(ctx, os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "content-init: %v\n", sanitize.Error(err))
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: content-init (fetch-upstream|overlay-custom) [flags]")
}

func fetchUpstream(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("fetch-upstream", flag.ExitOnError)
	analyzer := fs.String("analyzer", "", "Analyzer to fetch content for (Suricata or Zeek).")
	dir := fs.String("content-dir", "", "Directory to write content into.")
	feedURL := fs.String("feed-url", "", "Upstream Suricata rule feed URL.")
	scriptRepo := fs.String("script-repo", "", "Upstream Zeek script repository URL.")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *analyzer == "" {
		return errors.New("--analyzer and --content-dir are required")
	}

	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	target := filepath.Join(*dir, *analyzer)
	var fetcher content.Fetcher

	switch *analyzer {
	case "Suricata":
		if err := content.ValidateFeedURL(*feedURL); err != nil {
			return err
		}
		fetcher = &suricataUpdateFetcher{feedURL: *feedURL}
	case "Zeek":
		if err := content.ValidateFeedURL(*scriptRepo); err != nil {
			return err
		}
		fetcher = &zeekScriptFetcher{repo: *scriptRepo}
	default:
		return fmt.Errorf("unsupported analyzer %q", *analyzer)
	}

	resolver := &content.Resolver{Upstream: fetcher}
	merged, err := resolver.Resolve(ctx, target)
	if err != nil {
		return err
	}
	if err := content.Write(merged, target); err != nil {
		return err
	}
	return content.WriteStatus(target, merged.Status())
}

func overlayCustom(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("overlay-custom", flag.ExitOnError)
	analyzer := fs.String("analyzer", "", "Analyzer to overlay content for.")
	dir := fs.String("content-dir", "", "Directory holding upstream content.")
	reference := fs.String("reference", "", "Digest-pinned OCI artifact reference.")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *analyzer == "" || *reference == "" {
		return errors.New("--analyzer, --content-dir and --reference are required")
	}

	ref, err := content.ParseReference(*reference)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	target := filepath.Join(*dir, *analyzer)

	// The upstream layer is already on the volume from the previous init
	// container, so it is read back rather than re-fetched.
	existing, err := content.Read(target)
	if err != nil {
		return err
	}
	previous, err := content.ReadStatus(target)
	if err != nil {
		return err
	}

	resolver := &content.Resolver{
		Upstream: &staticFetcher{layer: content.Layer{
			Name:      content.LayerUpstream,
			Files:     existing,
			FetchedAt: previous.UpstreamFetchedAt,
		}},
		Custom: &orasFetcher{ref: ref},
		OnCustomFailure: func(err error) {
			// FR-043: report and continue. The analyzer starts on upstream
			// content, and status records that the overlay is absent.
			fmt.Fprintf(os.Stderr, "content-init: custom content unavailable, continuing upstream-only: %v\n",
				sanitize.Error(err))
		},
	}

	merged, err := resolver.Resolve(ctx, target)
	if err != nil {
		return err
	}
	if err := content.Write(merged, target); err != nil {
		return err
	}
	return content.WriteStatus(target, merged.Status())
}

// staticFetcher returns an already-resolved layer.
type staticFetcher struct{ layer content.Layer }

func (s *staticFetcher) Fetch(context.Context, string) (content.Layer, error) {
	return s.layer, nil
}

// suricataUpdateFetcher shells out to suricata-update.
//
// suricata-update is the upstream-supported path for ET Open: it owns the
// source list, the fetch, and the rule-file merge, all of which Trawl would
// otherwise reimplement and have to keep correct against feed changes.
type suricataUpdateFetcher struct{ feedURL string }

func (f *suricataUpdateFetcher) Fetch(ctx context.Context, dir string) (content.Layer, error) {
	staging := dir + ".fetch"
	if err := os.MkdirAll(staging, 0o750); err != nil {
		return content.Layer{}, sanitize.Errorf("creating fetch directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(staging) }()

	//nolint:gosec // the URL is installation configuration, validated as https
	cmd := exec.CommandContext(ctx, "suricata-update",
		"--no-test", "--no-reload",
		"--url", f.feedURL,
		"--data-dir", staging,
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return content.Layer{}, sanitize.Errorf("suricata-update failed: %v", err)
	}

	files, err := content.Read(staging)
	if err != nil {
		return content.Layer{}, err
	}
	return content.Layer{Name: content.LayerUpstream, Files: files, FetchedAt: time.Now().UTC()}, nil
}

// zeekScriptFetcher clones the pinned Zeek script repository.
type zeekScriptFetcher struct{ repo string }

func (f *zeekScriptFetcher) Fetch(ctx context.Context, dir string) (content.Layer, error) {
	staging := dir + ".fetch"
	_ = os.RemoveAll(staging)

	//nolint:gosec // the repository URL is installation configuration
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", f.repo, staging)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return content.Layer{}, sanitize.Errorf("cloning Zeek scripts failed: %v", err)
	}
	defer func() { _ = os.RemoveAll(staging) }()

	// The clone's .git directory is metadata, not content, and would otherwise
	// be copied onto every sensor's content volume.
	_ = os.RemoveAll(filepath.Join(staging, ".git"))

	files, err := content.Read(staging)
	if err != nil {
		return content.Layer{}, err
	}
	return content.Layer{Name: content.LayerUpstream, Files: files, FetchedAt: time.Now().UTC()}, nil
}

// orasFetcher pulls a digest-pinned OCI artifact.
type orasFetcher struct{ ref content.Reference }

func (f *orasFetcher) Fetch(ctx context.Context, dir string) (content.Layer, error) {
	staging := dir + ".custom"
	if err := os.MkdirAll(staging, 0o750); err != nil {
		return content.Layer{}, sanitize.Errorf("creating custom content directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(staging) }()

	// Pulled by digest, so the registry cannot serve different bytes than the
	// ones the rule review approved.
	//nolint:gosec // the reference is validated as repository@sha256:<64 hex>
	cmd := exec.CommandContext(ctx, "oras", "pull", f.ref.String(), "--output", staging)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return content.Layer{}, sanitize.Errorf("pulling custom content failed: %v", err)
	}

	files, err := content.Read(staging)
	if err != nil {
		return content.Layer{}, err
	}
	if len(files) == 0 {
		return content.Layer{}, errors.New("custom content artifact is empty")
	}
	return content.Layer{Name: content.LayerCustom, Files: files, Digest: f.ref.Digest}, nil
}
