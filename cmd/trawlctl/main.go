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

// Command trawlctl is the supported client for downloading capture artifacts.
//
// It exists because the download is a two-hop protocol - an authorized redirect
// from the gateway, then the bytes from object storage - and doing it with curl
// means either dropping the checksum verification or forwarding a Kubernetes
// bearer token to a bucket. The transport lives in internal/gateway so it can
// be tested against real servers; this binary is the credential handling and
// the file handling around it.
//
// The credential never appears in an argument or an environment variable. It is
// read from stdin, or from the standard output of a command this process runs
// (`kubectl create token`, typically). That is not a stylistic preference: a
// process's command line and environment are readable by other processes on the
// same machine and end up in shell history, CI logs, and `ps` output.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"trawl.cloud/trawl/internal/gateway"
	"trawl.cloud/trawl/internal/sanitize"
)

// Exit codes. The split matters to the acceptance script and to anything else
// driving this in a loop: a refused download is a fact about the cluster, while
// a usage error is a fact about the command line, and retrying tells them
// apart the wrong way round if they share a code.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

// maxTokenBytes bounds a token from stdin or from a token command. Service
// account tokens are a couple of kilobytes; anything approaching this is a
// pipe connected to the wrong thing, and reading it all into memory to find
// that out is avoidable.
const maxTokenBytes = 64 << 10

// The one command this client understands, named so the tests parse the same
// strings the binary does.
const (
	captureCommand  = "capture"
	downloadCommand = "download"
)

// partSuffix names the file the artifact is written to before its checksum is
// known. See download() for why this is load-bearing.
const partSuffix = ".part"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	os.Exit(run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run is main with its inputs and outputs passed in, so the whole command line
// is testable without building a binary.
func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) >= 2 && args[0] == captureCommand && args[1] == downloadCommand {
		return download(ctx, args[2:], stdin, stdout, stderr)
	}
	// Asking for help is not a mistake, so it goes to stdout and succeeds.
	if len(args) == 1 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
		usage(stdout)
		return exitOK
	}
	usage(stderr)
	return exitUsage
}

func usage(w io.Writer) {
	// Nothing useful can be done if writing to stderr fails, here or below:
	// there is no second channel to report it on.
	_, _ = fmt.Fprint(w, `trawlctl - client for Trawl capture artifacts

Usage:
  trawlctl capture download <name> --namespace <ns> --gateway <url> --ca <file>
           (--token-stdin | --token-exec <command> [-- <args>...]) --output <file>

The artifact is verified against the checksum the gateway reports and written
only if it matches. An existing --output file is never overwritten.
`)
}

// downloadOptions is the parsed command line.
type downloadOptions struct {
	name      string
	namespace string
	gateway   string
	caFile    string
	output    string

	tokenStdin bool
	tokenExec  []string
}

func download(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	opts, err := parseDownload(args, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "trawlctl: %v\n\n", err)
		usage(stderr)
		return exitUsage
	}

	// Refused before anything else happens. A download that ends by failing to
	// place its output has still spent a token and a presigned URL, and has
	// still been recorded in the ledger as a completed download.
	if _, err := os.Lstat(opts.output); err == nil {
		_, _ = fmt.Fprintf(stderr, "trawlctl: %s already exists; refusing to overwrite it\n", opts.output)
		return exitFailure
	} else if !errors.Is(err, os.ErrNotExist) {
		_, _ = fmt.Fprintf(stderr, "trawlctl: checking the output path: %v\n", sanitize.Error(err))
		return exitFailure
	}

	// Before the gateway is contacted, so a broken credential helper is not
	// reported as an authorization failure.
	token, err := readToken(ctx, opts, stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "trawlctl: %v\n", err)
		return exitFailure
	}

	client, err := gateway.NewClient(gateway.ClientOptions{BaseURL: opts.gateway, CAFile: opts.caFile})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "trawlctl: %v\n", err)
		return exitFailure
	}

	written, err := writeArtifact(ctx, client, token, opts)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "trawlctl: %s\n", describe(err))
		return exitFailure
	}

	_, _ = fmt.Fprintf(stdout, "wrote %d bytes to %s (sha256 verified against the gateway)\n", written, opts.output)
	return exitOK
}

func parseDownload(args []string, stderr io.Writer) (downloadOptions, error) {
	var opts downloadOptions

	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return opts, errors.New("capture download needs the name of a CaptureJob")
	}
	opts.name = args[0]

	fs := flag.NewFlagSet("trawlctl "+captureCommand+" "+downloadCommand, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {}
	fs.StringVar(&opts.namespace, "namespace", "", "Namespace of the CaptureJob.")
	fs.StringVar(&opts.gateway, "gateway", "", "Base URL of the artifact gateway, e.g. https://127.0.0.1:8443.")
	fs.StringVar(&opts.caFile, "ca", "", "PEM bundle the gateway's serving certificate is verified against.")
	fs.StringVar(&opts.output, "output", "", "Path to write the artifact to. Must not already exist.")
	fs.BoolVar(&opts.tokenStdin, "token-stdin", false, "Read the bearer token from standard input.")
	tokenExec := fs.String("token-exec", "", "Run this command and use its standard output as the bearer token.")
	if err := fs.Parse(args[1:]); err != nil {
		return opts, errors.New("invalid arguments")
	}

	// Anything left is the token command's own arguments, which the flag
	// package hands back after a `--`. Without --token-exec there is nothing
	// they could belong to, and silently ignoring a stray word is how a
	// mistyped flag becomes a download of the wrong capture.
	if *tokenExec != "" {
		opts.tokenExec = append([]string{*tokenExec}, fs.Args()...)
	} else if fs.NArg() > 0 {
		return opts, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}

	for _, required := range []struct {
		flag, value string
	}{
		{"--namespace", opts.namespace},
		{"--gateway", opts.gateway},
		{"--ca", opts.caFile},
		{"--output", opts.output},
	} {
		if strings.TrimSpace(required.value) == "" {
			return opts, fmt.Errorf("%s is required", required.flag)
		}
	}

	// Exactly one token source. Two would mean guessing which credential the
	// caller meant to use.
	if opts.tokenStdin == (len(opts.tokenExec) > 0) {
		return opts, errors.New("exactly one of --token-stdin and --token-exec is required")
	}
	return opts, nil
}

// readToken obtains the bearer token from the source the caller chose.
func readToken(ctx context.Context, opts downloadOptions, stdin io.Reader) (string, error) {
	var raw []byte
	var err error
	if opts.tokenStdin {
		raw, err = io.ReadAll(io.LimitReader(stdin, maxTokenBytes+1))
		if err != nil {
			return "", sanitize.Errorf("reading the token from stdin: %v", err)
		}
	} else {
		raw, err = execToken(ctx, opts.tokenExec)
		if err != nil {
			return "", err
		}
	}

	if len(raw) > maxTokenBytes {
		return "", fmt.Errorf("the token is longer than %d bytes; that is not a service account token", maxTokenBytes)
	}
	// Trimmed, because both sources end with a newline in practice and a
	// bearer token with a newline in it produces a header the gateway rejects
	// for a reason that has nothing to do with the caller's permissions.
	token := strings.TrimSpace(string(raw))
	if token == "" {
		if opts.tokenStdin {
			return "", errors.New("no token on stdin; pipe one in, " +
				"e.g. from `kubectl create token --audience=trawl-artifact-gateway`")
		}
		return "", errors.New("the token command printed nothing")
	}
	return token, nil
}

// execToken runs the caller's credential command and takes its standard output
// as the token.
//
// The command's standard error is reported but its standard output never is:
// on a partial failure that stream may hold a usable credential, and a token
// printed into a terminal by an error path is a token that has to be rotated.
func execToken(ctx context.Context, argv []string) ([]byte, error) {
	//nolint:gosec // the command is the operator's own, supplied on this process's command line
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin = nil

	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return nil, sanitize.Errorf("the token command failed: %v: %s",
				err, exitErr.Stderr)
		}
		return nil, sanitize.Errorf("the token command failed: %v", err)
	}
	return out, nil
}

// writeArtifact downloads into a temporary name beside the output and renames
// it only once Download has verified the checksum.
//
// The rename is the whole point. Download writes bytes to its writer before it
// can know whether they hash to what the controller recorded, because the hash
// is computed from those bytes - so between the first write and the last, the
// file on disk is an unverified artifact. Under the final name, nothing would
// distinguish it from a verified one.
func writeArtifact(ctx context.Context, client *gateway.Client, token string, opts downloadOptions) (int64, error) {
	part := opts.output + partSuffix

	// O_EXCL: a leftover .part is another download's, possibly one still
	// running, and taking it over would interleave two artifacts.
	//nolint:gosec // part is derived from --output, an operator-supplied flag on this process's own command line
	f, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, sanitize.Errorf("creating %s: %v", part, err)
	}
	// Removed on every path that does not reach the rename, including a panic:
	// what it holds is unverified evidence.
	committed := false
	defer func() {
		_ = f.Close()
		if !committed {
			_ = os.Remove(part)
		}
	}()

	written, err := client.Download(ctx, token, opts.namespace, opts.name, f)
	if err != nil {
		return written, err
	}
	if err := f.Sync(); err != nil {
		return written, sanitize.Errorf("flushing %s: %v", part, err)
	}
	if err := f.Close(); err != nil {
		return written, sanitize.Errorf("closing %s: %v", part, err)
	}
	if err := os.Rename(part, opts.output); err != nil {
		return written, sanitize.Errorf("renaming %s: %v", part, err)
	}
	committed = true
	return written, nil
}

// describe renders an error for an operator.
//
// A gateway refusal is reported with its code and request ID rather than as
// prose, because those two strings are what finds this request in the gateway's
// logs and in the audit ledger. Everything else is already sanitized by the
// layer that produced it.
func describe(err error) string {
	var apiErr *gateway.APIError
	if errors.As(err, &apiErr) {
		return fmt.Sprintf("the gateway refused the download: %s: %s (HTTP %d, request %s)",
			apiErr.Code, apiErr.Message, apiErr.StatusCode, apiErr.RequestID)
	}
	if errors.Is(err, gateway.ErrChecksumMismatch) {
		return fmt.Sprintf("%v; the downloaded bytes were discarded", err)
	}
	return err.Error()
}
