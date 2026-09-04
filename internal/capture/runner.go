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

package capture

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/sanitize"
	"trawl.cloud/trawl/internal/storage"
)

// Runner defaults.
const (
	// WorkFileName is the capture file inside WorkDir.
	WorkFileName = "capture.pcapng"

	// DefaultDryRunTimeout bounds the filter compilation.
	DefaultDryRunTimeout = 10 * time.Second
	// DefaultStartTimeout bounds how long dumpcap may take to create the
	// capture file after it is started.
	DefaultStartTimeout = 15 * time.Second
	// DefaultStopGrace is how long dumpcap gets to exit after SIGINT before
	// it is killed.
	DefaultStopGrace = 5 * time.Second
	// DefaultUploadBudget bounds the artifact upload.
	DefaultUploadBudget = 15 * time.Minute

	// stderrRingBytes is how much of dumpcap's output is kept. It exists for
	// the diagnostic fingerprint and a sanitized tail; the rest is dropped.
	stderrRingBytes = 64 << 10
	// stderrTailBytes is the most of that output a message may carry.
	stderrTailBytes = 200

	filePollInterval = 100 * time.Millisecond
)

// Uploader is the storage surface the runner needs. It is the write half of
// storage.Store; the runner never reads, lists, or deletes.
type Uploader interface {
	Put(ctx context.Context, key string, body []byte, opts storage.PutOptions) (storage.ObjectInfo, error)
	PutStream(ctx context.Context, key string, body io.Reader, size int64, opts storage.PutOptions) (storage.ObjectInfo, error)
}

// Runner performs one capture: validates, dry-runs the filter, runs dumpcap
// under the bounds, verifies the file, uploads it, and reports through the
// progress records. It holds no Kubernetes credentials.
type Runner struct {
	Spec trawlv1alpha1.CaptureJobSpec

	CaptureJobUID string
	Namespace     string
	Name          string
	// Interface is the resolved interface from the tap; the runner does not
	// read the tap itself.
	Interface string

	WorkDir  string
	Records  *RecordWriter
	Uploader Uploader

	// DumpcapCommand is the dumpcap executable and any leading arguments.
	// Tests substitute a fake.
	DumpcapCommand []string
	DumpcapVersion string
	RunnerVersion  string

	DryRunTimeout time.Duration
	StartTimeout  time.Duration
	StopGrace     time.Duration
	UploadBudget  time.Duration

	Now func() time.Time
	// Logf receives progress lines. Every argument passed to it is either a
	// fixed string, a number, or already sanitized.
	Logf func(format string, args ...any)
}

// Result is what the runner ends with. ExitCode is the process exit code
// and the other fields are what the result record carries.
type Result struct {
	ExitCode    int32
	Outcome     trawlv1alpha1.RunnerOutcome
	Reason      trawlv1alpha1.FailureReason
	StopReason  trawlv1alpha1.CaptureStopReason
	PacketCount int64
	SizeBytes   int64
	SHA256      string
	Message     string
}

// Run executes the capture. It never panics out and never returns without
// having attempted to write a result record.
func (r *Runner) Run(ctx context.Context) Result {
	r.applyDefaults()
	res := r.run(ctx)
	code := res.ExitCode
	fields := Fields{
		Outcome: res.Outcome, Reason: res.Reason, SHA256: res.SHA256, ExitCode: &code, Message: res.Message,
	}
	if res.Outcome == trawlv1alpha1.RunnerOutcomeSucceeded {
		// The packet count comes from the pcapng walk, which happens after the
		// ended record is written, so it rides on the result.
		packets := res.PacketCount
		fields.PacketCount = &packets
	}
	if err := r.Records.Write(RecordResult, fields); err != nil {
		r.Logf("result record not written: %v", sanitize.Error(err))
	}
	return res
}

func (r *Runner) applyDefaults() {
	if r.DryRunTimeout == 0 {
		r.DryRunTimeout = DefaultDryRunTimeout
	}
	if r.StartTimeout == 0 {
		r.StartTimeout = DefaultStartTimeout
	}
	if r.StopGrace == 0 {
		r.StopGrace = DefaultStopGrace
	}
	if r.UploadBudget == 0 {
		r.UploadBudget = DefaultUploadBudget
	}
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.Logf == nil {
		r.Logf = func(string, ...any) {}
	}
	if r.Records.Now == nil {
		r.Records.Now = r.Now
	}
}

func (r *Runner) run(ctx context.Context) Result {
	bounds, err := ParseBounds(r.Spec)
	if err != nil {
		return failure(trawlv1alpha1.FailureInvalidBounds, "", err.Error())
	}
	if err := ValidateFilterSyntax(r.Spec.Filter); err != nil {
		return failure(trawlv1alpha1.FailureInvalidFilter, "", err.Error())
	}
	if _, err := net.InterfaceByName(r.Interface); err != nil {
		return failure(trawlv1alpha1.FailureInterfaceUnavailable, "", "interface not present on this node")
	}

	// The filter is compiled against the live interface before any capture
	// file exists, so a bad filter can never leave a partial artifact behind.
	if res, ok := r.dryRun(ctx); !ok {
		return res
	}
	if err := r.Records.Write(RecordFilter, Fields{Interface: r.Interface}); err != nil {
		return failure(trawlv1alpha1.FailureInternalError, "", "cannot write progress records")
	}

	return r.capture(ctx, bounds)
}

// dryRun asks dumpcap to compile the filter. dumpcap -d opens the interface
// to learn its link type, so a failure here is the filter when one was
// given and the interface otherwise.
func (r *Runner) dryRun(ctx context.Context) (Result, bool) {
	ctx, cancel := context.WithTimeout(ctx, r.DryRunTimeout)
	defer cancel()
	args := append(append([]string{}, r.DumpcapCommand[1:]...), DryRunArgs(r.Interface, r.Spec.Filter)...)
	cmd := exec.CommandContext(ctx, r.DumpcapCommand[0], args...) //nolint:gosec // Fixed executable, arguments built here.
	ring := newRing(stderrRingBytes)
	cmd.Stdout = io.Discard
	cmd.Stderr = ring
	if err := cmd.Run(); err != nil {
		r.Logf("filter dry run failed: exit=%s stderr=%s", exitStatus(err), ring.hash())
		reason := trawlv1alpha1.FailureInvalidFilter
		msg := "the filter did not compile against the interface"
		if r.Spec.Filter == "" {
			reason = trawlv1alpha1.FailureInterfaceUnavailable
			msg = "dumpcap could not open the interface"
		}
		return failure(reason, "", msg+": "+ring.tail()), false
	}
	return Result{}, true
}

func (r *Runner) capture(ctx context.Context, bounds Bounds) Result {
	output := filepath.Join(r.WorkDir, WorkFileName)
	_ = os.Remove(output)

	args := append(append([]string{}, r.DumpcapCommand[1:]...), DumpcapArgs(r.Interface, r.Spec.Filter, bounds, output)...)
	// Not CommandContext: cancellation must interrupt dumpcap so it closes the
	// file cleanly, not kill it. stop() handles the signal sequence.
	cmd := exec.Command(r.DumpcapCommand[0], args...) //nolint:gosec,noctx // Fixed executable; see comment above.
	ring := newRing(stderrRingBytes)
	cmd.Stdout = ring
	cmd.Stderr = ring
	if err := cmd.Start(); err != nil {
		return failure(trawlv1alpha1.FailureInternalError, "", "dumpcap could not be started")
	}
	launched := r.Now()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	// dumpcap creates the file only after the interface is open and the
	// filter is attached, so its existence is the "capturing" signal.
	startedAt, exited, waitErr := r.awaitFile(output, done, r.StartTimeout)
	if startedAt.IsZero() {
		if !exited {
			_ = r.stop(cmd, done)
		}
		r.Logf("capture file never appeared: exit=%s stderr=%s", exitStatus(waitErr), ring.hash())
		return failure(trawlv1alpha1.FailureCaptureFailed, trawlv1alpha1.CaptureStopError,
			"dumpcap exited before creating the capture file: "+ring.tail())
	}
	if err := r.Records.Write(RecordStarted, Fields{StartedAt: &startedAt}); err != nil {
		_ = r.stop(cmd, done)
		return failure(trawlv1alpha1.FailureInternalError, trawlv1alpha1.CaptureStopError, "cannot write progress records")
	}

	cancelled := false
	if !exited {
		select {
		case waitErr = <-done:
		case <-ctx.Done():
			cancelled = true
			waitErr = r.stop(cmd, done)
		}
	}
	endedAt := r.Now()

	info, statErr := os.Stat(output)
	if statErr != nil {
		return failure(trawlv1alpha1.FailureCaptureFailed, trawlv1alpha1.CaptureStopError, "the capture file disappeared")
	}
	size := info.Size()
	stop := r.inferStop(cancelled, waitErr, size, endedAt.Sub(launched), bounds)

	if err := r.Records.Write(RecordEnded, Fields{EndedAt: &endedAt, StopReason: stop, SizeBytes: &size}); err != nil {
		return failure(trawlv1alpha1.FailureInternalError, stop, "cannot write progress records")
	}

	switch stop {
	case trawlv1alpha1.CaptureStopCancelled:
		_ = os.Remove(output)
		return failure(trawlv1alpha1.FailureCaptureFailed, stop, "the capture was cancelled before it completed")
	case trawlv1alpha1.CaptureStopError:
		r.Logf("dumpcap ended abnormally: exit=%s stderr=%s", exitStatus(waitErr), ring.hash())
		_ = os.Remove(output)
		return failure(trawlv1alpha1.FailureCaptureFailed, stop, "dumpcap ended abnormally: "+ring.tail())
	}
	if Overshoot(size, bounds.MaxSizeBytes) {
		_ = os.Remove(output)
		return failure(trawlv1alpha1.FailureSizeExceeded, stop,
			fmt.Sprintf("the capture file is %d bytes, more than %d over the %d byte bound; it was discarded",
				size, MaxOvershootBytes, bounds.MaxSizeBytes))
	}

	return r.store(ctx, output, bounds, startedAt, endedAt, stop)
}

// awaitFile waits for the capture file or for dumpcap to exit, whichever is
// first. It returns the time the file was seen (zero if it never was), whether
// dumpcap has exited, and its wait error if so.
func (r *Runner) awaitFile(path string, done <-chan error, timeout time.Duration) (time.Time, bool, error) {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(filePollInterval)
	defer tick.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return r.Now(), false, nil
		}
		select {
		case err := <-done:
			if _, statErr := os.Stat(path); statErr == nil {
				// It wrote the file and finished within one poll interval.
				return r.Now(), true, err
			}
			return time.Time{}, true, err
		case <-deadline.C:
			return time.Time{}, false, nil
		case <-tick.C:
		}
	}
}

// stop interrupts dumpcap so it finishes the file cleanly, then kills it.
func (r *Runner) stop(cmd *exec.Cmd, done <-chan error) error {
	_ = cmd.Process.Signal(syscall.SIGINT)
	select {
	case err := <-done:
		return err
	case <-time.After(r.StopGrace):
		_ = cmd.Process.Kill()
		return <-done
	}
}

// inferStop decides which bound ended the capture. dumpcap does not say; the
// file size against the size bound and the elapsed time against the duration
// bound do, and anything else is an abnormal end.
func (r *Runner) inferStop(cancelled bool, waitErr error, size int64, elapsed time.Duration, b Bounds) trawlv1alpha1.CaptureStopReason {
	if cancelled {
		return trawlv1alpha1.CaptureStopCancelled
	}
	if waitErr != nil {
		return trawlv1alpha1.CaptureStopError
	}
	// dumpcap's kB may be 1000 or 1024 bytes; the smaller reading is the
	// earliest point at which it can have stopped for size.
	if size >= DumpcapFilesizeKB(b.MaxSizeBytes)*1000 {
		return trawlv1alpha1.CaptureStopSize
	}
	if elapsed >= b.Duration-time.Second {
		return trawlv1alpha1.CaptureStopDuration
	}
	return trawlv1alpha1.CaptureStopError
}

func (r *Runner) store(ctx context.Context, output string, bounds Bounds, startedAt, endedAt time.Time, stop trawlv1alpha1.CaptureStopReason) Result {
	f, err := os.Open(output) //nolint:gosec // Path is WorkDir plus a constant.
	if err != nil {
		return failure(trawlv1alpha1.FailureCaptureFailed, stop, "the capture file could not be read")
	}
	defer f.Close() //nolint:errcheck // Read-only handle.

	packets, size, sum, err := CountAndHash(f)
	if err != nil {
		_ = os.Remove(output)
		return failure(trawlv1alpha1.FailureCaptureFailed, stop, "the capture file is not well-formed pcapng: "+err.Error())
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return failure(trawlv1alpha1.FailureInternalError, stop, "the capture file could not be rewound")
	}

	manifest := &Manifest{
		SchemaVersion:     ManifestSchemaVersion,
		CaptureJobUID:     r.CaptureJobUID,
		Namespace:         r.Namespace,
		Name:              r.Name,
		Interface:         r.Interface,
		Filter:            r.Spec.Filter,
		Snaplen:           bounds.Snaplen,
		RequestedDuration: r.Spec.Duration,
		RequestedMaxSize:  bounds.MaxSizeBytes,
		StartedAt:         startedAt.UTC(),
		EndedAt:           endedAt.UTC(),
		StopReason:        stop,
		PacketCount:       packets,
		SizeBytes:         size,
		SHA256:            sum,
		DumpcapVersion:    r.DumpcapVersion,
		RunnerVersion:     r.RunnerVersion,
	}
	raw, err := manifest.Marshal()
	if err != nil {
		return failure(trawlv1alpha1.FailureInternalError, stop, "the manifest could not be encoded")
	}

	uploadCtx, cancel := context.WithTimeout(ctx, r.UploadBudget)
	defer cancel()
	_, err = r.Uploader.PutStream(uploadCtx, ObjectKey(r.Namespace, r.CaptureJobUID), f, size, storage.PutOptions{
		IfNotExists: true,
		ContentType: ContentTypePcapng,
		Metadata: map[string]string{
			MetadataSHA256:        sum,
			MetadataCaptureJobUID: r.CaptureJobUID,
			MetadataPacketCount:   strconv.FormatInt(packets, 10),
		},
		Timeout: r.UploadBudget,
	})
	if err != nil {
		return uploadFailure(err, stop, "artifact")
	}
	_, err = r.Uploader.Put(uploadCtx, ManifestKey(r.Namespace, r.CaptureJobUID), raw, storage.PutOptions{
		IfNotExists: true,
		ContentType: ContentTypeManifest,
		Metadata:    map[string]string{MetadataCaptureJobUID: r.CaptureJobUID},
	})
	if err != nil {
		return uploadFailure(err, stop, "manifest")
	}

	_ = f.Close()
	_ = os.Remove(output)
	r.Logf("capture stored: packets=%d bytes=%d stop=%s", packets, size, stop)
	return Result{
		ExitCode:    ExitOK,
		Outcome:     trawlv1alpha1.RunnerOutcomeSucceeded,
		StopReason:  stop,
		PacketCount: packets,
		SizeBytes:   size,
		SHA256:      sum,
	}
}

func failure(reason trawlv1alpha1.FailureReason, stop trawlv1alpha1.CaptureStopReason, message string) Result {
	return Result{
		ExitCode:   ExitCodeFor(reason),
		Outcome:    trawlv1alpha1.RunnerOutcomeFailed,
		Reason:     reason,
		StopReason: stop,
		Message:    sanitize.String(message),
	}
}

func uploadFailure(err error, stop trawlv1alpha1.CaptureStopReason, what string) Result {
	if errors.Is(err, storage.ErrAlreadyExists) {
		return failure(trawlv1alpha1.FailureUploadFailed, stop,
			"an object already exists for this capture; the new "+what+" was not written over it")
	}
	return failure(trawlv1alpha1.FailureUploadFailed, stop, "storing the "+what+" failed: "+sanitize.Error(err).Error())
}

func exitStatus(err error) string {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return strconv.Itoa(exitErr.ExitCode())
	}
	if err == nil {
		return "0"
	}
	return "unknown"
}

// ring keeps the last n bytes written to it. dumpcap's output can include
// the filter, interface names, and whatever a hostile packet source
// arranges to have printed, so it is never logged whole.
type ring struct {
	mu   sync.Mutex
	buf  []byte
	size int
}

func newRing(size int) *ring { return &ring{size: size} }

func (r *ring) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.buf...)
}

func (r *ring) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, p...)
	if len(r.buf) > r.size {
		r.buf = r.buf[len(r.buf)-r.size:]
	}
	return len(p), nil
}

// hash is the diagnostic fingerprint of the captured output.
func (r *ring) hash() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return sanitize.DiagnosticHash(string(r.buf))
}

// tail is a short, sanitized end of the output for a message.
func (r *ring) tail() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	b := bytes.TrimSpace(r.buf)
	if len(b) > stderrTailBytes {
		b = b[len(b)-stderrTailBytes:]
	}
	return sanitize.String(string(b))
}

// DumpcapVersion runs `dumpcap --version` and returns the version token from
// its first line ("Dumpcap (Wireshark) 4.0.17 ..." → "4.0.17"), bounded and
// sanitized. It is recorded in the manifest for provenance and nothing
// depends on it.
func DumpcapVersion(ctx context.Context, path string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultDryRunTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--version") //nolint:gosec // Fixed executable from configuration.
	out := newRing(4096)
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return "", sanitize.Errorf("dumpcap --version: %v", err)
	}
	line, _, _ := bytes.Cut(out.bytes(), []byte("\n"))
	for f := range bytes.FieldsSeq(line) {
		if len(f) > 0 && f[0] >= '0' && f[0] <= '9' {
			return sanitize.String(string(f)), nil
		}
	}
	return "", errors.New("dumpcap --version printed no version")
}
