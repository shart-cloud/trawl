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
	"errors"
	"fmt"
	"time"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/config"
)

// Bound limits from the CRD contract. The admission webhook enforces the same
// numbers; the runner re-checks them because it must never trust that a Job
// was rendered from an admitted object.
const (
	MinDuration = time.Second
	MaxDuration = time.Hour

	MinSizeBytes = 1 << 20
	MaxSizeBytes = 1 << 30

	MinSnaplen = 64
	MaxSnaplen = 262144

	// MaxOvershootBytes is how far past maxSize the file may grow before the
	// runner discards it. dumpcap checks the size after each write, so the
	// last packet can carry the file over the limit by at most one packet.
	MaxOvershootBytes = 1 << 20

	// WorkVolumeHeadroomBytes is added to the work volume so the overshoot
	// tolerance and dumpcap's own bookkeeping never hit the volume limit
	// before the size bound does.
	WorkVolumeHeadroomBytes = 16 << 20
)

// Bounds are the parsed, range-checked capture limits.
type Bounds struct {
	Duration     time.Duration
	MaxSizeBytes int64
	// Snaplen is 0 when the interface default applies.
	Snaplen int32
}

// ParseBounds validates the bounds a spec carries. Errors name the field but
// never echo the value.
func ParseBounds(spec trawlv1alpha1.CaptureJobSpec) (Bounds, error) {
	d, err := config.ParseDuration(spec.Duration)
	if err != nil {
		return Bounds{}, errors.New("duration: not a valid duration")
	}
	if d < MinDuration || d > MaxDuration {
		return Bounds{}, fmt.Errorf("duration: must be between %s and %s", MinDuration, MaxDuration)
	}
	size, ok := spec.MaxSize.AsInt64()
	if !ok {
		return Bounds{}, errors.New("maxSize: must be a whole number of bytes")
	}
	if size < MinSizeBytes || size > MaxSizeBytes {
		return Bounds{}, fmt.Errorf("maxSize: must be between %d and %d bytes", MinSizeBytes, MaxSizeBytes)
	}
	if spec.Snaplen != 0 && (spec.Snaplen < MinSnaplen || spec.Snaplen > MaxSnaplen) {
		return Bounds{}, fmt.Errorf("snaplen: must be 0 or between %d and %d", MinSnaplen, MaxSnaplen)
	}
	return Bounds{Duration: d, MaxSizeBytes: size, Snaplen: spec.Snaplen}, nil
}

// DumpcapFilesizeKB converts a byte bound to the unit dumpcap's
// "-a filesize:" takes. dumpcap documents the unit as kB and has meant both
// 1000 and 1024 across versions; dividing by 1024 undershoots under either
// reading, so rounding can only make the capture smaller.
func DumpcapFilesizeKB(maxSize int64) int64 {
	return maxSize / 1024
}

// Overshoot reports whether a file grew further past the bound than the
// last-packet tolerance allows.
func Overshoot(size, maxSize int64) bool {
	return size > maxSize+MaxOvershootBytes
}

// ActiveDeadline is the Job's activeDeadlineSeconds: the capture itself plus
// the time allowed to start before it and to upload after it.
func ActiveDeadline(b Bounds, startupBudget, uploadBudget time.Duration) time.Duration {
	return startupBudget + b.Duration + uploadBudget
}

// WorkVolumeBytes sizes the emptyDir the runner writes into.
func WorkVolumeBytes(b Bounds) int64 {
	return b.MaxSizeBytes + WorkVolumeHeadroomBytes
}
