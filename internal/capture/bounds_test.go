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
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
)

func TestParseBoundsAcceptsTheContractRange(t *testing.T) {
	spec := trawlv1alpha1.CaptureJobSpec{Duration: "60s", MaxSize: resource.MustParse("64Mi"), Snaplen: 1500}
	b, err := ParseBounds(spec)
	if err != nil {
		t.Fatalf("ParseBounds: %v", err)
	}
	if b.Duration != time.Minute || b.MaxSizeBytes != 64<<20 || b.Snaplen != 1500 {
		t.Errorf("bounds %+v", b)
	}
}

func TestParseBoundsRejectsOutOfRange(t *testing.T) {
	cases := map[string]trawlv1alpha1.CaptureJobSpec{
		"zero duration":      {Duration: "0s", MaxSize: resource.MustParse("64Mi")},
		"garbage duration":   {Duration: "soon", MaxSize: resource.MustParse("64Mi")},
		"too long":           {Duration: "2h", MaxSize: resource.MustParse("64Mi")},
		"too small":          {Duration: "60s", MaxSize: resource.MustParse("512Ki")},
		"too large":          {Duration: "60s", MaxSize: resource.MustParse("2Gi")},
		"tiny snaplen":       {Duration: "60s", MaxSize: resource.MustParse("64Mi"), Snaplen: 32},
		"huge snaplen":       {Duration: "60s", MaxSize: resource.MustParse("64Mi"), Snaplen: 1 << 20},
		"negative snaplen":   {Duration: "60s", MaxSize: resource.MustParse("64Mi"), Snaplen: -1},
		"fractional maxSize": {Duration: "60s", MaxSize: resource.MustParse("1.5")},
	}
	for name, spec := range cases {
		if _, err := ParseBounds(spec); err == nil {
			t.Errorf("%s: accepted %+v", name, spec)
		}
	}
}

func TestDumpcapFilesizeUndershoots(t *testing.T) {
	// dumpcap's "kB" may mean 1000 or 1024; dividing by 1024 undershoots
	// under either reading, so the bound is never exceeded by rounding.
	if got := DumpcapFilesizeKB(64 << 20); got != 65536 {
		t.Errorf("64Mi → %d kB, want 65536", got)
	}
	if got := DumpcapFilesizeKB(1<<20 + 1023); got != 1024 {
		t.Errorf("1Mi+1023 → %d kB, want 1024", got)
	}
}

func TestOvershootTolerance(t *testing.T) {
	limit := int64(64 << 20)
	if Overshoot(limit, limit) || Overshoot(limit+MaxOvershootBytes, limit) {
		t.Error("within tolerance reported as overshoot")
	}
	if !Overshoot(limit+MaxOvershootBytes+1, limit) {
		t.Error("beyond tolerance not reported")
	}
}

func TestActiveDeadlineAndWorkVolumeIncludeBudgets(t *testing.T) {
	b := Bounds{Duration: time.Minute, MaxSizeBytes: 64 << 20}
	if got := ActiveDeadline(b, 5*time.Minute, 15*time.Minute); got != 21*time.Minute {
		t.Errorf("ActiveDeadline = %v", got)
	}
	if got := WorkVolumeBytes(b); got != 64<<20+WorkVolumeHeadroomBytes {
		t.Errorf("WorkVolumeBytes = %d", got)
	}
}
