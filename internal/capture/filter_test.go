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
	"slices"
	"strings"
	"testing"
	"time"
)

func TestValidateFilterSyntax(t *testing.T) {
	ok := []string{"", "tcp port 443", "host 10.0.0.5 and not port 22", strings.Repeat("a", MaxFilterBytes)}
	for _, f := range ok {
		if err := ValidateFilterSyntax(f); err != nil {
			t.Errorf("%q rejected: %v", f, err)
		}
	}
	bad := map[string]string{
		"too long":  strings.Repeat("a", MaxFilterBytes+1),
		"newline":   "tcp\nport 443",
		"control":   "tcp\x00",
		"non-ascii": "tcp port 443 ünd",
		"tab":       "tcp\tport",
	}
	for name, f := range bad {
		err := ValidateFilterSyntax(f)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), "tcp") {
			t.Errorf("%s: error echoes the filter: %v", name, err)
		}
	}
}

func TestDumpcapArgsCarryEveryBound(t *testing.T) {
	b := Bounds{Duration: 90 * time.Second, MaxSizeBytes: 64 << 20, Snaplen: 1500}
	args := DumpcapArgs("eth0", "tcp port 443", b, "/work/capture.pcapng")
	wantPairs := [][2]string{
		{"-i", "eth0"}, {"-f", "tcp port 443"}, {"-a", "duration:90"}, {"-a", "filesize:65536"},
		{"-s", "1500"}, {"-w", "/work/capture.pcapng"},
	}
	for _, p := range wantPairs {
		if !hasPair(args, p[0], p[1]) {
			t.Errorf("args %q lack %q %q", args, p[0], p[1])
		}
	}
	for _, flag := range []string{"-n", "-q", "-P"} {
		want := flag != "-P"
		if slices.Contains(args, flag) != want {
			t.Errorf("args %q: %s present=%v, want %v", args, flag, !want, want)
		}
	}
}

func TestDumpcapArgsOmitEmptyFilterAndZeroSnaplen(t *testing.T) {
	b := Bounds{Duration: time.Second, MaxSizeBytes: 1 << 20}
	args := DumpcapArgs("eth0", "", b, "/work/c")
	if slices.Contains(args, "-f") || slices.Contains(args, "-s") {
		t.Errorf("args %q carry an empty filter or snaplen", args)
	}
	dry := DryRunArgs("eth0", "")
	if !slices.Contains(dry, "-d") || slices.Contains(dry, "-w") || slices.Contains(dry, "-f") {
		t.Errorf("dry-run args %q", dry)
	}
	dry = DryRunArgs("eth0", "tcp")
	if !hasPair(dry, "-f", "tcp") {
		t.Errorf("dry-run args %q lack the filter", dry)
	}
}

func hasPair(args []string, flag, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}
