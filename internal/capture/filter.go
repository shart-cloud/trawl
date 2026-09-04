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
	"strconv"
)

// MaxFilterBytes bounds the BPF expression. libpcap has no documented limit;
// the bound exists so a filter can be carried in status messages and audit
// records without truncation.
const MaxFilterBytes = 1024

// ValidateFilterSyntax checks the shape of a filter: size and character set
// only. Whether libpcap accepts it is decided by dumpcap's dry run on the
// target node, because the answer depends on the interface's link type.
//
// Errors never include the filter, so a value that failed validation cannot
// reach an event or a log through the error path.
func ValidateFilterSyntax(filter string) error {
	if len(filter) > MaxFilterBytes {
		return fmt.Errorf("filter: longer than %d bytes", MaxFilterBytes)
	}
	for i := 0; i < len(filter); i++ {
		if c := filter[i]; c < 0x20 || c > 0x7e {
			return errors.New("filter: must be printable ASCII without control characters")
		}
	}
	return nil
}

// DumpcapArgs builds the capture invocation. Every bound is passed to
// dumpcap itself, so the process stops on its own even if the runner does not.
//
//	-n  no name resolution (no DNS from a privileged process)
//	-q  no per-packet counter on stderr
//	-P is deliberately absent: the artifact is pcapng.
func DumpcapArgs(iface, filter string, b Bounds, output string) []string {
	args := []string{"-i", iface}
	if filter != "" {
		args = append(args, "-f", filter)
	}
	args = append(args,
		"-a", "duration:"+strconv.FormatInt(int64(b.Duration.Seconds()), 10),
		"-a", "filesize:"+strconv.FormatInt(DumpcapFilesizeKB(b.MaxSizeBytes), 10),
	)
	if b.Snaplen != 0 {
		args = append(args, "-s", strconv.FormatInt(int64(b.Snaplen), 10))
	}
	return append(args, "-n", "-q", "-w", output)
}

// DryRunArgs compiles the filter against the interface without writing a
// file: dumpcap -d prints the generated BPF program and exits. A filter that
// does not compile fails here, before any packet is captured.
func DryRunArgs(iface, filter string) []string {
	args := []string{"-i", iface}
	if filter != "" {
		args = append(args, "-f", filter)
	}
	return append(args, "-d")
}
