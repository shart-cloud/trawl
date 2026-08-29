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

package sensor

import (
	"os"
	"syscall"
)

// openLog opens an analyzer log and returns its inode.
//
// The inode is what makes rotation detectable. Analyzers rotate their own logs,
// and a tailer holding the old inode would go silent while the analyzer kept
// writing — a monitoring outage whose only symptom is an absence of data, which
// is the hardest kind to notice.
func openLog(path string) (*os.File, uint64, error) {
	//nolint:gosec // the path is the operator-configured analyzer log location
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	ino, err := inodeOf(f)
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	return f, ino, nil
}

// rotated reports whether the file at path now has a different identity than
// the one the tailer holds open, or has disappeared.
func rotated(path string, openInode uint64) bool {
	info, err := os.Stat(path)
	if err != nil {
		// Gone, mid-rotation. Reopening will either find the new file or wait.
		return true
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return stat.Ino != openInode
}

func inodeOf(f *os.File) (uint64, error) {
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		// Not a Unix filesystem; rotation detection degrades to "never
		// rotated", which is correct on platforms without inodes.
		return 0, nil
	}
	return stat.Ino, nil
}
