//go:build windows

package agent

import "os"

// Windows is a development/test build target only. Production PGW runtime
// publication is Linux-specific and receives POSIX group ownership there.
func secureForwarderReadable(path string, directory, _ bool) error {
	mode := os.FileMode(0o640)
	if directory {
		mode = 0o750
	}
	return secureSetOwnerMode(path, 0, 0, mode, directory)
}
