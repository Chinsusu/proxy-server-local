//go:build unix

package agent

import (
	"fmt"
	"os"
)

func validateUnixSocketPath(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("agent: inspect control socket: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("agent: control path is not a real Unix socket")
	}
	return nil
}
