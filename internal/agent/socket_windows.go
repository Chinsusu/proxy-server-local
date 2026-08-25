//go:build windows

package agent

import "fmt"

func validateUnixSocketPath(string) error {
	return fmt.Errorf("agent: Unix control socket is unsupported on Windows")
}
