//go:build windows

package agent

import "fmt"

// PGW's privileged Agent is Linux-only. Refuse to consume a persistent service
// token on Windows rather than pretending POSIX mode/no-follow checks exist.
func readSecureTokenFile(string, int64) ([]byte, error) {
	return nil, fmt.Errorf("agent: secure service token files are unsupported on Windows")
}
