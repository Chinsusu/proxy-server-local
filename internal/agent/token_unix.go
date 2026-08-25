//go:build unix

package agent

import (
	"fmt"
)

func readSecureTokenFile(path string, limit int64) ([]byte, error) {
	token, err := secureReadToken(path, limit)
	if err != nil {
		return nil, fmt.Errorf("agent: securely read service token: %w", err)
	}
	if len(token) < 1 {
		return nil, fmt.Errorf("agent: empty service token")
	}
	return token, nil
}
