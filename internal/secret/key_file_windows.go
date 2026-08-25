//go:build windows

package secret

func secureReadKeyFile(string, int64) ([]byte, error) {
	return nil, ErrACLUnsupported
}

func secureReadTokenFile(string, int64) ([]byte, error) {
	return nil, ErrACLUnsupported
}
