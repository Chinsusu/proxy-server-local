package snapshotcrypto

// LoadKeyFile applies the platform trust policy and reads an exact raw 32-byte
// AES key. In production Linux this means an absolute, component-wise
// no-follow path to a root-owned regular file with mode exactly 0600.
func LoadKeyFile(path string) (Key, error) {
	return platformLoadKeyFile(path)
}
