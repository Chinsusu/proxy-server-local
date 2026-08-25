//go:build !linux

package snapshotcrypto

import "errors"

var nonLinuxKeyFileLoader = func(string) (Key, error) {
	return Key{}, errors.New("secure root-owned snapshot key files are supported only on Linux")
}

func platformLoadKeyFile(name string) (Key, error) {
	// Same-package Windows tests may replace this unexported hook with a
	// descriptor-safe fixture opener. Production callers cannot weaken Linux:
	// the hook is not compiled there.
	return nonLinuxKeyFileLoader(name)
}
