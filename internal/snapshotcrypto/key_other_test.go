//go:build !linux

package snapshotcrypto

import "testing"

func TestNonLinuxKeyLoaderCanBeSafelyInjectedBySamePackageTests(t *testing.T) {
	original := nonLinuxKeyFileLoader
	t.Cleanup(func() { nonLinuxKeyFileLoader = original })
	nonLinuxKeyFileLoader = func(path string) (Key, error) {
		if path != `C:\fixture\snapshot.key` {
			t.Fatalf("loader path = %q", path)
		}
		return *testKey(9), nil
	}
	key, err := LoadKeyFile(`C:\fixture\snapshot.key`)
	if err != nil || key[0] != 9 {
		t.Fatalf("LoadKeyFile() key[0]=%d, error=%v", key[0], err)
	}
}
