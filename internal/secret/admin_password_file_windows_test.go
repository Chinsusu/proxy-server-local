//go:build windows

package secret

import (
	"errors"
	"testing"
)

func TestLoadRootOwnedAdminPasswordFileFailsClosedOnWindows(t *testing.T) {
	if _, err := LoadRootOwnedAdminPasswordFile(`C:\admin-password`, 4096); !errors.Is(err, ErrACLUnsupported) {
		t.Fatalf("err=%v, want ACL unsupported", err)
	}
}
