//go:build unix

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBearerAuthenticatorUsesScopedTokenDigest(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "agent.token")
	if err := os.WriteFile(tokenFile, []byte("scoped-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	authenticator, err := NewBearerAuthenticator(tokenFile)
	if err != nil {
		t.Fatalf("NewBearerAuthenticator: %v", err)
	}
	if !authenticator.Authorized("Bearer scoped-token") {
		t.Fatal("expected scoped token to authorize")
	}
	for _, header := range []string{"", "scoped-token", "Bearer ", "Bearer wrong", "bearer scoped-token"} {
		if authenticator.Authorized(header) {
			t.Fatalf("unexpected authorization for %q", header)
		}
	}
	if authenticator.Authorized("Bearer " + strings.Repeat("x", maxAuthorizationHeaderBytes)) {
		t.Fatal("oversized authorization header was accepted")
	}
}
