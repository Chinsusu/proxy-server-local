package domain

import "testing"

func TestValidateProxyAuthenticationRejectsNULForHTTPAndSOCKS5(t *testing.T) {
	for _, proxyType := range []ProxyType{ProxyHTTP, ProxySOCKS5} {
		for _, credential := range []struct {
			name     string
			username string
			password []byte
		}{
			{name: "username", username: "bad\x00user", password: []byte("password")},
			{name: "password", username: "user", password: []byte("bad\x00password")},
		} {
			t.Run(string(proxyType)+"_"+credential.name, func(t *testing.T) {
				if err := ValidateProxyAuthentication(proxyType, credential.username, credential.password, true); err == nil {
					t.Fatal("NUL credential was accepted")
				}
			})
		}
	}
}

func TestValidateProxyAuthenticationKeepsOpaqueNonNULCredentials(t *testing.T) {
	if err := ValidateProxyAuthentication(ProxyHTTP, "user\nname", []byte("pass\r\nword"), true); err != nil {
		t.Fatalf("non-NUL opaque credentials rejected: %v", err)
	}
}

func TestDesiredSnapshotRequiresExplicitDenyOnlyIPv6Policy(t *testing.T) {
	snapshot, err := BuildDesiredSnapshotWithIPv6Policy(7, IPv6PolicyDeny, nil)
	if err != nil || snapshot.IPv6Policy != IPv6PolicyDeny {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	if err := ValidateDesiredSnapshot(snapshot); err != nil {
		t.Fatalf("valid deny snapshot rejected: %v", err)
	}
	for _, value := range []IPv6Policy{"", "allow", "auto", "DENY"} {
		if _, err := BuildDesiredSnapshotWithIPv6Policy(7, value, nil); err == nil {
			t.Fatalf("permissive or unknown IPv6 policy %q accepted", value)
		}
	}
	snapshot.IPv6Policy = "allow"
	if err := ValidateDesiredSnapshot(snapshot); err == nil {
		t.Fatal("tampered permissive IPv6 policy accepted")
	}
}
