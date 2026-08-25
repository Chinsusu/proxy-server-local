package httpx

import (
	"bytes"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestProxyIdentityVerifiedReplayAndSpoofProtection(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	verifier, err := NewProxyIdentityVerifier(key)
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Close()
	now := time.Unix(1_700_000_000, 0).UTC()
	verifier.now = func() time.Time { return now }
	header, err := SignProxyIdentity(key, netip.MustParseAddr("198.51.100.19"), now, "nonce_0123456789")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", "/v1/auth/login", nil)
	request.RemoteAddr = "127.0.0.1:40000"
	request.Header = header
	client, err := CanonicalLoginClientIP(request, verifier)
	if err != nil || client != "198.51.100.19" {
		t.Fatalf("client=%q err=%v", client, err)
	}
	if _, err := CanonicalLoginClientIP(request, verifier); err == nil {
		t.Fatal("replayed proxy nonce accepted")
	}

	forged, err := SignProxyIdentity(bytes.Repeat([]byte{8}, 32), netip.MustParseAddr("198.51.100.20"), now, "nonce_abcdefghij")
	if err != nil {
		t.Fatal(err)
	}
	request.Header = forged
	if _, err := CanonicalLoginClientIP(request, verifier); err == nil {
		t.Fatal("forged signature accepted")
	}
	request.RemoteAddr = "198.51.100.1:40000"
	if _, err := CanonicalLoginClientIP(request, verifier); err == nil {
		t.Fatal("non-loopback peer supplied proxy identity")
	}
}

func TestProxyIdentitySkewRotationAndDirectFallback(t *testing.T) {
	current := bytes.Repeat([]byte{1}, 32)
	previous := bytes.Repeat([]byte{2}, 32)
	verifier, err := NewProxyIdentityVerifier(current, previous)
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Close()
	now := time.Unix(1_700_000_000, 0).UTC()
	verifier.now = func() time.Time { return now }
	header, err := SignProxyIdentity(previous, netip.MustParseAddr("2001:db8::10"), now, "nonce_abcdefghijkl")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", "/v1/auth/login", nil)
	request.RemoteAddr = "[::1]:40000"
	request.Header = header
	if client, err := CanonicalLoginClientIP(request, verifier); err != nil || client != "2001:db8::10" {
		t.Fatalf("rotated client=%q err=%v", client, err)
	}
	stale, err := SignProxyIdentity(current, netip.MustParseAddr("198.51.100.4"), now.Add(-61*time.Second), "nonce_stale_0123")
	if err != nil {
		t.Fatal(err)
	}
	request.Header = stale
	if _, err := CanonicalLoginClientIP(request, verifier); err == nil {
		t.Fatal("stale identity accepted")
	}
	request.Header = nil
	request.RemoteAddr = "127.0.0.2:40000"
	if client, err := CanonicalLoginClientIP(request, verifier); err != nil || client != "127.0.0.2" {
		t.Fatalf("direct fallback client=%q err=%v", client, err)
	}
	request.RemoteAddr = "198.51.100.9:40000"
	if _, err := CanonicalLoginClientIP(request, verifier); err == nil {
		t.Fatal("non-loopback direct login peer accepted")
	}
}
