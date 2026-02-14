package auth

import (
	"testing"
	"time"
)

func TestSignAndParseJWT(t *testing.T) {
	secret := "test-secret-for-jwt-signing-1234567890"
	subject := "admin@test.com"
	role := "admin"

	tok, exp, err := SignJWT(subject, role, secret, time.Hour)
	if err != nil {
		t.Fatalf("SignJWT: %v", err)
	}
	if tok == "" {
		t.Fatal("expected non-empty token")
	}
	if exp.IsZero() {
		t.Fatal("expected non-zero expiry")
	}

	claims, err := ParseJWT(tok, secret)
	if err != nil {
		t.Fatalf("ParseJWT: %v", err)
	}
	if claims.Role != role {
		t.Fatalf("expected role %s, got %s", role, claims.Role)
	}
	sub, _ := claims.GetSubject()
	if sub != subject {
		t.Fatalf("expected subject %s, got %s", subject, sub)
	}
}

func TestParseJWT_WrongSecret(t *testing.T) {
	tok, _, _ := SignJWT("user", "admin", "correct-secret-1234567890123456", time.Hour)
	_, err := ParseJWT(tok, "wrong-secret-12345678901234567890")
	if err == nil {
		t.Fatal("expected error with wrong secret")
	}
}

func TestParseJWT_ExpiredToken(t *testing.T) {
	tok, _, _ := SignJWT("user", "admin", "test-secret-1234567890123456789", -time.Hour) // TTL in the past
	_, err := ParseJWT(tok, "test-secret-1234567890123456789")
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestParseJWT_InvalidFormat(t *testing.T) {
	_, err := ParseJWT("not-a-jwt-token", "secret")
	if err == nil {
		t.Fatal("expected error for garbage token")
	}
}

func TestSignJWT_EmptySecret(t *testing.T) {
	_, _, err := SignJWT("user", "admin", "", time.Hour)
	if err == nil {
		t.Fatal("expected error for empty secret")
	}
}
