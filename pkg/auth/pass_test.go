package auth

import (
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	password := "correct-horse-battery-staple"
	hash, err := HashPassword(password, DefaultParams())
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == "" {
		t.Fatal("expected non-empty hash")
	}

	ok, err := VerifyPassword(hash, password)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("expected password to verify successfully")
	}
}

func TestVerify_WrongPassword(t *testing.T) {
	hash, _ := HashPassword("correct-password", DefaultParams())
	ok, err := VerifyPassword(hash, "wrong-password")
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if ok {
		t.Fatal("expected wrong password to fail verification")
	}
}

func TestHashPassword_EmptyString(t *testing.T) {
	_, err := HashPassword("", DefaultParams())
	if err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestVerifyPassword_InvalidFormat(t *testing.T) {
	_, err := VerifyPassword("not-a-valid-hash", "password")
	if err == nil {
		t.Fatal("expected error for invalid hash format")
	}
}

func TestHashPassword_DifferentHashes(t *testing.T) {
	// Two hashes of the same password should differ (different salt)
	h1, _ := HashPassword("same-password", DefaultParams())
	h2, _ := HashPassword("same-password", DefaultParams())
	if h1 == h2 {
		t.Fatal("expected different hashes for same password (different salts)")
	}
	// But both should verify
	ok1, _ := VerifyPassword(h1, "same-password")
	ok2, _ := VerifyPassword(h2, "same-password")
	if !ok1 || !ok2 {
		t.Fatal("both hashes should verify against the same password")
	}
}
