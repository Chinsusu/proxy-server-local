package auth

import (
	"errors"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	password := []byte("correct-horse-battery-staple")
	hash, err := HashPassword(password, DefaultParams())
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == "" {
		t.Fatal("expected non-empty hash")
	}

	ok, err := VerifyPassword([]byte(hash), password)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("expected password to verify successfully")
	}
}

func TestHashAndVerifyBytesNeverRequirePasswordString(t *testing.T) {
	password := []byte("correct-horse-battery-staple")
	hash, err := HashPasswordBytes(password, DefaultParams())
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := VerifyPasswordBytes([]byte(hash), password); err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	wrong := []byte("wrong-password")
	if ok, err := VerifyPasswordBytes([]byte(hash), wrong); err != nil || ok {
		t.Fatalf("wrong ok=%v err=%v", ok, err)
	}
	wipe(password)
	wipe(wrong)
}

func TestArgonParamsAndGlobalWorkBudgetFailClosed(t *testing.T) {
	for _, params := range []ArgonParams{{}, {Memory: maxArgonMemoryKiB + 1, Iterations: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32}, {Memory: 8, Iterations: 1, Parallelism: 2, SaltLen: 16, KeyLen: 32}} {
		if _, err := HashPassword([]byte("password"), params); err == nil {
			t.Fatalf("unsafe params accepted: %+v", params)
		}
	}
	first, ok := TryAcquirePasswordWork()
	if !ok {
		t.Fatal("first work slot unavailable")
	}
	second, ok := TryAcquirePasswordWork()
	if !ok {
		t.Fatal("second work slot unavailable")
	}
	if _, ok := TryAcquirePasswordWork(); ok {
		t.Fatal("unbounded Argon2 work admitted")
	}
	first()
	second()
}

func TestHashAndVerifyHonorGlobalWorkBudget(t *testing.T) {
	password := []byte("budgeted-password")
	hash, err := HashPassword(password, DefaultParams())
	if err != nil {
		t.Fatal(err)
	}
	first, ok := TryAcquirePasswordWork()
	if !ok {
		t.Fatal("first work slot unavailable")
	}
	defer first()
	second, ok := TryAcquirePasswordWork()
	if !ok {
		t.Fatal("second work slot unavailable")
	}
	defer second()
	if _, err := HashPassword(password, DefaultParams()); !errors.Is(err, ErrPasswordWorkBusy) {
		t.Fatalf("HashPassword err=%v, want work budget error", err)
	}
	if _, err := VerifyPassword([]byte(hash), password); !errors.Is(err, ErrPasswordWorkBusy) {
		t.Fatalf("VerifyPassword err=%v, want work budget error", err)
	}
}

func TestVerify_WrongPassword(t *testing.T) {
	hash, _ := HashPassword([]byte("correct-password"), DefaultParams())
	ok, err := VerifyPassword([]byte(hash), []byte("wrong-password"))
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if ok {
		t.Fatal("expected wrong password to fail verification")
	}
}

func TestHashPassword_EmptyString(t *testing.T) {
	_, err := HashPassword(nil, DefaultParams())
	if err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestVerifyPassword_InvalidFormat(t *testing.T) {
	_, err := VerifyPassword([]byte("not-a-valid-hash"), []byte("password"))
	if err == nil {
		t.Fatal("expected error for invalid hash format")
	}
}

func TestHashPassword_DifferentHashes(t *testing.T) {
	// Two hashes of the same password should differ (different salt)
	h1, _ := HashPassword([]byte("same-password"), DefaultParams())
	h2, _ := HashPassword([]byte("same-password"), DefaultParams())
	if h1 == h2 {
		t.Fatal("expected different hashes for same password (different salts)")
	}
	// But both should verify
	ok1, _ := VerifyPassword([]byte(h1), []byte("same-password"))
	ok2, _ := VerifyPassword([]byte(h2), []byte("same-password"))
	if !ok1 || !ok2 {
		t.Fatal("both hashes should verify against the same password")
	}
}

func TestValidatePasswordHashRejectsMalformedOrResourceAmplifyingPHC(t *testing.T) {
	valid, err := HashPassword([]byte("correct-password"), DefaultParams())
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePasswordHash(valid); err != nil {
		t.Fatalf("valid hash rejected: %v", err)
	}
	for _, invalid := range []string{
		"$argon2id$v=19$m=999999999,t=3,p=2$YWJjZGVmZ2hpamtsbW5vcA$YWJjZGVmZ2hpamtsbW5vcA",
		"$argon2id$v=19$m=65536,t=3,p=99$YWJjZGVmZ2hpamtsbW5vcA$YWJjZGVmZ2hpamtsbW5vcA",
		"$argon2id$v=18$m=65536,t=3,p=2$YWJjZGVmZ2hpamtsbW5vcA$YWJjZGVmZ2hpamtsbW5vcA",
	} {
		if err := ValidatePasswordHash(invalid); err == nil {
			t.Fatalf("unsafe hash accepted: %q", invalid)
		}
	}
}
