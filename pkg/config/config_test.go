package config

import (
	"os"
	"testing"
)

func TestValidateJWTSecret_Default(t *testing.T) {
	os.Setenv("PGW_JWT_STRICT", "false") // avoid log.Fatal in test
	defer os.Unsetenv("PGW_JWT_STRICT")

	err := ValidateJWTSecret("dev-change-me")
	if err == nil {
		t.Fatal("expected error for default JWT secret")
	}
}

func TestValidateJWTSecret_TooShort(t *testing.T) {
	os.Setenv("PGW_JWT_STRICT", "false")
	defer os.Unsetenv("PGW_JWT_STRICT")

	err := ValidateJWTSecret("short")
	if err == nil {
		t.Fatal("expected error for short JWT secret")
	}
}

func TestValidateJWTSecret_Valid(t *testing.T) {
	os.Setenv("PGW_JWT_STRICT", "false")
	defer os.Unsetenv("PGW_JWT_STRICT")

	err := ValidateJWTSecret("a-very-long-secret-that-is-at-least-32-chars-long")
	if err != nil {
		t.Fatalf("expected no error for valid secret, got: %v", err)
	}
}

func TestLoadAPI_Defaults(t *testing.T) {
	// Clear env to test defaults
	os.Unsetenv("PGW_API_ADDR")
	os.Unsetenv("PGW_JWT_SECRET")

	cfg := LoadAPI()
	if cfg.Addr != ":8080" {
		t.Fatalf("expected default addr :8080, got %s", cfg.Addr)
	}
	if cfg.JWTSecret != defaultJWTSecret {
		t.Fatalf("expected default JWT secret %q, got %s", defaultJWTSecret, cfg.JWTSecret)
	}
}

func TestLoadHealth_Default(t *testing.T) {
	os.Unsetenv("PGW_HEALTH_INTERVAL")
	h := LoadHealth()
	if h.Interval.Seconds() != 30 {
		t.Fatalf("expected 30s interval, got %v", h.Interval)
	}
}

func TestLoadHealth_Custom(t *testing.T) {
	os.Setenv("PGW_HEALTH_INTERVAL", "10s")
	defer os.Unsetenv("PGW_HEALTH_INTERVAL")

	h := LoadHealth()
	if h.Interval.Seconds() != 10 {
		t.Fatalf("expected 10s interval, got %v", h.Interval)
	}
}
