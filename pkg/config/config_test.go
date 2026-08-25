package config

import (
	"bytes"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/Chinsusu/proxy-server-local/pkg/auth"
)

func withSecretLoader(t *testing.T, loader func(string) ([]byte, error)) {
	t.Helper()
	original := loadSecretFile
	loadSecretFile = loader
	t.Cleanup(func() { loadSecretFile = original })
}

func validAdminPassHash(t *testing.T) []byte {
	t.Helper()
	hash, err := auth.HashPassword([]byte("configuration-test-password"), auth.DefaultParams())
	if err != nil {
		t.Fatal(err)
	}
	return []byte(hash)
}

func credentialLoader(t *testing.T) func(string) ([]byte, error) {
	t.Helper()
	hash := validAdminPassHash(t)
	t.Cleanup(func() { zero(hash) })
	return func(path string) ([]byte, error) {
		if strings.HasSuffix(strings.ReplaceAll(path, "\\", "/"), "/admin_pass_hash") {
			return append([]byte(nil), hash...), nil
		}
		return bytes.Repeat([]byte{9}, minJWTSecretBytes), nil
	}
}

func clearJWTEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{"PGW_JWT_SECRET", "PGW_JWT_STRICT", "PGW_ADMIN_PASS", "PGW_ADMIN_PASS_HASH", "PGW_UI_PROXY_TOKEN", "CREDENTIALS_DIRECTORY", "PGW_JWT_SECRET_FILE", "PGW_ADMIN_PASS_HASH_FILE", "PGW_UI_PROXY_TOKEN_FILE", "PGW_API_ADDR", "PGW_IPV6_POLICY"} {
		value, present := os.LookupEnv(key)
		_ = os.Unsetenv(key)
		t.Cleanup(func() {
			if present {
				_ = os.Setenv(key, value)
			} else {
				_ = os.Unsetenv(key)
			}
		})
	}
}

func TestLoadAPIUsesSystemdCredentialAndPrivateDefault(t *testing.T) {
	clearJWTEnvironment(t)
	if err := os.Setenv("CREDENTIALS_DIRECTORY", "/run/credentials/pgw-api.service"); err != nil {
		t.Fatal(err)
	}
	var requestedPaths []string
	loader := credentialLoader(t)
	withSecretLoader(t, func(path string) ([]byte, error) {
		requestedPaths = append(requestedPaths, path)
		return loader(path)
	})
	cfg, err := LoadAPI()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != defaultAPIAddr {
		t.Fatalf("addr=%q", cfg.Addr)
	}
	if cfg.IPv6Policy != "deny" {
		t.Fatalf("ipv6_policy=%q", cfg.IPv6Policy)
	}
	if len(cfg.JWTSecret) != minJWTSecretBytes || len(cfg.AdminPassHash) == 0 || len(cfg.UIProxyToken) != minJWTSecretBytes {
		t.Fatalf("secret_length=%d hash_length=%d proxy_token_length=%d", len(cfg.JWTSecret), len(cfg.AdminPassHash), len(cfg.UIProxyToken))
	}
	wantPaths := []string{
		"/run/credentials/pgw-api.service/jwt_secret",
		"/run/credentials/pgw-api.service/admin_pass_hash",
		"/run/credentials/pgw-api.service/ui_proxy_token",
	}
	if !reflect.DeepEqual(requestedPaths, wantPaths) {
		t.Fatalf("paths=%q want=%q", requestedPaths, wantPaths)
	}
}

func TestLoadIPv6PolicyRejectsPermissiveAndUnknownValues(t *testing.T) {
	for _, value := range []string{"allow", "auto", "", "DENY"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("PGW_IPV6_POLICY", value)
			if _, err := LoadIPv6Policy(); err == nil {
				t.Fatalf("unsafe IPv6 policy %q accepted", value)
			}
		})
	}
}

func TestLoadAPIFailsClosedForEnvironmentSecretOrStrictBypass(t *testing.T) {
	for _, value := range []struct{ key, value string }{{"PGW_JWT_SECRET", "not-allowed"}, {"PGW_JWT_STRICT", "false"}, {"PGW_ADMIN_PASS", "not-allowed"}, {"PGW_ADMIN_PASS_HASH", "not-allowed"}, {"PGW_UI_PROXY_TOKEN", "not-allowed"}} {
		t.Run(value.key, func(t *testing.T) {
			clearJWTEnvironment(t)
			if err := os.Setenv(value.key, value.value); err != nil {
				t.Fatal(err)
			}
			withSecretLoader(t, credentialLoader(t))
			if _, err := LoadAPI(); err == nil {
				t.Fatal("insecure environment configuration was accepted")
			}
		})
	}
}

func TestLoadAPIFailsForSecretSourceAndInvalidKey(t *testing.T) {
	clearJWTEnvironment(t)
	withSecretLoader(t, func(string) ([]byte, error) { return nil, errors.New("unsafe mode") })
	if _, err := LoadAPI(); err == nil {
		t.Fatal("unsafe source was accepted")
	}
	withSecretLoader(t, func(path string) ([]byte, error) {
		if strings.HasSuffix(path, "admin_pass_hash") {
			return validAdminPassHash(t), nil
		}
		return []byte("too-short"), nil
	})
	if _, err := LoadAPI(); err == nil {
		t.Fatal("short signing key was accepted")
	}
}

func TestLoadAPIFailsForInvalidAdminPasswordHash(t *testing.T) {
	clearJWTEnvironment(t)
	withSecretLoader(t, func(path string) ([]byte, error) {
		if strings.HasSuffix(path, "admin_pass_hash") {
			return []byte("not-an-argon2id-hash"), nil
		}
		return bytes.Repeat([]byte{1}, minJWTSecretBytes), nil
	})
	if _, err := LoadAPI(); err == nil {
		t.Fatal("invalid admin password hash was accepted")
	}
}

func TestValidatePrivateAPIAddr(t *testing.T) {
	for _, address := range []string{"127.0.0.1:8080", "[::1]:8080"} {
		if err := ValidatePrivateAPIAddr(address); err != nil {
			t.Fatalf("loopback address %q rejected: %v", address, err)
		}
	}
	for _, address := range []string{":8080", "0.0.0.0:8080", "192.168.2.1:8080", "localhost:8080", "127.0.0.1:0"} {
		if err := ValidatePrivateAPIAddr(address); err == nil {
			t.Fatalf("non-private address %q accepted", address)
		}
	}
}

func TestValidatePrivateAgentAddr(t *testing.T) {
	for _, address := range []string{"127.0.0.1:9090", "[::1]:9090"} {
		if err := ValidatePrivateAgentAddr(address); err != nil {
			t.Fatalf("loopback address %q rejected: %v", address, err)
		}
	}
	for _, address := range []string{":9090", "0.0.0.0:9090", "192.168.2.1:9090", "localhost:9090"} {
		if err := ValidatePrivateAgentAddr(address); err == nil {
			t.Fatalf("public address %q accepted", address)
		}
	}
}

func TestLoadHealthDefaults(t *testing.T) {
	value, present := os.LookupEnv("PGW_HEALTH_INTERVAL")
	_ = os.Unsetenv("PGW_HEALTH_INTERVAL")
	t.Cleanup(func() {
		if present {
			_ = os.Setenv("PGW_HEALTH_INTERVAL", value)
		}
	})
	if got := LoadHealth().Interval; got.Seconds() != 30 {
		t.Fatalf("interval=%v", got)
	}
}
