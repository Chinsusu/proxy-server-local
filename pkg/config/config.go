package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Chinsusu/proxy-server-local/internal/domain"
	"github.com/Chinsusu/proxy-server-local/internal/secret"
	"github.com/Chinsusu/proxy-server-local/pkg/auth"
)

const (
	minJWTSecretBytes        = 32
	defaultJWTSecretPath     = "/etc/pgw/jwt_secret"
	defaultAdminPassHashPath = "/etc/pgw/admin_pass_hash"
	defaultUIProxyTokenPath  = "/etc/pgw/ui_proxy_token"
	defaultAPIAddr           = "127.0.0.1:8080"
)

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// API contains only values required by the private API listener. JWTSecret is
// loaded from a service-owned credential/file, never from an environment
// value, and is zeroed by the API process on shutdown.
type API struct {
	Addr          string
	JWTSecret     []byte
	AdminPassHash []byte
	UIProxyToken  []byte
	IPv6Policy    domain.IPv6Policy
}

type UI struct{ Addr string }
type Health struct{ Interval time.Duration }
type Agent struct{ Addr, WANIF, LANIF string }
type Fwd struct{ Addr string }

// loadSecretFile is replaceable only in package tests. Production always
// uses the no-follow, owner/mode-validated secret reader.
var loadSecretFile = secret.LoadTokenFile

// LoadAPI fails closed: the API is private by default and its signing key must
// come from the systemd credential named jwt_secret or a validated fallback
// file. PGW_JWT_SECRET and PGW_JWT_STRICT are deliberately unsupported.
func LoadAPI() (API, error) {
	if _, present := os.LookupEnv("PGW_JWT_SECRET"); present {
		return API{}, errors.New("PGW_JWT_SECRET is unsupported; use a service credential or secure key file")
	}
	if _, present := os.LookupEnv("PGW_JWT_STRICT"); present {
		return API{}, errors.New("PGW_JWT_STRICT is unsupported; JWT validation cannot be bypassed")
	}
	if _, present := os.LookupEnv("PGW_ADMIN_PASS"); present {
		return API{}, errors.New("PGW_ADMIN_PASS is unsupported; use the admin_pass_hash service credential")
	}
	if _, present := os.LookupEnv("PGW_ADMIN_PASS_HASH"); present {
		return API{}, errors.New("PGW_ADMIN_PASS_HASH is unsupported; use the admin_pass_hash service credential")
	}
	if _, present := os.LookupEnv("PGW_UI_PROXY_TOKEN"); present {
		return API{}, errors.New("PGW_UI_PROXY_TOKEN is unsupported; use the ui_proxy_token service credential")
	}
	ipv6Policy, err := LoadIPv6Policy()
	if err != nil {
		return API{}, err
	}
	addr := getenv("PGW_API_ADDR", defaultAPIAddr)
	if err := ValidatePrivateAPIAddr(addr); err != nil {
		return API{}, err
	}
	path, err := credentialPath("jwt_secret", "PGW_JWT_SECRET_FILE", defaultJWTSecretPath)
	if err != nil {
		return API{}, err
	}
	jwtSecret, err := loadSecretFile(path)
	if err != nil {
		return API{}, fmt.Errorf("load JWT signing key: %w", err)
	}
	if err := ValidateJWTSecret(jwtSecret); err != nil {
		zero(jwtSecret)
		return API{}, err
	}
	adminPath, err := credentialPath("admin_pass_hash", "PGW_ADMIN_PASS_HASH_FILE", defaultAdminPassHashPath)
	if err != nil {
		zero(jwtSecret)
		return API{}, err
	}
	adminPassHash, err := loadSecretFile(adminPath)
	if err != nil {
		zero(jwtSecret)
		return API{}, fmt.Errorf("load admin password hash: %w", err)
	}
	if err := auth.ValidatePasswordHash(string(adminPassHash)); err != nil {
		zero(jwtSecret)
		zero(adminPassHash)
		return API{}, errors.New("admin password hash is not a valid bounded Argon2id PHC value")
	}
	uiProxyPath, err := credentialPath("ui_proxy_token", "PGW_UI_PROXY_TOKEN_FILE", defaultUIProxyTokenPath)
	if err != nil {
		zero(jwtSecret)
		zero(adminPassHash)
		return API{}, err
	}
	uiProxyToken, err := loadSecretFile(uiProxyPath)
	if err != nil {
		zero(jwtSecret)
		zero(adminPassHash)
		return API{}, fmt.Errorf("load UI proxy token: %w", err)
	}
	if len(uiProxyToken) < minJWTSecretBytes {
		zero(jwtSecret)
		zero(adminPassHash)
		zero(uiProxyToken)
		return API{}, errors.New("UI proxy token must contain at least 32 bytes")
	}
	return API{Addr: addr, JWTSecret: jwtSecret, AdminPassHash: adminPassHash, UIProxyToken: uiProxyToken, IPv6Policy: ipv6Policy}, nil
}

// LoadIPv6Policy has no permissive fallback. PGW only supports the explicit
// deny contract until an IPv6 data plane is designed and independently gated.
func LoadIPv6Policy() (domain.IPv6Policy, error) {
	if value, present := os.LookupEnv("PGW_IPV6_POLICY"); present {
		return domain.NormalizeIPv6Policy(value)
	}
	return domain.IPv6PolicyDeny, nil
}

func credentialPath(credentialName, fallbackEnvironment, defaultPath string) (string, error) {
	if credentialsDirectory, present := os.LookupEnv("CREDENTIALS_DIRECTORY"); present {
		credentialsDirectory = strings.TrimSpace(credentialsDirectory)
		if credentialsDirectory == "" || !isAbsolutePath(credentialsDirectory) {
			return "", fmt.Errorf("CREDENTIALS_DIRECTORY is invalid for %s", credentialName)
		}
		// Credentials are a Linux/systemd deployment contract; path.Join keeps
		// the configured Unix path stable when tests run on another platform.
		return path.Join(credentialsDirectory, credentialName), nil
	}
	path := strings.TrimSpace(getenv(fallbackEnvironment, defaultPath))
	if path == "" || !isAbsolutePath(path) {
		return "", fmt.Errorf("%s must be an absolute path", fallbackEnvironment)
	}
	return path, nil
}

// isAbsolutePath accepts the Unix paths used by Linux deployments even when
// configuration tests are compiled on a non-Unix workstation. The production
// secret reader still fails closed on platforms without ACL validation.
func isAbsolutePath(value string) bool {
	return filepath.IsAbs(value) || path.IsAbs(value)
}

// ValidatePrivateAPIAddr prevents a plaintext API listener from being exposed
// directly. Browser traffic must terminate TLS at the UI reverse proxy and
// reach this listener over loopback.
func ValidatePrivateAPIAddr(addr string) error {
	return validateNumericLoopbackAddr(addr, "PGW_API_ADDR")
}

// ValidatePrivateAgentAddr prevents the privileged Agent trigger listener
// from being exposed outside the host. Its actual control plane remains UDS.
func ValidatePrivateAgentAddr(addr string) error {
	return validateNumericLoopbackAddr(addr, "PGW_AGENT_ADDR")
}

func validateNumericLoopbackAddr(addr, field string) error {
	host, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("%s must be an explicit loopback host:port", field)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%s must bind a numeric loopback address", field)
	}
	if numericPort, err := strconv.Atoi(port); err != nil || numericPort < 1 || numericPort > 65535 {
		return fmt.Errorf("%s has an invalid port", field)
	}
	return nil
}

func LoadUI() UI {
	return UI{Addr: getenv("PGW_UI_ADDR", ":8081")}
}
func LoadHealth() Health {
	iv := getenv("PGW_HEALTH_INTERVAL", "30s")
	d, _ := time.ParseDuration(iv)
	if d == 0 {
		d = 30 * time.Second
	}
	return Health{Interval: d}
}
func LoadAgent() Agent {
	return Agent{Addr: getenv("PGW_AGENT_ADDR", "127.0.0.1:9090"), WANIF: getenv("PGW_WAN_IFACE", "eth0"), LANIF: getenv("PGW_LAN_IFACE", "ens19")}
}
func LoadFwd() Fwd { return Fwd{Addr: getenv("PGW_FWD_ADDR", ":15000")} }

// ValidateJWTSecret does not log or terminate. Its caller is responsible for
// failing process startup, which keeps this function deterministic and makes
// a development bypass impossible.
func ValidateJWTSecret(value []byte) error {
	if len(value) < minJWTSecretBytes {
		return fmt.Errorf("JWT signing key must contain at least %d bytes", minJWTSecretBytes)
	}
	return nil
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
