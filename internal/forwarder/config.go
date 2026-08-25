// Package forwarder implements the per-port transparent PGW forwarder.
//
// A forwarder deliberately has no API client.  The privileged agent writes a
// non-secret, per-port runtime configuration and systemd injects credentials
// through its credential API.  Keeping that boundary here prevents an API
// response, environment variable, command line or log record from becoming a
// secret transport.
package forwarder

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxConfigBytes     = 64 << 10
	maxCredentialBytes = 4 << 10
)

// Config is intentionally limited to non-secret forwarder state.  Credentials
// are always loaded from CREDENTIALS_DIRECTORY using ReadCredentials.
type Config struct {
	Version        int    `json:"version"`
	MappingID      string `json:"mapping_id"`
	ListenAddress  string `json:"listen_address"`
	ProxyType      string `json:"proxy_type"`
	ProxyHost      string `json:"proxy_host"`
	ProxyPort      int    `json:"proxy_port"`
	MaxConnections int    `json:"max_connections,omitempty"`
	DialTimeout    string `json:"dial_timeout,omitempty"`
	IdleTimeout    string `json:"idle_timeout,omitempty"`
	DrainTimeout   string `json:"drain_timeout,omitempty"`
}

// Credentials is held only for the lifetime of the forwarder process.  It has
// no JSON representation to avoid accidental serialization.
type Credentials struct {
	Username   []byte
	Password   []byte
	Configured bool
}

// Wipe erases mutable credential buffers owned by this value. It is safe to
// call more than once. Callers transfer ownership to NewServer on success.
func (c *Credentials) Wipe() {
	wipe(c.Username)
	wipe(c.Password)
	c.Username = nil
	c.Password = nil
	c.Configured = false
}

// RuntimeConfig is validated and parsed exactly once before the listener is
// opened. Durations are kept out of Config so malformed values cannot reach a
// running data plane.
type RuntimeConfig struct {
	Config
	DialTimeout  time.Duration
	IdleTimeout  time.Duration
	DrainTimeout time.Duration
}

func ReadConfig(path string) (RuntimeConfig, error) {
	if path == "" || !filepath.IsAbs(path) {
		return RuntimeConfig{}, errors.New("forwarder config path must be absolute")
	}
	f, info, err := openSafeRead(path)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("read forwarder config: %w", err)
	}
	defer f.Close()
	if !info.Mode().IsRegular() {
		return RuntimeConfig{}, errors.New("forwarder config must be a regular file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return RuntimeConfig{}, errors.New("forwarder config must not be group or world writable")
	}
	b, err := readBounded(f, maxConfigBytes)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("read forwarder config: %w", err)
	}
	defer wipe(b)
	if err := rejectDuplicateJSONKeys(b); err != nil {
		return RuntimeConfig{}, fmt.Errorf("decode forwarder config: %w", err)
	}

	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return RuntimeConfig{}, fmt.Errorf("decode forwarder config: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return RuntimeConfig{}, errors.New("forwarder config must contain one JSON value")
	}
	if err := cfg.Validate(); err != nil {
		return RuntimeConfig{}, err
	}
	runtime := RuntimeConfig{Config: cfg}
	if runtime.DialTimeout, err = parseDuration(cfg.DialTimeout, 5*time.Second); err != nil {
		return RuntimeConfig{}, fmt.Errorf("invalid dial_timeout: %w", err)
	}
	if runtime.IdleTimeout, err = parseDuration(cfg.IdleTimeout, 30*time.Minute); err != nil {
		return RuntimeConfig{}, fmt.Errorf("invalid idle_timeout: %w", err)
	}
	if runtime.DrainTimeout, err = parseDuration(cfg.DrainTimeout, 30*time.Second); err != nil {
		return RuntimeConfig{}, fmt.Errorf("invalid drain_timeout: %w", err)
	}
	return runtime, nil
}

func (cfg Config) Validate() error {
	if cfg.Version != 1 {
		return errors.New("unsupported forwarder config version")
	}
	if !safeIdentifier(cfg.MappingID) {
		return errors.New("invalid mapping_id")
	}
	host, portText, err := net.SplitHostPort(cfg.ListenAddress)
	if err != nil || host == "" {
		return errors.New("listen_address must be an explicit host:port")
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() {
		return errors.New("listen_address must use a concrete IP address")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("listen_address has invalid port")
	}
	if cfg.ProxyType != "http" && cfg.ProxyType != "socks5" {
		return errors.New("unsupported proxy_type")
	}
	if !safeEndpointHost(cfg.ProxyHost) {
		return errors.New("invalid proxy_host")
	}
	if cfg.ProxyPort < 1 || cfg.ProxyPort > 65535 {
		return errors.New("invalid proxy_port")
	}
	if cfg.MaxConnections < 0 || cfg.MaxConnections > 65536 {
		return errors.New("invalid max_connections")
	}
	return nil
}

func parseDuration(value string, fallback time.Duration) (time.Duration, error) {
	if value == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil || d <= 0 {
		return 0, errors.New("must be a positive duration")
	}
	return d, nil
}

// ReadCredentials opens each systemd credential exactly once and returns owned
// mutable buffers. The caller must transfer ownership to NewServer or call
// Credentials.Wipe on every error path; callers must never log or serialize
// the returned bytes.
func ReadCredentials(directory string) (Credentials, error) {
	// A direct development invocation and a systemd unit with no supplied
	// credentials are both valid no-auth configurations. No fallback path is
	// consulted: credentials are accepted only through systemd's directory.
	if directory == "" {
		return Credentials{}, nil
	}
	if !filepath.IsAbs(directory) {
		return Credentials{}, errors.New("credentials directory must be absolute")
	}
	directoryInfo, err := os.Lstat(directory)
	if err != nil || directoryInfo.Mode()&os.ModeSymlink != 0 || !directoryInfo.IsDir() {
		return Credentials{}, errors.New("credentials directory is unavailable")
	}
	username, usernamePresent, err := readOptionalCredential(filepath.Join(directory, "proxy_username"))
	if err != nil {
		return Credentials{}, errors.New("read proxy username credential")
	}
	password, passwordPresent, err := readOptionalCredential(filepath.Join(directory, "proxy_password"))
	if err != nil {
		wipe(username)
		return Credentials{}, errors.New("read proxy password credential")
	}
	if usernamePresent != passwordPresent {
		wipe(username)
		wipe(password)
		return Credentials{}, errors.New("proxy credentials must provide username and password together")
	}
	if !usernamePresent {
		wipe(username)
		wipe(password)
		return Credentials{}, nil
	}
	return Credentials{Username: username, Password: password, Configured: len(username) != 0 || len(password) != 0}, nil
}

func readOptionalCredential(path string) ([]byte, bool, error) {
	f, info, err := openSafeRead(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, errors.New("credential is unavailable")
	}
	defer f.Close()
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return nil, false, errors.New("credential is unavailable")
	}
	b, err := readBounded(f, maxCredentialBytes)
	if err != nil {
		return nil, false, errors.New("credential is invalid")
	}
	if bytes.IndexByte(b, 0) >= 0 {
		wipe(b)
		return nil, false, errors.New("credential is invalid")
	}
	// Credentials are opaque byte sequences. In particular, trimming a trailing
	// newline silently changes a valid password and would make authentication
	// differ from the encrypted value retrieved by the Agent.
	return b, true, nil
}

func readBounded(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		wipe(b)
		return nil, errors.New("file exceeds size limit")
	}
	return b, nil
}

var (
	wipeHookMu sync.Mutex
	wipeHook   func(int)
)

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	wipeHookMu.Lock()
	hook := wipeHook
	wipeHookMu.Unlock()
	if hook != nil {
		hook(len(b))
	}
}

// setWipeHookForTest exposes only buffer lengths to tests. It deliberately
// cannot observe credential bytes.
func setWipeHookForTest(hook func(int)) func() {
	wipeHookMu.Lock()
	previous := wipeHook
	wipeHook = hook
	wipeHookMu.Unlock()
	return func() {
		wipeHookMu.Lock()
		wipeHook = previous
		wipeHookMu.Unlock()
	}
}

// encoding/json accepts duplicate object keys and silently keeps the last
// value. Runtime policy must not have that ambiguity, even for nested values.
func rejectDuplicateJSONKeys(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("forwarder config must contain one JSON value")
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key must be a string")
			}
			if _, exists := seen[key]; exists {
				return errors.New("duplicate JSON object key")
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func safeIdentifier(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func safeEndpointHost(value string) bool {
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "\x00\r\n\t /\\@") {
		return false
	}
	return true
}
