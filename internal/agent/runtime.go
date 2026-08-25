package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Chinsusu/proxy-server-local/internal/domain"
)

const maxCredentialBytes = 4 << 10

var safeMappingID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

type Systemd interface {
	Start(context.Context, string) error
	Restart(context.Context, string) error
	Stop(context.Context, string) error
	State(context.Context, string) (activeState, subState string, err error)
}

type RuntimeConfig struct {
	Root          string
	RollbackRoot  string
	ListenHost    string
	PortStart     int
	PortEnd       int
	ReadyTimeout  time.Duration
	PollInterval  time.Duration
	Telemetry     *Telemetry
	skipOwnership bool
}

type RuntimeManager struct {
	config    RuntimeConfig
	systemd   Systemd
	telemetry *Telemetry
}

type forwarderConfig struct {
	Version        int    `json:"version"`
	MappingID      string `json:"mapping_id"`
	ListenAddress  string `json:"listen_address"`
	ProxyType      string `json:"proxy_type"`
	ProxyHost      string `json:"proxy_host"`
	ProxyPort      int    `json:"proxy_port"`
	MaxConnections int    `json:"max_connections,omitempty"`
	DialTimeout    string `json:"dial_timeout,omitempty"`
	IdleTimeout    string `json:"idle_timeout,omitempty"`
}

type restoreManifest struct {
	Version        int           `json:"version"`
	Nonce          string        `json:"nonce"`
	Port           int           `json:"port"`
	Old            RuntimeRecord `json:"old"`
	Next           RuntimeRecord `json:"next"`
	ConfigSHA256   string        `json:"config_sha256"`
	MetadataSHA256 string        `json:"metadata_sha256"`
	UsernameSHA256 string        `json:"username_sha256"`
	PasswordSHA256 string        `json:"password_sha256"`
}

func NewRuntimeManager(config RuntimeConfig, systemd Systemd) (*RuntimeManager, error) {
	if systemd == nil {
		return nil, fmt.Errorf("agent: systemd adapter is required")
	}
	if !filepath.IsAbs(config.Root) || filepath.Clean(config.Root) != config.Root || config.Root == filepath.VolumeName(config.Root)+string(filepath.Separator) {
		return nil, fmt.Errorf("agent: unsafe runtime root")
	}
	if config.RollbackRoot == "" {
		config.RollbackRoot = filepath.Join(filepath.Dir(config.Root), "agent-rollback")
	}
	if !filepath.IsAbs(config.RollbackRoot) || filepath.Clean(config.RollbackRoot) != config.RollbackRoot || config.RollbackRoot == filepath.VolumeName(config.RollbackRoot)+string(filepath.Separator) {
		return nil, fmt.Errorf("agent: unsafe rollback root")
	}
	if config.RollbackRoot == config.Root || strings.HasPrefix(config.RollbackRoot+string(filepath.Separator), config.Root+string(filepath.Separator)) {
		return nil, fmt.Errorf("agent: rollback root must not be inside forwarder runtime root")
	}
	if address, err := netip.ParseAddr(config.ListenHost); err != nil || !address.Is4() {
		return nil, fmt.Errorf("agent: forwarder listen host must be IPv4")
	}
	if config.PortStart < 1 || config.PortEnd > 65535 || config.PortStart > config.PortEnd {
		return nil, fmt.Errorf("agent: invalid runtime port range")
	}
	if config.ReadyTimeout <= 0 {
		config.ReadyTimeout = 15 * time.Second
	}
	if config.PollInterval <= 0 {
		config.PollInterval = 200 * time.Millisecond
	}
	return &RuntimeManager{config: config, systemd: systemd, telemetry: config.Telemetry}, nil
}

func (m *RuntimeManager) Ready(ctx context.Context, port int) (bool, error) {
	unit, err := m.unit(port)
	if err != nil {
		return false, err
	}
	active, sub, err := m.systemd.State(ctx, unit)
	if err != nil {
		return false, err
	}
	return active == "active" && sub == "running", nil
}

func (m *RuntimeManager) Matches(_ context.Context, record RuntimeRecord) (bool, error) {
	if _, err := m.unit(record.Port); err != nil {
		return false, err
	}
	data, err := readRegularBounded(filepath.Join(m.config.Root, strconv.Itoa(record.Port), "runtime.meta.json"), 16<<10)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var stored RuntimeRecord
	if err := decoder.Decode(&stored); err != nil {
		return false, err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return false, err
	}
	return stored == record, nil
}

func (m *RuntimeManager) Activate(ctx context.Context, mapping domain.AgentMapping, credential domain.AgentCredential, replace bool) error {
	m.runtimeLog(ctx, "info", "forwarder_prepare_started", mapping, "prepare", "unknown")
	prepared := false
	defer func() {
		if !prepared {
			m.runtimeObserve("prepare", "failure")
		}
	}()
	if err := domain.ValidateAgentMapping(mapping); err != nil {
		return fmt.Errorf("agent: invalid forwarder mapping: %w", err)
	}
	if err := domain.ValidateAgentCredential(mapping, credential); err != nil {
		return fmt.Errorf("agent: invalid forwarder credential: %w", err)
	}
	unit, err := m.unit(mapping.LocalRedirectPort)
	if err != nil {
		return err
	}
	config := forwarderConfig{
		Version: 1, MappingID: mapping.ID,
		ListenAddress: net.JoinHostPort(m.config.ListenHost, strconv.Itoa(mapping.LocalRedirectPort)),
		ProxyType:     string(mapping.ProxyType), ProxyHost: mapping.ProxyHost, ProxyPort: mapping.ProxyPort,
	}
	configBytes, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("agent: encode forwarder config: %w", err)
	}
	configBytes = append(configBytes, '\n')
	recordBytes, err := json.Marshal(runtimeRecord(mapping))
	if err != nil {
		return fmt.Errorf("agent: encode forwarder runtime metadata: %w", err)
	}
	recordBytes = append(recordBytes, '\n')
	directory, err := m.prepareDirectory(mapping.LocalRedirectPort)
	if err != nil {
		return err
	}
	failCleanup := true
	defer func() {
		if failCleanup {
			_ = m.removeRuntime(mapping.LocalRedirectPort)
		}
	}()
	credentialsDirectory := filepath.Join(directory, "credentials")
	username := []byte(credential.Username)
	password := credential.Password
	if !credential.AuthConfigured {
		username = nil
		password = nil
	}
	if err := publishRuntimeFile(credentialsDirectory, "proxy_username", username, 0o600); err != nil {
		return fmt.Errorf("agent: publish username credential: %w", err)
	}
	if err := publishRuntimeFile(credentialsDirectory, "proxy_password", password, 0o600); err != nil {
		return fmt.Errorf("agent: publish password credential: %w", err)
	}
	if err := publishRuntimeFile(directory, "forwarder.json", configBytes, 0o640); err != nil {
		return fmt.Errorf("agent: publish forwarder config: %w", err)
	}
	if err := publishRuntimeFile(directory, "runtime.meta.json", recordBytes, 0o600); err != nil {
		return fmt.Errorf("agent: publish forwarder runtime metadata: %w", err)
	}
	if err := secureForwarderReadable(filepath.Join(directory, "forwarder.json"), false, m.config.skipOwnership); err != nil {
		return err
	}
	prepared = true
	m.runtimeObserve("prepare", "success")
	if replace {
		err = m.systemd.Restart(ctx, unit)
	} else {
		err = m.systemd.Start(ctx, unit)
	}
	if err != nil {
		m.runtimeObserve(operationForReplace(replace), "failure")
		return fmt.Errorf("agent: start forwarder unit: %w", err)
	}
	m.runtimeObserve(operationForReplace(replace), "success")

	if err := m.waitReady(ctx, mapping.LocalRedirectPort); err != nil {
		m.runtimeObserve("ready", "failure")
		stopContext, stopCancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		_ = m.systemd.Stop(stopContext, unit)
		stopCancel()
		return err
	}
	m.runtimeObserve("ready", "success")
	m.runtimeLog(ctx, "info", "forwarder_ready", mapping, "ready", "success")
	failCleanup = false
	return nil
}

func (m *RuntimeManager) Capture(ctx context.Context, old, next RuntimeRecord) (*RestorePoint, error) {
	if old.Port != next.Port || old.Port < m.config.PortStart || old.Port > m.config.PortEnd {
		return nil, fmt.Errorf("agent: invalid same-port restore transition")
	}
	ready, err := m.Ready(ctx, old.Port)
	if err != nil || !ready {
		return nil, fmt.Errorf("agent: previous forwarder is not ready for capture")
	}
	matches, err := m.Matches(ctx, old)
	if err != nil || !matches {
		return nil, fmt.Errorf("agent: previous forwarder runtime metadata does not match LKG")
	}
	if err := m.ensureRollbackRoot(); err != nil {
		return nil, err
	}
	stage, err := secureMkdirTemp(m.config.RollbackRoot, ".restore-", 0o700)
	if err != nil {
		return nil, fmt.Errorf("agent: create runtime restore point: %w", err)
	}
	point := &RestorePoint{port: old.Port, directory: stage, old: old, next: next}
	ok := false
	defer func() {
		if !ok {
			_ = m.Discard(point)
		}
	}()
	source := filepath.Join(m.config.Root, strconv.Itoa(old.Port))
	configBytes, err := readRegularBounded(filepath.Join(source, "forwarder.json"), 64<<10)
	if err != nil {
		return nil, fmt.Errorf("agent: capture forwarder config: %w", err)
	}
	defer zero(configBytes)
	if err := publishRuntimeFile(stage, "forwarder.json", configBytes, 0o600); err != nil {
		return nil, err
	}
	metadataBytes, err := readRegularBounded(filepath.Join(source, "runtime.meta.json"), 16<<10)
	if err != nil {
		return nil, fmt.Errorf("agent: capture forwarder runtime metadata: %w", err)
	}
	defer zero(metadataBytes)
	if err := publishRuntimeFile(stage, "runtime.meta.json", metadataBytes, 0o600); err != nil {
		return nil, err
	}
	for _, name := range []string{"proxy_username", "proxy_password"} {
		material, err := readRegularBounded(filepath.Join(source, "credentials", name), maxCredentialBytes)
		if err != nil {
			return nil, fmt.Errorf("agent: capture forwarder credential: %w", err)
		}
		if err := publishRuntimeFile(stage, name, material, 0o600); err != nil {
			zero(material)
			return nil, err
		}
		zero(material)
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("agent: generate restore-point nonce: %w", err)
	}
	manifest := restoreManifest{
		Version: 1, Nonce: hex.EncodeToString(nonce), Port: old.Port, Old: old, Next: next,
		ConfigSHA256:   bytesSHA256(configBytes),
		MetadataSHA256: bytesSHA256(metadataBytes),
	}
	zero(nonce)
	for name, destination := range map[string]*string{
		"proxy_username": &manifest.UsernameSHA256,
		"proxy_password": &manifest.PasswordSHA256,
	} {
		material, err := readRegularBounded(filepath.Join(stage, name), maxCredentialBytes)
		if err != nil {
			return nil, err
		}
		*destination = bytesSHA256(material)
		zero(material)
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("agent: encode restore-point manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := publishRuntimeFile(stage, "manifest.json", manifestBytes, 0o600); err != nil {
		return nil, err
	}
	point.integrity = bytesSHA256(manifestBytes)
	ok = true
	return point, nil
}

func (m *RuntimeManager) Restore(ctx context.Context, point *RestorePoint) error {
	if err := m.validateRestorePoint(point); err != nil {
		return err
	}
	directory, err := m.prepareDirectory(point.port)
	if err != nil {
		return err
	}
	configBytes, err := readRegularBounded(filepath.Join(point.directory, "forwarder.json"), 64<<10)
	if err != nil {
		return fmt.Errorf("agent: read restore config: %w", err)
	}
	defer zero(configBytes)
	credentialsDirectory := filepath.Join(directory, "credentials")
	for _, name := range []string{"proxy_username", "proxy_password"} {
		material, err := readRegularBounded(filepath.Join(point.directory, name), maxCredentialBytes)
		if err != nil {
			return fmt.Errorf("agent: read restore credential: %w", err)
		}
		if err := publishRuntimeFile(credentialsDirectory, name, material, 0o600); err != nil {
			zero(material)
			return err
		}
		zero(material)
	}
	if err := publishRuntimeFile(directory, "forwarder.json", configBytes, 0o640); err != nil {
		return err
	}
	metadataBytes, err := readRegularBounded(filepath.Join(point.directory, "runtime.meta.json"), 16<<10)
	if err != nil {
		return fmt.Errorf("agent: read restore runtime metadata: %w", err)
	}
	defer zero(metadataBytes)
	if err := publishRuntimeFile(directory, "runtime.meta.json", metadataBytes, 0o600); err != nil {
		return err
	}
	if err := secureForwarderReadable(filepath.Join(directory, "forwarder.json"), false, m.config.skipOwnership); err != nil {
		return err
	}
	unit, _ := m.unit(point.port)
	if err := m.systemd.Restart(ctx, unit); err != nil {
		return fmt.Errorf("agent: restart restored forwarder: %w", err)
	}
	if err := m.waitReady(ctx, point.port); err != nil {
		return fmt.Errorf("agent: restored forwarder not ready: %w", err)
	}
	return m.Discard(point)
}

func (m *RuntimeManager) Discard(point *RestorePoint) error {
	if err := m.validateRestoreLocation(point); err != nil {
		return err
	}
	for _, name := range []string{"proxy_username", "proxy_password"} {
		_ = wipeRuntimeFile(filepath.Join(point.directory, name))
	}
	if err := secureRemoveTree(point.directory); err != nil {
		return fmt.Errorf("agent: discard runtime restore point: %w", err)
	}
	return nil
}

func (m *RuntimeManager) waitReady(ctx context.Context, port int) error {
	readyCtx, cancel := context.WithTimeout(ctx, m.config.ReadyTimeout)
	defer cancel()
	ticker := time.NewTicker(m.config.PollInterval)
	defer ticker.Stop()
	for {
		ready, err := m.Ready(readyCtx, port)
		if err == nil && ready {
			return nil
		}
		select {
		case <-readyCtx.Done():
			return fmt.Errorf("agent: forwarder readiness timeout: %w", readyCtx.Err())
		case <-ticker.C:
		}
	}
}

func (m *RuntimeManager) ensureRollbackRoot() error {
	if err := secureEnsureDirectory(m.config.RollbackRoot, 0o700); err != nil {
		return fmt.Errorf("agent: create rollback root: %w", err)
	}
	return nil
}

func (m *RuntimeManager) validateRestorePoint(point *RestorePoint) error {
	if err := m.validateRestoreLocation(point); err != nil {
		return err
	}
	if !isSHA256(point.integrity) {
		return fmt.Errorf("agent: invalid runtime restore-point integrity")
	}
	manifestBytes, err := readRegularBounded(filepath.Join(point.directory, "manifest.json"), 64<<10)
	if err != nil {
		return fmt.Errorf("agent: read runtime restore-point manifest: %w", err)
	}
	if bytesSHA256(manifestBytes) != point.integrity {
		return fmt.Errorf("agent: runtime restore-point manifest integrity mismatch")
	}
	decoder := json.NewDecoder(strings.NewReader(string(manifestBytes)))
	decoder.DisallowUnknownFields()
	var manifest restoreManifest
	if err := decoder.Decode(&manifest); err != nil {
		return fmt.Errorf("agent: decode runtime restore-point manifest: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return fmt.Errorf("agent: decode runtime restore-point manifest: %w", err)
	}
	_, nonceErr := hex.DecodeString(manifest.Nonce)
	if manifest.Version != 1 || len(manifest.Nonce) != 64 || nonceErr != nil || manifest.Port != point.port || manifest.Old != point.old || manifest.Next != point.next {
		return fmt.Errorf("agent: runtime restore-point binding mismatch")
	}
	for name, want := range map[string]string{
		"forwarder.json":    manifest.ConfigSHA256,
		"runtime.meta.json": manifest.MetadataSHA256,
		"proxy_username":    manifest.UsernameSHA256,
		"proxy_password":    manifest.PasswordSHA256,
	} {
		path := filepath.Join(point.directory, name)
		limit := int64(maxCredentialBytes)
		if name == "forwarder.json" || name == "runtime.meta.json" {
			limit = 64 << 10
		}
		material, err := readRegularBounded(path, limit)
		if err != nil {
			return fmt.Errorf("agent: validate restore-point file %s: %w", name, err)
		}
		got := bytesSHA256(material)
		zero(material)
		if !isSHA256(want) || got != want {
			return fmt.Errorf("agent: runtime restore-point file integrity mismatch")
		}
	}
	return nil
}

func (m *RuntimeManager) validateRestoreLocation(point *RestorePoint) error {
	if point == nil || point.port < m.config.PortStart || point.port > m.config.PortEnd {
		return fmt.Errorf("agent: invalid runtime restore point")
	}
	directory := filepath.Clean(point.directory)
	if filepath.Dir(directory) != m.config.RollbackRoot || directory == m.config.RollbackRoot {
		return fmt.Errorf("agent: unsafe runtime restore point")
	}
	return secureValidateDirectory(directory)
}

func (m *RuntimeManager) CleanupOrphans(_ context.Context) error {
	if err := secureRemoveChildren(m.config.RollbackRoot, ".restore-"); err != nil {
		return fmt.Errorf("agent: remove orphan restore points: %w", err)
	}
	return nil
}

func bytesSHA256(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func wipeRuntimeFile(path string) error {
	return secureWipeFile(path)
}

func (m *RuntimeManager) Stop(ctx context.Context, port int) error {
	unit, err := m.unit(port)
	if err != nil {
		return err
	}
	if err := m.systemd.Stop(ctx, unit); err != nil {
		m.runtimeObserve("stop", "failure")
		return fmt.Errorf("agent: stop forwarder unit: %w", err)
	}
	err = m.removeRuntime(port)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	m.runtimeObserve("stop", outcome)
	return err
}

func operationForReplace(replace bool) string {
	if replace {
		return "restart"
	}
	return "start"
}
func (m *RuntimeManager) runtimeObserve(operation, outcome string) {
	if m.telemetry != nil {
		m.telemetry.Metrics.ObserveForwarder(operation, outcome)
	}
}
func (m *RuntimeManager) runtimeLog(ctx context.Context, level, event string, mapping domain.AgentMapping, state, outcome string) {
	if m.telemetry != nil {
		m.telemetry.Log(ctx, level, event, map[string]any{"mapping_id": mapping.ID, "proxy_id": mapping.ProxyID, "state": state, "outcome": outcome})
	}
}

func (m *RuntimeManager) prepareDirectory(port int) (string, error) {
	if _, err := m.unit(port); err != nil {
		return "", err
	}
	if err := secureEnsureDirectory(m.config.Root, 0o750); err != nil {
		return "", fmt.Errorf("agent: create runtime root: %w", err)
	}
	if err := secureForwarderReadable(m.config.Root, true, m.config.skipOwnership); err != nil {
		return "", err
	}
	directory := filepath.Join(m.config.Root, strconv.Itoa(port))
	credentials := filepath.Join(directory, "credentials")
	if err := secureEnsureDirectory(directory, 0o750); err != nil {
		return "", fmt.Errorf("agent: create runtime directory: %w", err)
	}
	if err := secureEnsureDirectory(credentials, 0o700); err != nil {
		return "", fmt.Errorf("agent: create runtime directory: %w", err)
	}
	if err := secureForwarderReadable(directory, true, m.config.skipOwnership); err != nil {
		return "", err
	}
	return directory, nil
}

func (m *RuntimeManager) removeRuntime(port int) error {
	if _, err := m.unit(port); err != nil {
		return err
	}
	target := filepath.Clean(filepath.Join(m.config.Root, strconv.Itoa(port)))
	if filepath.Dir(target) != m.config.Root || target == m.config.Root {
		return fmt.Errorf("agent: unsafe runtime cleanup target")
	}
	if err := secureValidateDirectory(target); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var scrubErrors []error
	for _, name := range []string{"proxy_username", "proxy_password"} {
		path := filepath.Join(target, "credentials", name)
		if err := wipeRuntimeFile(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			scrubErrors = append(scrubErrors, fmt.Errorf("agent: scrub runtime credential %s: %w", name, err))
		}
	}
	if err := secureRemoveTree(target); err != nil {
		return fmt.Errorf("agent: remove runtime directory: %w", err)
	}
	return errors.Join(scrubErrors...)
}

func (m *RuntimeManager) unit(port int) (string, error) {
	if port < m.config.PortStart || port > m.config.PortEnd {
		return "", fmt.Errorf("agent: forwarder port outside protected range")
	}
	return "pgw-fwd@" + strconv.Itoa(port) + ".service", nil
}

func publishRuntimeFile(directory, name string, content []byte, mode os.FileMode) error {
	if !safeLeaf(name) {
		return fmt.Errorf("agent: unsafe runtime filename")
	}
	return secureWriteFileAtomic(directory, name, content, mode)
}
