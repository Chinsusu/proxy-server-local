package sqlite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Chinsusu/proxy-server-local/internal/domain"
)

const maxLegacyStateBytes = 32 << 20
const maxLegacyRecords = 10000
const maxLegacyFieldBytes = 4096
const maxLegacyJSONTokens = 200000

type ImportOptions struct {
	DryRun bool
	Actor  string
}

type ImportReport struct {
	Checksum        string   `json:"checksum"`
	DryRun          bool     `json:"dry_run"`
	AlreadyImported bool     `json:"already_imported"`
	Proxies         int      `json:"proxies"`
	Clients         int      `json:"clients"`
	Mappings        int      `json:"mappings"`
	Duplicates      []string `json:"duplicates,omitempty"`
	Warnings        []string `json:"warnings,omitempty"`
}

type ImportConflictError struct {
	Duplicates []string
}

func (e *ImportConflictError) Error() string {
	return "legacy state import conflicts with existing data: " + strings.Join(e.Duplicates, ", ")
}

// ImportState imports the v1 JSON file only after strict decoding and full
// semantic validation. It does not activate imported mappings: old runtime
// state is not evidence that a newly upgraded fail-close data plane is ready.
// Operators explicitly activate drafts after the Agent has verified them.
func (r *Repository) ImportState(ctx context.Context, input io.Reader, options ImportOptions) (ImportReport, error) {
	limited := &countingReader{Reader: io.LimitReader(contextCheckingReader{ctx: ctx, reader: input}, maxLegacyStateBytes+1)}
	hash := sha256.New()
	state, err := decodeLegacyState(ctx, io.TeeReader(limited, hash))
	if limited.Count > maxLegacyStateBytes {
		return ImportReport{}, &domain.ValidationError{Field: "state.json", Message: "exceeds 32 MiB limit"}
	}
	checksum := hash.Sum(nil)
	report := ImportReport{Checksum: hex.EncodeToString(checksum), DryRun: options.DryRun}
	if err != nil {
		return report, err
	}
	defer zeroLegacyStateSecrets(state)
	normalized, warnings, err := validateLegacyState(ctx, state)
	if err != nil {
		return report, err
	}
	defer zeroNormalizedLegacySecrets(&normalized)
	report.Proxies = len(normalized.proxies)
	report.Clients = len(normalized.clients)
	report.Mappings = len(normalized.mappings)
	report.Warnings = warnings
	if options.DryRun {
		alreadyImported, err := hasImportChecksum(ctx, r.db, report.Checksum)
		if err != nil {
			return report, err
		}
		if alreadyImported {
			report.AlreadyImported = true
			return report, nil
		}
		duplicates, err := findExistingLegacyState(ctx, r.db, normalized)
		if err != nil {
			return report, err
		}
		report.Duplicates = duplicates
		if len(duplicates) > 0 {
			return report, &ImportConflictError{Duplicates: duplicates}
		}
		return report, nil
	}

	err = r.WithinImmediate(ctx, func(ctx context.Context, uow *UnitOfWork) error {
		var requestHash string
		err := uow.tx.QueryRowContext(ctx, `SELECT request_hash FROM idempotency_keys WHERE scope = ? AND key = ?`,
			"migration.import_v1", report.Checksum).Scan(&requestHash)
		if err == nil {
			if requestHash != report.Checksum {
				return &domain.ConflictError{Constraint: "idempotency_key", Message: "legacy import checksum key reused"}
			}
			report.AlreadyImported = true
			return nil
		}
		if !errorsIsNoRows(err) {
			return fmt.Errorf("sqlite: find import idempotency key: %w", err)
		}

		duplicates, err := findExistingLegacyState(ctx, uow.tx, normalized)
		if err != nil {
			return err
		}
		if len(duplicates) > 0 {
			report.Duplicates = duplicates
			return &ImportConflictError{Duplicates: duplicates}
		}
		for i := range normalized.proxies {
			p := &normalized.proxies[i]
			_, err := uow.CreateProxy(ctx, CreateProxyInput{
				ID: p.id, Label: p.label, Type: p.proxyType, Host: p.host, Port: p.port,
				Username: p.username, Password: p.password, Enabled: p.enabled, Actor: options.Actor,
			})
			zero(p.password)
			if err != nil {
				return err
			}
			if err := uow.audit(ctx, options.Actor, "migration.import_v1", "proxy", p.id, []byte(`{"secret_redacted":true}`)); err != nil {
				return err
			}
		}
		for _, c := range normalized.clients {
			_, err := uow.CreateClient(ctx, CreateClientInput{ID: c.id, IPCIDR: c.ipCIDR, Note: c.note, Enabled: c.enabled, Actor: options.Actor})
			if err != nil {
				return err
			}
			if err := uow.audit(ctx, options.Actor, "migration.import_v1", "client", c.id, []byte(`{}`)); err != nil {
				return err
			}
		}
		for _, m := range normalized.mappings {
			_, err := uow.CreateMapping(ctx, CreateMappingInput{
				ID: m.id, ClientID: m.clientID, ProxyID: m.proxyID, PolicyID: "default-web-only",
				LocalRedirectPort: m.localRedirectPort, Actor: options.Actor,
			})
			if err != nil {
				return err
			}
			if err := uow.audit(ctx, options.Actor, "migration.import_v1", "mapping", m.id,
				[]byte(`{"policy":"web_only","desired_state":"DRAFT"}`)); err != nil {
				return err
			}
		}
		response, err := json.Marshal(report)
		if err != nil {
			return fmt.Errorf("sqlite: encode import report: %w", err)
		}
		if _, err := uow.tx.ExecContext(ctx, `INSERT INTO idempotency_keys
            (scope, key, request_hash, response, created_at) VALUES (?, ?, ?, ?, ?)`,
			"migration.import_v1", report.Checksum, report.Checksum, response, unixMilli(uow.repo.now())); err != nil {
			return mapWriteError(err, "idempotency key")
		}
		return nil
	})
	return report, err
}

type legacyState struct {
	Proxies  map[string]legacyProxy   `json:"proxies"`
	Clients  map[string]legacyClient  `json:"clients"`
	Mappings map[string]legacyMapping `json:"mappings"`
}

type legacyProxy struct {
	ID            string       `json:"id"`
	Label         string       `json:"label"`
	Type          string       `json:"type"`
	Host          string       `json:"host"`
	Port          int          `json:"port"`
	Username      *string      `json:"username"`
	Password      legacySecret `json:"password"`
	Enabled       bool         `json:"enabled"`
	Status        string       `json:"status"`
	LatencyMS     *int         `json:"latency_ms"`
	ExitIP        *string      `json:"exit_ip"`
	LastCheckedAt *time.Time   `json:"last_checked_at"`
}

// legacySecret keeps imported JSON password bytes out of a long-lived Go
// string. Missing and JSON null retain the v1 behavior of "not configured";
// a present empty string also remains unconfigured because CreateProxy only
// persists non-empty credentials.
type legacySecret struct {
	bytes []byte
	set   bool
}

// legacySecretWipeHook is test-only observability for error-path ownership.
// It is nil in production and never receives secret bytes.
var legacySecretWipeHook func()

func (s *legacySecret) UnmarshalJSON(value []byte) error {
	zero(s.bytes)
	s.bytes = nil
	s.set = true
	value = bytes.TrimSpace(value)
	if bytes.Equal(value, []byte("null")) {
		return nil
	}
	decoded, err := decodeJSONStringBytes(value)
	if err != nil {
		return err
	}
	s.bytes = decoded
	return nil
}

func (s *legacySecret) wipe() {
	zero(s.bytes)
	s.bytes = nil
	if legacySecretWipeHook != nil {
		legacySecretWipeHook()
	}
}

func decodeJSONStringBytes(value []byte) ([]byte, error) {
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return nil, fmt.Errorf("password must be a JSON string or null")
	}
	output := make([]byte, 0, len(value)-2)
	for index := 1; index < len(value)-1; index++ {
		character := value[index]
		if character < 0x20 {
			zero(output)
			return nil, fmt.Errorf("password contains an invalid JSON control character")
		}
		if character == '"' {
			zero(output)
			return nil, fmt.Errorf("password contains an unescaped JSON quote")
		}
		if character != '\\' {
			output = append(output, character)
			continue
		}
		index++
		if index >= len(value)-1 {
			zero(output)
			return nil, fmt.Errorf("password contains an incomplete JSON escape")
		}
		switch value[index] {
		case '"', '\\', '/':
			output = append(output, value[index])
		case 'b':
			output = append(output, '\b')
		case 'f':
			output = append(output, '\f')
		case 'n':
			output = append(output, '\n')
		case 'r':
			output = append(output, '\r')
		case 't':
			output = append(output, '\t')
		case 'u':
			if index+4 >= len(value) {
				zero(output)
				return nil, fmt.Errorf("password contains an incomplete Unicode escape")
			}
			runeValue, ok := decodeJSONHexRune(value[index+1 : index+5])
			if !ok {
				zero(output)
				return nil, fmt.Errorf("password contains an invalid Unicode escape")
			}
			index += 4
			if runeValue >= 0xD800 && runeValue <= 0xDBFF {
				if index+6 >= len(value) || value[index+1] != '\\' || value[index+2] != 'u' {
					zero(output)
					return nil, fmt.Errorf("password contains an unpaired Unicode surrogate")
				}
				low, ok := decodeJSONHexRune(value[index+3 : index+7])
				if !ok || low < 0xDC00 || low > 0xDFFF {
					zero(output)
					return nil, fmt.Errorf("password contains an invalid Unicode surrogate")
				}
				runeValue = 0x10000 + (runeValue-0xD800)*0x400 + (low - 0xDC00)
				index += 6
			} else if runeValue >= 0xDC00 && runeValue <= 0xDFFF {
				zero(output)
				return nil, fmt.Errorf("password contains an unpaired Unicode surrogate")
			}
			output = utf8.AppendRune(output, rune(runeValue))
		default:
			zero(output)
			return nil, fmt.Errorf("password contains an invalid JSON escape")
		}
	}
	return output, nil
}

func decodeJSONHexRune(value []byte) (rune, bool) {
	if len(value) != 4 {
		return 0, false
	}
	var result rune
	for _, character := range value {
		result <<= 4
		switch {
		case character >= '0' && character <= '9':
			result += rune(character - '0')
		case character >= 'a' && character <= 'f':
			result += rune(character-'a') + 10
		case character >= 'A' && character <= 'F':
			result += rune(character-'A') + 10
		default:
			return 0, false
		}
	}
	return result, true
}

type legacyClient struct {
	ID      string `json:"id"`
	IPCidr  string `json:"ip_cidr"`
	Note    string `json:"note"`
	Enabled bool   `json:"enabled"`
}

type legacyMapping struct {
	ID                string     `json:"id"`
	ClientID          string     `json:"client_id"`
	ProxyID           string     `json:"proxy_id"`
	Protocol          string     `json:"protocol"`
	LocalRedirectPort int        `json:"local_redirect_port"`
	State             string     `json:"state"`
	LastAppliedAt     *time.Time `json:"last_applied_at"`
}

func decodeLegacyState(ctx context.Context, reader io.Reader) (state legacyState, err error) {
	defer func() {
		if err != nil {
			zeroLegacyStateSecrets(state)
		}
	}()
	budget := &jsonTokenBudget{remaining: maxLegacyJSONTokens}
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return state, &domain.ValidationError{Field: "state.json", Message: "must be a JSON object"}
	}
	seen := map[string]bool{}
	for decoder.More() {
		if err := ctx.Err(); err != nil {
			return state, err
		}
		fieldToken, err := decoder.Token()
		if err != nil {
			return state, err
		}
		field, ok := fieldToken.(string)
		if !ok || seen[field] {
			return state, &domain.ValidationError{Field: "state.json", Message: "contains duplicate or invalid top-level field"}
		}
		seen[field] = true
		switch field {
		case "proxies":
			state.Proxies, err = decodeLegacyObject(ctx, decoder, validateLegacyProxyFields, budget)
		case "clients":
			state.Clients, err = decodeLegacyObject(ctx, decoder, validateLegacyClientFields, budget)
		case "mappings":
			state.Mappings, err = decodeLegacyObject(ctx, decoder, validateLegacyMappingFields, budget)
		default:
			return state, &domain.ValidationError{Field: "state.json", Message: "contains unknown field " + field}
		}
		if err != nil {
			return state, err
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return state, &domain.ValidationError{Field: "state.json", Message: "has an incomplete object"}
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return state, &domain.ValidationError{Field: "state.json", Message: "must contain exactly one JSON document"}
	}
	if state.Proxies == nil {
		state.Proxies = map[string]legacyProxy{}
	}
	if state.Clients == nil {
		state.Clients = map[string]legacyClient{}
	}
	if state.Mappings == nil {
		state.Mappings = map[string]legacyMapping{}
	}
	return state, nil
}

func decodeLegacyObject[T any](ctx context.Context, decoder *json.Decoder, validate func(string, T) error, budget *jsonTokenBudget) (map[string]T, error) {
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, &domain.ValidationError{Field: "state.json", Message: "resource section must be an object"}
	}
	values := make(map[string]T)
	for decoder.More() {
		if err := ctx.Err(); err != nil {
			return values, err
		}
		if len(values) >= maxLegacyRecords {
			return values, &domain.ValidationError{Field: "state.json", Message: "exceeds record limit"}
		}
		keyToken, err := decoder.Token()
		if err != nil {
			return values, err
		}
		key, ok := keyToken.(string)
		if !ok || len(key) == 0 || len(key) > maxLegacyFieldBytes {
			return values, &domain.ValidationError{Field: "state.json", Message: "invalid record key"}
		}
		if _, exists := values[key]; exists {
			return values, &domain.ConflictError{Constraint: "state.json", Message: "duplicate record " + key}
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			zero(raw)
			return values, &domain.ValidationError{Field: "state.json", Message: err.Error()}
		}
		value, err := decodeLegacyRawValue[T](ctx, raw, budget)
		zero(raw)
		if err != nil {
			wipeLegacyValue(&value)
			return values, err
		}
		if err := validate(key, value); err != nil {
			wipeLegacyValue(&value)
			return values, err
		}
		values[key] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return values, &domain.ValidationError{Field: "state.json", Message: "resource section is incomplete"}
	}
	return values, nil
}

func decodeLegacyRawValue[T any](ctx context.Context, raw []byte, budget *jsonTokenBudget) (T, error) {
	var value T
	if err := rejectDuplicateJSONKeysWithBudget(ctx, raw, budget); err != nil {
		return value, err
	}
	if err := ctx.Err(); err != nil {
		return value, err
	}
	strict := json.NewDecoder(bytes.NewReader(raw))
	strict.DisallowUnknownFields()
	if err := strict.Decode(&value); err != nil {
		return value, &domain.ValidationError{Field: "state.json", Message: err.Error()}
	}
	if err := ctx.Err(); err != nil {
		return value, err
	}
	return value, nil
}

func wipeLegacyValue[T any](value *T) {
	if proxy, ok := any(value).(*legacyProxy); ok {
		proxy.Password.wipe()
	}
}

func rejectDuplicateJSONKeys(ctx context.Context, raw []byte) error {
	return rejectDuplicateJSONKeysWithBudget(ctx, raw, &jsonTokenBudget{remaining: maxLegacyJSONTokens})
}

func rejectDuplicateJSONKeysWithBudget(ctx context.Context, raw []byte, budget *jsonTokenBudget) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := walkJSONValue(ctx, decoder, 0, budget); err != nil {
		return &domain.ValidationError{Field: "state.json", Message: err.Error()}
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return &domain.ValidationError{Field: "state.json", Message: "invalid nested JSON value"}
	}
	return nil
}

type jsonTokenBudget struct{ remaining int }

func (b *jsonTokenBudget) take() error {
	b.remaining--
	if b.remaining < 0 {
		return fmt.Errorf("JSON token limit exceeded")
	}
	return nil
}

func walkJSONValue(ctx context.Context, decoder *json.Decoder, depth int, budget *jsonTokenBudget) error {
	if depth > 64 {
		return fmt.Errorf("JSON nesting exceeds limit")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if err := budget.take(); err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			if err := ctx.Err(); err != nil {
				return err
			}
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if err := budget.take(); err != nil {
				return err
			}
			if !ok || len(key) > maxLegacyFieldBytes {
				return fmt.Errorf("invalid object key")
			}
			if _, found := keys[key]; found {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			keys[key] = struct{}{}
			if err := walkJSONValue(ctx, decoder, depth+1, budget); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		if err == nil {
			err = budget.take()
		}
		return err
	case '[':
		for decoder.More() {
			if err := walkJSONValue(ctx, decoder, depth+1, budget); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		if err == nil {
			err = budget.take()
		}
		return err
	default:
		return fmt.Errorf("invalid JSON delimiter")
	}
}

func validateLegacyProxyFields(_ string, value legacyProxy) error {
	if len(value.Password.bytes) > maxLegacyFieldBytes {
		return &domain.ValidationError{Field: "state.json", Message: "field exceeds size limit"}
	}
	return validateFieldLengths(value.ID, value.Label, value.Type, value.Host, dereference(value.Username), dereference(value.ExitIP))
}
func validateLegacyClientFields(_ string, value legacyClient) error {
	return validateFieldLengths(value.ID, value.IPCidr, value.Note)
}
func validateLegacyMappingFields(_ string, value legacyMapping) error {
	return validateFieldLengths(value.ID, value.ClientID, value.ProxyID, value.Protocol, value.State)
}
func validateFieldLengths(values ...string) error {
	for _, value := range values {
		if len(value) > maxLegacyFieldBytes {
			return &domain.ValidationError{Field: "state.json", Message: "field exceeds size limit"}
		}
	}
	return nil
}
func dereference(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

type countingReader struct {
	io.Reader
	Count int64
}

type contextCheckingReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextCheckingReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	count, err := r.reader.Read(buffer)
	if contextErr := r.ctx.Err(); contextErr != nil {
		return count, contextErr
	}
	return count, err
}

func (r *countingReader) Read(buffer []byte) (int, error) {
	count, err := r.Reader.Read(buffer)
	r.Count += int64(count)
	return count, err
}

type normalizedLegacyState struct {
	proxies  []normalizedLegacyProxy
	clients  []normalizedLegacyClient
	mappings []normalizedLegacyMapping
}

type normalizedLegacyProxy struct {
	id, label, host, username string
	password                  []byte
	proxyType                 domain.ProxyType
	port                      int
	enabled                   bool
}

type normalizedLegacyClient struct {
	id, ipCIDR, note string
	enabled          bool
}

type normalizedLegacyMapping struct {
	id, clientID, proxyID string
	localRedirectPort     int
}

func validateLegacyState(ctx context.Context, state legacyState) (normalizedLegacyState, []string, error) {
	result := normalizedLegacyState{}
	warnings := make([]string, 0)
	proxyIDs := make(map[string]struct{}, len(state.Proxies))
	clientIDs := make(map[string]struct{}, len(state.Clients))
	clientCIDRs := make(map[string]string, len(state.Clients))

	proxyKeys := sortedLegacyKeys(state.Proxies)
	for _, key := range proxyKeys {
		if err := ctx.Err(); err != nil {
			return result, warnings, err
		}
		legacy := state.Proxies[key]
		id, err := legacyID("proxy", key, legacy.ID)
		if err != nil {
			return result, warnings, err
		}
		if _, exists := proxyIDs[id]; exists {
			return result, warnings, &domain.ConflictError{Constraint: "proxy_id", Message: "duplicate proxy ID " + id}
		}
		proxyType := domain.ProxyType(strings.ToLower(strings.TrimSpace(legacy.Type)))
		if err := domain.ValidateProxy(proxyType, legacy.Host, legacy.Port); err != nil {
			return result, warnings, err
		}
		proxyIDs[id] = struct{}{}
		username := ""
		var password []byte
		if legacy.Username != nil {
			username = *legacy.Username
		}
		if len(legacy.Password.bytes) > 0 {
			password = append([]byte(nil), legacy.Password.bytes...)
		}
		result.proxies = append(result.proxies, normalizedLegacyProxy{id: id, label: legacy.Label, proxyType: proxyType,
			host: legacy.Host, port: legacy.Port, username: username, password: password, enabled: legacy.Enabled})
	}

	clientKeys := sortedLegacyKeys(state.Clients)
	for _, key := range clientKeys {
		if err := ctx.Err(); err != nil {
			return result, warnings, err
		}
		legacy := state.Clients[key]
		id, err := legacyID("client", key, legacy.ID)
		if err != nil {
			return result, warnings, err
		}
		if _, exists := clientIDs[id]; exists {
			return result, warnings, &domain.ConflictError{Constraint: "client_id", Message: "duplicate client ID " + id}
		}
		cidr, err := domain.NormalizeIPv4HostCIDR(legacy.IPCidr)
		if err != nil {
			return result, warnings, err
		}
		if previous, exists := clientCIDRs[cidr]; exists {
			return result, warnings, &domain.ConflictError{Constraint: "client_ip_cidr", Message: "duplicate client IP " + cidr + " (" + previous + ", " + id + ")"}
		}
		if strings.TrimSpace(legacy.IPCidr) != cidr {
			warnings = append(warnings, "normalized client "+id+" to "+cidr)
		}
		clientIDs[id] = struct{}{}
		clientCIDRs[cidr] = id
		result.clients = append(result.clients, normalizedLegacyClient{id: id, ipCIDR: cidr, note: legacy.Note, enabled: legacy.Enabled})
	}

	mappingKeys := sortedLegacyKeys(state.Mappings)
	mappingIDs := make(map[string]struct{}, len(state.Mappings))
	for _, key := range mappingKeys {
		if err := ctx.Err(); err != nil {
			return result, warnings, err
		}
		legacy := state.Mappings[key]
		id, err := legacyID("mapping", key, legacy.ID)
		if err != nil {
			return result, warnings, err
		}
		if _, exists := mappingIDs[id]; exists {
			return result, warnings, &domain.ConflictError{Constraint: "mapping_id", Message: "duplicate mapping ID " + id}
		}
		if _, ok := clientIDs[legacy.ClientID]; !ok {
			return result, warnings, &domain.ValidationError{Field: "mappings." + id + ".client_id", Message: "does not reference an imported client"}
		}
		if _, ok := proxyIDs[legacy.ProxyID]; !ok {
			return result, warnings, &domain.ValidationError{Field: "mappings." + id + ".proxy_id", Message: "does not reference an imported proxy"}
		}
		if legacy.LocalRedirectPort < domain.ForwarderPortStart || legacy.LocalRedirectPort > domain.ForwarderPortEnd {
			return result, warnings, &domain.ValidationError{Field: "mappings." + id + ".local_redirect_port", Message: "must be between 15001 and 15999"}
		}
		mappingIDs[id] = struct{}{}
		result.mappings = append(result.mappings, normalizedLegacyMapping{id: id, clientID: legacy.ClientID,
			proxyID: legacy.ProxyID, localRedirectPort: legacy.LocalRedirectPort})
		warnings = append(warnings, "imported mapping "+id+" as DRAFT with web_only policy")
	}
	return result, warnings, nil
}

func legacyID(entity, mapKey, field string) (string, error) {
	key, value := strings.TrimSpace(mapKey), strings.TrimSpace(field)
	if key == "" {
		return "", &domain.ValidationError{Field: entity + ".id", Message: "map key must not be empty"}
	}
	if value != "" && value != key {
		return "", &domain.ValidationError{Field: entity + ".id", Message: "must match its map key"}
	}
	return key, nil
}

func sortedLegacyKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func hasImportChecksum(ctx context.Context, query sqlExecutor, checksum string) (bool, error) {
	var requestHash string
	err := query.QueryRowContext(ctx, `SELECT request_hash FROM idempotency_keys WHERE scope = ? AND key = ?`, "migration.import_v1", checksum).Scan(&requestHash)
	if errorsIsNoRows(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("sqlite: find import idempotency key: %w", err)
	}
	return requestHash == checksum, nil
}

func findExistingLegacyState(ctx context.Context, query sqlExecutor, state normalizedLegacyState) ([]string, error) {
	duplicates := make([]string, 0)
	existingClientIDs := make(map[string]struct{})
	for _, group := range []struct {
		entity string
		table  string
		ids    []string
	}{
		{entity: "proxy", table: "proxies", ids: legacyProxyIDs(state.proxies)},
		{entity: "client", table: "clients", ids: legacyClientIDs(state.clients)},
		{entity: "mapping", table: "mappings", ids: legacyMappingIDs(state.mappings)},
	} {
		for _, id := range group.ids {
			var exists int
			statement := "SELECT 1 FROM " + group.table + " WHERE id = ?"
			if err := query.QueryRowContext(ctx, statement, id).Scan(&exists); err == nil {
				duplicates = append(duplicates, group.entity+":"+id)
				if group.entity == "client" {
					existingClientIDs[id] = struct{}{}
				}
			} else if !errorsIsNoRows(err) {
				return nil, fmt.Errorf("sqlite: check existing %s: %w", group.entity, err)
			}
		}
	}
	for _, client := range state.clients {
		var existingID string
		err := query.QueryRowContext(ctx, `SELECT id FROM clients WHERE ip_cidr = ?`, client.ipCIDR).Scan(&existingID)
		if err == nil {
			if _, sameID := existingClientIDs[client.id]; !sameID || existingID != client.id {
				duplicates = append(duplicates, "client_ip_cidr:"+client.ipCIDR)
			}
		} else if !errorsIsNoRows(err) {
			return nil, fmt.Errorf("sqlite: check existing client CIDR: %w", err)
		}
	}
	return duplicates, nil
}

func legacyProxyIDs(values []normalizedLegacyProxy) []string {
	result := make([]string, len(values))
	for i := range values {
		result[i] = values[i].id
	}
	return result
}

func zeroNormalizedLegacySecrets(state *normalizedLegacyState) {
	for i := range state.proxies {
		zero(state.proxies[i].password)
		state.proxies[i].password = nil
	}
}

func zeroLegacyStateSecrets(state legacyState) {
	for key, proxy := range state.Proxies {
		proxy.Password.wipe()
		state.Proxies[key] = proxy
	}
}
func legacyClientIDs(values []normalizedLegacyClient) []string {
	result := make([]string, len(values))
	for i := range values {
		result[i] = values[i].id
	}
	return result
}
func legacyMappingIDs(values []normalizedLegacyMapping) []string {
	result := make([]string, len(values))
	for i := range values {
		result[i] = values[i].id
	}
	return result
}

func errorsIsNoRows(err error) bool { return err == sql.ErrNoRows }
