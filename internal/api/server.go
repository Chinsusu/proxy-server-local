// Package api provides the versioned PGW control-plane HTTP contract. It does
// not own nftables, systemd, or the forwarder lifecycle; those operations are
// exclusively performed by the Agent after it reads a desired snapshot.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"github.com/Chinsusu/proxy-server-local/internal/application"
	"github.com/Chinsusu/proxy-server-local/internal/domain"
	"github.com/Chinsusu/proxy-server-local/internal/persistence/sqlite"
	"github.com/Chinsusu/proxy-server-local/internal/secret"
	"github.com/Chinsusu/proxy-server-local/pkg/observability"
)

const maxBodyBytes = 1 << 20

type AdminAuthenticator func(*http.Request) (actor string, ok bool)

type Config struct {
	Service         *application.Service
	AdminAuth       AdminAuthenticator
	AgentToken      []byte
	RequireAgentUDS bool
	Observer        *observability.Observer
}

type Server struct {
	service         *application.Service
	adminAuth       AdminAuthenticator
	agentToken      []byte
	requireAgentUDS bool
	observer        *observability.Observer
	mux             *http.ServeMux
}

// operatorAgentState includes the signed global IPv6 policy without implying
// that it has been enforced. The policy is verified only when the Agent has
// reported the current desired generation as VERIFIED.
type operatorAgentState struct {
	domain.ReconcileState
	IPv6Policy         domain.IPv6Policy `json:"ipv6_policy"`
	IPv6PolicyVerified bool              `json:"ipv6_policy_verified"`
}

func New(cfg Config) (*Server, error) {
	if cfg.Service == nil {
		return nil, fmt.Errorf("api: service is required")
	}
	if cfg.AdminAuth == nil {
		return nil, fmt.Errorf("api: admin authenticator is required")
	}
	if len(cfg.AgentToken) == 0 {
		return nil, fmt.Errorf("api: agent service token is required")
	}
	observer := cfg.Observer
	if observer == nil {
		observer = observability.NewDiscard("pgw-api")
	}
	server := &Server{service: cfg.Service, adminAuth: cfg.AdminAuth, agentToken: append([]byte(nil), cfg.AgentToken...), requireAgentUDS: cfg.RequireAgentUDS, observer: observer, mux: http.NewServeMux()}
	server.routes()
	return server, nil
}

func (s *Server) Close() { zero(s.agentToken) }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, requestID := observability.WithRequest(r.Context(), r.Header.Get("X-Request-ID"), s.observer)
	w.Header().Set("X-Request-ID", requestID)
	s.mux.ServeHTTP(w, r.WithContext(context.WithValue(ctx, requestIDContextKey{}, requestID)))
}

type requestIDContextKey struct{}

func requestIDFrom(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDContextKey{}).(string); ok {
		return id
	}
	return ""
}

func (s *Server) routes() {
	// Keep unknown v2 paths inside the versioned error envelope instead of
	// allowing net/http's plaintext default 404 to leak through.
	s.mux.HandleFunc("/v2", s.v2NotFound)
	s.mux.HandleFunc("/v2/", s.v2NotFound)
	s.mux.HandleFunc("/v2/proxies", s.proxies)
	s.mux.HandleFunc("/v2/proxies/", s.proxyByID)
	s.mux.HandleFunc("/v2/clients", s.clients)
	s.mux.HandleFunc("/v2/clients/", s.clientByID)
	s.mux.HandleFunc("/v2/egress-policies", s.policies)
	s.mux.HandleFunc("/v2/egress-policies/", s.policyByID)
	s.mux.HandleFunc("/v2/mappings", s.mappings)
	s.mux.HandleFunc("/v2/mappings/", s.mappingByID)
	s.mux.HandleFunc("/v2/agent/state", s.agentState)
	s.mux.HandleFunc("/v2/audit-events", s.auditEvents)
	s.mux.HandleFunc("/internal/agent/v1/snapshot", s.agentSnapshot)
	s.mux.HandleFunc("/internal/agent/v1/mappings/", s.agentCredential)
	s.mux.HandleFunc("/internal/agent/v1/ack", s.agentAck)
	s.mux.HandleFunc("/internal/agent/v1/state", s.agentInternalState)
}

func (s *Server) v2NotFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, r, http.StatusNotFound, "not_found", "resource was not found", nil)
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) (string, bool) {
	actor, ok := s.adminAuth(r)
	if !ok {
		writeError(w, r, http.StatusUnauthorized, "unauthorized", "authentication is required", nil)
		return "", false
	}
	return actor, true
}

func (s *Server) requireAgent(w http.ResponseWriter, r *http.Request) bool {
	if s.requireAgentUDS && r.RemoteAddr != "@" && !strings.HasPrefix(r.RemoteAddr, "unix") {
		// net/http represents Unix connections as either "@" or a path depending
		// on the listener implementation. TCP remote addresses always contain a
		// port and are rejected by this branch.
		if _, _, hasPort := strings.Cut(r.RemoteAddr, ":"); hasPort {
			writeError(w, r, http.StatusForbidden, "agent_transport_required", "agent endpoint requires a Unix socket", nil)
			return false
		}
	}
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(h), "bearer ") {
		writeError(w, r, http.StatusUnauthorized, "unauthorized", "agent token is required", nil)
		return false
	}
	provided := []byte(strings.TrimSpace(h[7:]))
	defer zero(provided)
	if subtle.ConstantTimeCompare(provided, s.agentToken) != 1 {
		writeError(w, r, http.StatusUnauthorized, "unauthorized", "agent token is invalid", nil)
		return false
	}
	return true
}

func (s *Server) proxies(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		cursor, limit, err := pageArgs(r)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		page, err := s.service.Repository().ListProxiesPage(r.Context(), cursor, limit)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, page)
	case http.MethodPost:
		key, ok := requireIdempotency(w, r)
		if !ok {
			return
		}
		body, err := readBody(w, r)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		defer zero(body)
		var input struct {
			ID       string            `json:"id"`
			Label    string            `json:"label"`
			Type     domain.ProxyType  `json:"type"`
			Host     string            `json:"host"`
			Port     int               `json:"port"`
			Username string            `json:"username"`
			Password *secret.JSONBytes `json:"password"`
			Enabled  *bool             `json:"enabled"`
		}
		defer func() {
			if input.Password != nil {
				secret.Wipe(input.Password.Bytes)
			}
		}()
		if err := decodeStrict(body, &input); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_json", "request body is invalid", nil)
			return
		}
		enabled := true
		if input.Enabled != nil {
			enabled = *input.Enabled
		}
		var password []byte
		if input.Password != nil {
			password = input.Password.Bytes
			input.Password.Bytes = nil
		}
		defer zero(password)
		proxy, replay, err := s.service.CreateProxy(r.Context(), sqlite.CreateProxyInput{ID: input.ID, Label: input.Label, Type: input.Type, Host: input.Host, Port: input.Port, Username: input.Username, Password: password, PasswordConfigured: input.Password != nil || input.Username != "", Enabled: enabled, Actor: actor}, key, body)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		setVersion(w, proxy.Version)
		if replay {
			w.Header().Set("Idempotency-Replayed", "true")
		}
		writeJSON(w, http.StatusCreated, proxy)
	default:
		methodNotAllowed(w, r, "GET, POST")
	}
}

func (s *Server) proxyByID(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v2/proxies/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, r, http.StatusNotFound, "not_found", "resource was not found", nil)
		return
	}
	switch r.Method {
	case http.MethodGet:
		proxy, err := s.service.Repository().GetProxy(r.Context(), id)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		setVersion(w, proxy.Version)
		writeJSON(w, http.StatusOK, proxy)
	case http.MethodPatch:
		version, ok := requireVersion(w, r)
		if !ok {
			return
		}
		key, ok := requireIdempotency(w, r)
		if !ok {
			return
		}
		body, err := readBody(w, r)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		defer zero(body)
		var input struct {
			Label              *string           `json:"label"`
			Type               *domain.ProxyType `json:"type"`
			Host               *string           `json:"host"`
			Port               *int              `json:"port"`
			Enabled            *bool             `json:"enabled"`
			Username           *string           `json:"username"`
			Password           *secret.JSONBytes `json:"password"`
			PasswordConfigured *bool             `json:"password_configured"`
		}
		defer func() {
			if input.Password != nil {
				secret.Wipe(input.Password.Bytes)
			}
		}()
		if err := decodeStrict(body, &input); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_json", "request body is invalid", nil)
			return
		}
		if input.Label == nil && input.Type == nil && input.Host == nil && input.Port == nil && input.Enabled == nil && input.Username == nil && input.Password == nil && input.PasswordConfigured == nil {
			writeDomainError(w, r, &domain.ValidationError{Field: "body", Message: "must include at least one mutable field"})
			return
		}
		var password *[]byte
		if input.Password != nil {
			p := input.Password.Bytes
			input.Password.Bytes = nil
			password = &p
			defer zero(p)
		}
		proxy, replay, err := s.service.PatchProxy(r.Context(), id, version, sqlite.PatchProxyInput{Label: input.Label, Type: input.Type, Host: input.Host, Port: input.Port, Enabled: input.Enabled, Username: input.Username, Password: password, PasswordConfigured: input.PasswordConfigured, Actor: actor}, key, body)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		setVersion(w, proxy.Version)
		if replay {
			w.Header().Set("Idempotency-Replayed", "true")
		}
		writeJSON(w, http.StatusOK, proxy)
	case http.MethodDelete:
		version, ok := requireVersion(w, r)
		if !ok {
			return
		}
		key, ok := requireIdempotency(w, r)
		if !ok {
			return
		}
		replay, err := s.service.DeleteProxy(r.Context(), id, version, actor, key, nil)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		if replay {
			w.Header().Set("Idempotency-Replayed", "true")
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w, r, "GET, PATCH, DELETE")
	}
}

func (s *Server) clients(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		cursor, limit, err := pageArgs(r)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		page, err := s.service.Repository().ListClientsPage(r.Context(), cursor, limit)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, page)
	case http.MethodPost:
		key, ok := requireIdempotency(w, r)
		if !ok {
			return
		}
		body, err := readBody(w, r)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		defer zero(body)
		var input struct {
			ID      string `json:"id"`
			IPCIDR  string `json:"ip_cidr"`
			Note    string `json:"note"`
			Enabled *bool  `json:"enabled"`
		}
		if err := decodeStrict(body, &input); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_json", "request body is invalid", nil)
			return
		}
		enabled := true
		if input.Enabled != nil {
			enabled = *input.Enabled
		}
		client, replay, err := s.service.CreateClient(r.Context(), sqlite.CreateClientInput{ID: input.ID, IPCIDR: input.IPCIDR, Note: input.Note, Enabled: enabled, Actor: actor}, key, body)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		setVersion(w, client.Version)
		if replay {
			w.Header().Set("Idempotency-Replayed", "true")
		}
		writeJSON(w, http.StatusCreated, client)
	default:
		methodNotAllowed(w, r, "GET, POST")
	}
}

func (s *Server) clientByID(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v2/clients/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, r, http.StatusNotFound, "not_found", "resource was not found", nil)
		return
	}
	switch r.Method {
	case http.MethodGet:
		client, err := s.service.Repository().GetClient(r.Context(), id)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		setVersion(w, client.Version)
		writeJSON(w, http.StatusOK, client)
	case http.MethodPatch:
		version, ok := requireVersion(w, r)
		if !ok {
			return
		}
		key, ok := requireIdempotency(w, r)
		if !ok {
			return
		}
		body, err := readBody(w, r)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		defer zero(body)
		var input struct {
			Note    *string `json:"note"`
			Enabled *bool   `json:"enabled"`
		}
		if err := decodeStrict(body, &input); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_json", "request body is invalid", nil)
			return
		}
		if input.Note == nil && input.Enabled == nil {
			writeDomainError(w, r, &domain.ValidationError{Field: "body", Message: "must include at least one mutable field"})
			return
		}
		client, replay, err := s.service.PatchClient(r.Context(), id, version, sqlite.PatchClientInput{Note: input.Note, Enabled: input.Enabled, Actor: actor}, key, body)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		setVersion(w, client.Version)
		if replay {
			w.Header().Set("Idempotency-Replayed", "true")
		}
		writeJSON(w, http.StatusOK, client)
	case http.MethodDelete:
		version, ok := requireVersion(w, r)
		if !ok {
			return
		}
		key, ok := requireIdempotency(w, r)
		if !ok {
			return
		}
		replay, err := s.service.DeleteClient(r.Context(), id, version, actor, key, nil)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		if replay {
			w.Header().Set("Idempotency-Replayed", "true")
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w, r, "GET, PATCH, DELETE")
	}
}

func (s *Server) policies(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r, "GET")
		return
	}
	cursor, limit, err := pageArgs(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	page, err := s.service.Repository().ListPoliciesPage(r.Context(), cursor, limit)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}
func (s *Server) policyByID(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r, "GET")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v2/egress-policies/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, r, http.StatusNotFound, "not_found", "resource was not found", nil)
		return
	}
	policy, err := s.service.Repository().GetPolicy(r.Context(), id)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	setVersion(w, policy.Version)
	writeJSON(w, http.StatusOK, policy)
}

func (s *Server) mappings(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		cursor, limit, err := pageArgs(r)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		page, err := s.service.Repository().ListMappingsPage(r.Context(), cursor, limit)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, page)
	case http.MethodPost:
		key, ok := requireIdempotency(w, r)
		if !ok {
			return
		}
		body, err := readBody(w, r)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		defer zero(body)
		var input struct {
			ID                string `json:"id"`
			ClientID          string `json:"client_id"`
			ProxyID           string `json:"proxy_id"`
			PolicyID          string `json:"policy_id"`
			LocalRedirectPort int    `json:"local_redirect_port"`
		}
		if err := decodeStrict(body, &input); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_json", "request body is invalid", nil)
			return
		}
		mapping, replay, err := s.service.CreateMapping(r.Context(), sqlite.CreateMappingInput{ID: input.ID, ClientID: input.ClientID, ProxyID: input.ProxyID, PolicyID: input.PolicyID, LocalRedirectPort: input.LocalRedirectPort, Actor: actor}, key, body)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		setVersion(w, mapping.Version)
		if replay {
			w.Header().Set("Idempotency-Replayed", "true")
		}
		writeJSON(w, http.StatusCreated, mapping)
	default:
		methodNotAllowed(w, r, "GET, POST")
	}
}

func (s *Server) mappingByID(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	id, action, hasAction, valid := parseMappingRoute(strings.TrimPrefix(r.URL.Path, "/v2/mappings/"))
	if !valid {
		writeError(w, r, http.StatusNotFound, "not_found", "resource was not found", nil)
		return
	}
	if hasAction {
		s.mappingAction(w, r, id, action, actor)
		return
	}
	switch r.Method {
	case http.MethodGet:
		mapping, err := s.service.Repository().GetMapping(r.Context(), id)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		setVersion(w, mapping.Version)
		writeJSON(w, http.StatusOK, mapping)
	case http.MethodPatch:
		version, ok := requireVersion(w, r)
		if !ok {
			return
		}
		key, ok := requireIdempotency(w, r)
		if !ok {
			return
		}
		body, err := readBody(w, r)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		defer zero(body)
		var input struct {
			LocalRedirectPort *int    `json:"local_redirect_port"`
			PolicyID          *string `json:"policy_id"`
		}
		if err := decodeStrict(body, &input); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_json", "request body is invalid", nil)
			return
		}
		mapping, replay, err := s.service.PatchMapping(r.Context(), id, version, sqlite.PatchMappingInput{LocalRedirectPort: input.LocalRedirectPort, PolicyID: input.PolicyID, Actor: actor}, key, body)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		setVersion(w, mapping.Version)
		if replay {
			w.Header().Set("Idempotency-Replayed", "true")
		}
		writeJSON(w, http.StatusOK, mapping)
	case http.MethodDelete:
		version, ok := requireVersion(w, r)
		if !ok {
			return
		}
		key, ok := requireIdempotency(w, r)
		if !ok {
			return
		}
		mapping, replay, err := s.service.DeleteMapping(r.Context(), id, version, actor, key, nil)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		setVersion(w, mapping.Version)
		if replay {
			w.Header().Set("Idempotency-Replayed", "true")
		}
		writeJSON(w, http.StatusOK, mapping)
	default:
		methodNotAllowed(w, r, "GET, PATCH, DELETE")
	}
}

// parseMappingRoute accepts only a mapping resource ID or one exact action.
// Both historical `id:activate` and canonical `id/activate` forms remain
// supported during the migration window, but mixed separators, extra path
// segments, empty components, and unknown actions are never routed as a
// mapping operation.
func parseMappingRoute(path string) (id, action string, hasAction, valid bool) {
	if path == "" {
		return "", "", false, false
	}
	if strings.Contains(path, "/") {
		parts := strings.Split(path, "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.Contains(parts[0], ":") || !mappingActionName(parts[1]) {
			return "", "", false, false
		}
		return parts[0], parts[1], true, true
	}
	if strings.Contains(path, ":") {
		if strings.Count(path, ":") != 1 {
			return "", "", false, false
		}
		id, action, _ = strings.Cut(path, ":")
		if id == "" || !mappingActionName(action) {
			return "", "", false, false
		}
		return id, action, true, true
	}
	return path, "", false, true
}

func mappingActionName(action string) bool {
	return action == "activate" || action == "suspend"
}

func (s *Server) mappingAction(w http.ResponseWriter, r *http.Request, id, action, actor string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, r, "POST")
		return
	}
	version, ok := requireVersion(w, r)
	if !ok {
		return
	}
	key, ok := requireIdempotency(w, r)
	if !ok {
		return
	}
	body, err := readBody(w, r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	defer zero(body)
	var mapping domain.Mapping
	var replay bool
	switch action {
	case "activate":
		mapping, replay, err = s.service.ActivateMapping(r.Context(), id, version, actor, key, body)
	case "suspend":
		mapping, replay, err = s.service.SuspendMapping(r.Context(), id, version, actor, key, body)
	default:
		writeError(w, r, http.StatusNotFound, "not_found", "action was not found", nil)
		return
	}
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	setVersion(w, mapping.Version)
	if replay {
		w.Header().Set("Idempotency-Replayed", "true")
	}
	writeJSON(w, http.StatusOK, mapping)
}

func (s *Server) agentState(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r, "GET")
		return
	}
	state, err := s.service.Repository().GetReconcileState(r.Context())
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	s.observeAgentState(state)
	writeJSON(w, http.StatusOK, operatorAgentState{
		ReconcileState:     state,
		IPv6Policy:         s.service.Repository().IPv6Policy(),
		IPv6PolicyVerified: state.State == string(domain.DataPlaneVerified) && state.PendingGeneration == state.AppliedGeneration,
	})
}
func (s *Server) auditEvents(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r, "GET")
		return
	}
	cursor, limit, err := auditPageArgs(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	page, err := s.service.Repository().ListAuditPage(r.Context(), cursor, limit)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) agentSnapshot(w http.ResponseWriter, r *http.Request) {
	if !s.requireAgent(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r, "GET")
		return
	}
	snapshot, err := s.service.DesiredSnapshot(r.Context())
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if observer := observability.FromContext(r.Context()); observer != nil {
		observer.Metrics.SetAgentState(snapshot.Generation, 0, "unknown")
	}
	if wanted := r.URL.Query().Get("generation"); wanted != "" && wanted != strconv.FormatInt(snapshot.Generation, 10) {
		writeError(w, r, http.StatusConflict, "stale_generation", "requested generation is no longer current", map[string]any{"generation": snapshot.Generation})
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}
func (s *Server) agentCredential(w http.ResponseWriter, r *http.Request) {
	if !s.requireAgent(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r, "GET")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/internal/agent/v1/mappings/")
	id, action, hasAction := strings.Cut(path, "/")
	if !hasAction || action != "credential" || id == "" {
		writeError(w, r, http.StatusNotFound, "not_found", "resource was not found", nil)
		return
	}
	credential, err := s.service.CredentialForActiveMapping(r.Context(), id)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	defer zero(credential.Password)
	writeJSON(w, http.StatusOK, credential)
}
func (s *Server) agentAck(w http.ResponseWriter, r *http.Request) {
	if !s.requireAgent(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w, r, "POST")
		return
	}
	body, err := readBody(w, r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	defer zero(body)
	var ack domain.AgentAck
	if err := decodeStrict(body, &ack); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_json", "request body is invalid", nil)
		return
	}
	state, err := s.service.AcknowledgeAgent(r.Context(), ack, "agent")
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	s.observeAgentState(state)
	writeJSON(w, http.StatusOK, state)
}
func (s *Server) agentInternalState(w http.ResponseWriter, r *http.Request) {
	if !s.requireAgent(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r, "GET")
		return
	}
	state, err := s.service.Repository().GetReconcileState(r.Context())
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	s.observeAgentState(state)
	writeJSON(w, http.StatusOK, state)
}

func (s *Server) observeAgentState(state domain.ReconcileState) {
	if s.observer != nil {
		s.observer.Metrics.SetAgentState(state.PendingGeneration, state.AppliedGeneration, state.State)
	}
}

func pageArgs(r *http.Request) (string, int, error) { return pageArgsWith(r, false) }
func auditPageArgs(r *http.Request) (int64, int, error) {
	cursor, limit, err := pageArgsWith(r, true)
	if err != nil {
		return 0, 0, err
	}
	if cursor == "" {
		return 0, limit, nil
	}
	value, err := strconv.ParseInt(cursor, 10, 64)
	if err != nil || value < 0 {
		return 0, 0, &domain.ValidationError{Field: "cursor", Message: "must be a non-negative audit event id"}
	}
	return value, limit, nil
}
func pageArgsWith(r *http.Request, numeric bool) (string, int, error) {
	cursor := r.URL.Query().Get("cursor")
	if len(cursor) > 256 {
		return "", 0, &domain.ValidationError{Field: "cursor", Message: "is too long"}
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 200 {
			return "", 0, &domain.ValidationError{Field: "limit", Message: "must be between 1 and 200"}
		}
		limit = value
	}
	return cursor, limit, nil
}
func readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		zero(body)
		return nil, &domain.ValidationError{Field: "body", Message: "is too large or unreadable"}
	}
	return body, nil
}
func decodeStrict(body []byte, target any) error {
	allowed, err := jsonObjectFields(target)
	if err != nil {
		return err
	}
	if _, err := secret.StrictJSONObject(body, allowed); err != nil {
		return fmt.Errorf("invalid JSON request")
	}
	return json.Unmarshal(body, target)
}

func jsonObjectFields(target any) ([]string, error) {
	typeOf := reflect.TypeOf(target)
	if typeOf == nil || typeOf.Kind() != reflect.Ptr || typeOf.Elem().Kind() != reflect.Struct {
		return nil, fmt.Errorf("strict JSON target must be a struct pointer")
	}
	typeOf = typeOf.Elem()
	fields := make([]string, 0, typeOf.NumField())
	for index := 0; index < typeOf.NumField(); index++ {
		field := typeOf.Field(index)
		if field.PkgPath != "" { // unexported
			continue
		}
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields = append(fields, name)
	}
	return fields, nil
}
func requireIdempotency(w http.ResponseWriter, r *http.Request) (string, bool) {
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" || len(key) > 200 {
		writeError(w, r, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key is required for mutations", nil)
		return "", false
	}
	return key, true
}
func requireVersion(w http.ResponseWriter, r *http.Request) (int64, bool) {
	raw := strings.Trim(strings.TrimSpace(r.Header.Get("If-Match")), "\"")
	if raw == "" {
		writeError(w, r, 428, "if_match_required", "If-Match resource version is required", nil)
		return 0, false
	}
	version, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || version < 1 {
		writeError(w, r, http.StatusBadRequest, "invalid_if_match", "If-Match must be a positive resource version", nil)
		return 0, false
	}
	return version, true
}
func setVersion(w http.ResponseWriter, version int64) {
	w.Header().Set("ETag", fmt.Sprintf("\"%d\"", version))
}
func methodNotAllowed(w http.ResponseWriter, r *http.Request, allowed string) {
	w.Header().Set("Allow", allowed)
	writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method is not allowed", nil)
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string, details any) {
	payload := map[string]any{"error": map[string]any{"code": code, "message": message}, "request_id": requestIDFrom(r.Context())}
	if details != nil {
		payload["error"].(map[string]any)["details"] = details
	}
	writeJSON(w, status, payload)
}
func writeDomainError(w http.ResponseWriter, r *http.Request, err error) {
	var validation *domain.ValidationError
	var missing *domain.NotFoundError
	var conflict *domain.ConflictError
	switch {
	case errors.As(err, &validation):
		writeError(w, r, http.StatusBadRequest, "validation_error", "request validation failed", map[string]any{"field": validation.Field})
	case errors.As(err, &missing):
		writeError(w, r, http.StatusNotFound, "not_found", "resource was not found", nil)
	case errors.As(err, &conflict):
		writeError(w, r, http.StatusConflict, conflict.Constraint, "resource conflict", nil)
	default:
		if observer := observability.FromContext(r.Context()); observer != nil {
			observer.Metrics.ObserveDBError("operation_error")
		}
		writeError(w, r, http.StatusInternalServerError, "internal_error", "internal server error", nil)
	}
}
func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
