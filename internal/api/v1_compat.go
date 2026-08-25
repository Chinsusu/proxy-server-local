package api

// The v1 facade is intentionally a translation layer over application.Service,
// not a second store. It remains during the migration window so the existing
// UI works while inheriting encrypted secrets, SQLite transactions and Agent
// ownership. Passwords are accepted on writes but never rendered on reads.

import (
	"net/http"
	"strings"

	"github.com/Chinsusu/proxy-server-local/internal/application"
	"github.com/Chinsusu/proxy-server-local/internal/domain"
	"github.com/Chinsusu/proxy-server-local/internal/persistence/sqlite"
	"github.com/Chinsusu/proxy-server-local/internal/secret"
	"github.com/google/uuid"
)

func (s *Server) LegacyV1Handler() http.Handler { return http.HandlerFunc(s.serveV1) }

func IsV1ControlPath(path string) bool {
	return path == "/v1/proxies" || strings.HasPrefix(path, "/v1/proxies/") ||
		path == "/v1/clients" || strings.HasPrefix(path, "/v1/clients/") ||
		path == "/v1/mappings" || strings.HasPrefix(path, "/v1/mappings/")
}

func (s *Server) serveV1(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	switch {
	case r.URL.Path == "/v1/proxies":
		s.v1Proxies(w, r, actor)
	case strings.HasPrefix(r.URL.Path, "/v1/proxies/"):
		s.v1ProxyByID(w, r, actor)
	case r.URL.Path == "/v1/clients":
		s.v1Clients(w, r, actor)
	case strings.HasPrefix(r.URL.Path, "/v1/clients/"):
		s.v1ClientByID(w, r, actor)
	case r.URL.Path == "/v1/mappings" || r.URL.Path == "/v1/mappings/active":
		s.v1Mappings(w, r, actor)
	case strings.HasPrefix(r.URL.Path, "/v1/mappings/"):
		s.v1MappingByID(w, r, actor)
	default:
		writeError(w, r, http.StatusNotFound, "not_found", "resource was not found", nil)
	}
}

type v1Proxy struct {
	ID                 string  `json:"id"`
	Label              string  `json:"label,omitempty"`
	Type               string  `json:"type"`
	Host               string  `json:"host"`
	Port               int     `json:"port"`
	Username           *string `json:"username,omitempty"`
	PasswordConfigured bool    `json:"password_configured"`
	Enabled            bool    `json:"enabled"`
	Status             string  `json:"status"`
	LatencyMS          *int    `json:"latency_ms,omitempty"`
	ExitIP             string  `json:"exit_ip,omitempty"`
}
type v1Client struct {
	ID      string `json:"id"`
	IPCidr  string `json:"ip_cidr"`
	Note    string `json:"note,omitempty"`
	Enabled bool   `json:"enabled"`
}
type v1MappingView struct {
	ID                string   `json:"id"`
	Client            v1Client `json:"client"`
	Proxy             v1Proxy  `json:"proxy"`
	State             string   `json:"state"`
	LocalRedirectPort int      `json:"local_redirect_port"`
}

func toV1Proxy(value domain.Proxy) v1Proxy {
	var username *string
	if value.Username != "" {
		user := value.Username
		username = &user
	}
	return v1Proxy{ID: value.ID, Label: value.Label, Type: string(value.Type), Host: value.Host, Port: value.Port, Username: username, PasswordConfigured: value.PasswordConfigured, Enabled: value.Enabled, Status: string(value.Status), LatencyMS: value.LatencyMS, ExitIP: value.ExitIP}
}
func toV1Client(value domain.Client) v1Client {
	return v1Client{ID: value.ID, IPCidr: value.IPCIDR, Note: value.Note, Enabled: value.Enabled}
}
func v1MappingState(value domain.Mapping) string {
	if value.DataPlaneState == domain.DataPlaneFailed {
		return "FAILED"
	}
	if value.DataPlaneState == domain.DataPlaneVerified {
		return "APPLIED"
	}
	return "PENDING"
}

func (s *Server) v1Proxies(w http.ResponseWriter, r *http.Request, actor string) {
	switch r.Method {
	case http.MethodGet:
		items, err := allProxies(r, s.service)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		result := make([]v1Proxy, 0, len(items))
		for _, value := range items {
			result = append(result, toV1Proxy(value))
		}
		writeJSON(w, http.StatusOK, result)
	case http.MethodPost:
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
			Username *string           `json:"username"`
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
		username := ""
		if input.Username != nil {
			username = *input.Username
		}
		password := []byte(nil)
		if input.Password != nil {
			password = input.Password.Bytes
			input.Password.Bytes = nil
		}
		defer zero(password)
		value, _, err := s.service.CreateProxy(r.Context(), sqlite.CreateProxyInput{ID: input.ID, Label: input.Label, Type: input.Type, Host: input.Host, Port: input.Port, Username: username, Password: password, PasswordConfigured: input.Password != nil || username != "", Enabled: enabled, Actor: actor}, legacyIdempotency(r), body)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		writeJSON(w, http.StatusCreated, toV1Proxy(value))
	default:
		methodNotAllowed(w, r, "GET, POST")
	}
}

func (s *Server) v1ProxyByID(w http.ResponseWriter, r *http.Request, actor string) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/proxies/")
	if strings.HasSuffix(path, "/check") {
		id := strings.TrimSuffix(path, "/check")
		if id == "" || strings.Contains(id, "/") {
			writeError(w, r, http.StatusNotFound, "not_found", "resource was not found", nil)
			return
		}
		if r.Method != http.MethodPost {
			methodNotAllowed(w, r, "POST")
			return
		}
		result, err := s.service.CheckProxy(r.Context(), id)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
		return
	}
	id := path
	if id == "" || strings.Contains(id, "/") {
		writeError(w, r, http.StatusNotFound, "not_found", "resource was not found", nil)
		return
	}
	value, err := s.service.Repository().GetProxy(r.Context(), id)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, toV1Proxy(value))
		return
	}
	if r.Method == http.MethodDelete {
		if _, err := s.service.DeleteProxy(r.Context(), id, value.Version, actor, legacyIdempotency(r), nil); err != nil {
			writeDomainError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	methodNotAllowed(w, r, "GET, DELETE")
}

func (s *Server) v1Clients(w http.ResponseWriter, r *http.Request, actor string) {
	switch r.Method {
	case http.MethodGet:
		items, err := allClients(r, s.service)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		result := make([]v1Client, 0, len(items))
		for _, value := range items {
			result = append(result, toV1Client(value))
		}
		writeJSON(w, http.StatusOK, result)
	case http.MethodPost:
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
		value, _, err := s.service.CreateClient(r.Context(), sqlite.CreateClientInput{ID: input.ID, IPCIDR: input.IPCIDR, Note: input.Note, Enabled: enabled, Actor: actor}, legacyIdempotency(r), body)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		writeJSON(w, http.StatusCreated, toV1Client(value))
	default:
		methodNotAllowed(w, r, "GET, POST")
	}
}

func (s *Server) v1ClientByID(w http.ResponseWriter, r *http.Request, actor string) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/clients/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, r, http.StatusNotFound, "not_found", "resource was not found", nil)
		return
	}
	value, err := s.service.Repository().GetClient(r.Context(), id)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, toV1Client(value))
		return
	}
	if r.Method == http.MethodDelete {
		if _, err := s.service.DeleteClient(r.Context(), id, value.Version, actor, legacyIdempotency(r), nil); err != nil {
			writeDomainError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	methodNotAllowed(w, r, "GET, DELETE")
}

func (s *Server) v1Mappings(w http.ResponseWriter, r *http.Request, actor string) {
	switch r.Method {
	case http.MethodGet:
		items, err := allMappings(r, s.service)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		result, err := s.toV1Mappings(r, items, r.URL.Path == "/v1/mappings/active")
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	case http.MethodPost:
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
			LocalRedirectPort int    `json:"local_redirect_port"`
			Protocol          string `json:"protocol"`
		}
		if err := decodeStrict(body, &input); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_json", "request body is invalid", nil)
			return
		}
		value, _, err := s.service.CreateAndActivateMapping(r.Context(), sqlite.CreateMappingInput{ID: input.ID, ClientID: input.ClientID, ProxyID: input.ProxyID, LocalRedirectPort: input.LocalRedirectPort, Actor: actor}, legacyIdempotency(r), body)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		result, err := s.toV1Mappings(r, []domain.Mapping{value}, false)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		writeJSON(w, http.StatusCreated, result[0])
	default:
		methodNotAllowed(w, r, "GET, POST")
	}
}

func (s *Server) v1MappingByID(w http.ResponseWriter, r *http.Request, actor string) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/mappings/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, r, http.StatusNotFound, "not_found", "resource was not found", nil)
		return
	}
	value, err := s.service.Repository().GetMapping(r.Context(), id)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if r.Method == http.MethodDelete {
		if _, _, err := s.service.DeleteMapping(r.Context(), id, value.Version, actor, legacyIdempotency(r), nil); err != nil {
			writeDomainError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r, "GET, DELETE")
		return
	}
	result, err := s.toV1Mappings(r, []domain.Mapping{value}, false)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if len(result) != 1 {
		// A cascade soft-delete deliberately retains the mapping for audit
		// history but it is no longer a v1-readable resource.
		writeError(w, r, http.StatusNotFound, "not_found", "resource was not found", nil)
		return
	}
	writeJSON(w, http.StatusOK, result[0])
}

func (s *Server) toV1Mappings(r *http.Request, values []domain.Mapping, onlyActive bool) ([]v1MappingView, error) {
	result := make([]v1MappingView, 0, len(values))
	for _, value := range values {
		if value.DesiredState == domain.DesiredDeleted {
			continue
		}
		if onlyActive && value.DesiredState != domain.DesiredActive {
			continue
		}
		client, err := s.service.Repository().GetClient(r.Context(), value.ClientID)
		if err != nil {
			return nil, err
		}
		proxy, err := s.service.Repository().GetProxy(r.Context(), value.ProxyID)
		if err != nil {
			return nil, err
		}
		result = append(result, v1MappingView{ID: value.ID, Client: toV1Client(client), Proxy: toV1Proxy(proxy), State: v1MappingState(value), LocalRedirectPort: value.LocalRedirectPort})
	}
	return result, nil
}

func allProxies(r *http.Request, service *application.Service) ([]domain.Proxy, error) {
	var result []domain.Proxy
	cursor := ""
	for {
		page, err := service.Repository().ListProxiesPage(r.Context(), cursor, 200)
		if err != nil {
			return nil, err
		}
		result = append(result, page.Items...)
		if page.NextCursor == "" {
			return result, nil
		}
		cursor = page.NextCursor
	}
}
func allClients(r *http.Request, service *application.Service) ([]domain.Client, error) {
	var result []domain.Client
	cursor := ""
	for {
		page, err := service.Repository().ListClientsPage(r.Context(), cursor, 200)
		if err != nil {
			return nil, err
		}
		result = append(result, page.Items...)
		if page.NextCursor == "" {
			return result, nil
		}
		cursor = page.NextCursor
	}
}
func allMappings(r *http.Request, service *application.Service) ([]domain.Mapping, error) {
	var result []domain.Mapping
	cursor := ""
	for {
		page, err := service.Repository().ListMappingsPage(r.Context(), cursor, 200)
		if err != nil {
			return nil, err
		}
		result = append(result, page.Items...)
		if page.NextCursor == "" {
			return result, nil
		}
		cursor = page.NextCursor
	}
}
func legacyIdempotency(r *http.Request) string {
	if key := strings.TrimSpace(r.Header.Get("Idempotency-Key")); key != "" {
		return "v1:" + key
	}
	return "v1:" + uuid.NewString()
}
