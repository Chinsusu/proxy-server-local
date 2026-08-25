package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Chinsusu/proxy-server-local/internal/domain"
)

type HTTPControlConfig struct {
	APIBase          string
	CredentialSocket string
	TokenFile        string
	Timeout          time.Duration
}

type HTTPControl struct {
	base      *url.URL
	tokenFile string
	client    *http.Client
}

func NewHTTPControl(config HTTPControlConfig) (*HTTPControl, error) {
	base, err := url.Parse(config.APIBase)
	if err != nil || base.Scheme != "http" || base.Host == "" || base.User != nil {
		return nil, fmt.Errorf("agent: API base must be a plain local HTTP URL")
	}
	if strings.TrimSpace(config.CredentialSocket) == "" || !filepath.IsAbs(config.CredentialSocket) {
		return nil, fmt.Errorf("agent: absolute credential Unix socket path is required")
	}
	if strings.TrimSpace(config.TokenFile) == "" || !filepath.IsAbs(config.TokenFile) {
		return nil, fmt.Errorf("agent: absolute service token file is required")
	}
	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Second
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		if err := validateUnixSocketPath(config.CredentialSocket); err != nil {
			return nil, err
		}
		return (&net.Dialer{}).DialContext(ctx, "unix", config.CredentialSocket)
	}
	return &HTTPControl{
		base: base, tokenFile: config.TokenFile,
		client: &http.Client{Timeout: config.Timeout, Transport: transport},
	}, nil
}

func (c *HTTPControl) FetchSnapshot(ctx context.Context, generation int64) (domain.DesiredSnapshot, error) {
	query := url.Values{}
	query.Set("generation", strconv.FormatInt(generation, 10))
	return c.fetchSnapshot(ctx, query)
}

func (c *HTTPControl) FetchLatest(ctx context.Context) (domain.DesiredSnapshot, error) {
	return c.fetchSnapshot(ctx, nil)
}

func (c *HTTPControl) fetchSnapshot(ctx context.Context, query url.Values) (domain.DesiredSnapshot, error) {
	endpoint := c.resolve("/internal/agent/v1/snapshot", query)
	request, err := c.request(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return domain.DesiredSnapshot{}, err
	}
	var snapshot domain.DesiredSnapshot
	if err := c.doJSON(request, 2<<20, &snapshot); err != nil {
		return domain.DesiredSnapshot{}, fmt.Errorf("agent: fetch snapshot: %w", err)
	}
	return snapshot, nil
}

func (c *HTTPControl) FetchCredential(ctx context.Context, mappingID string) (domain.AgentCredential, error) {
	if !safeMappingID.MatchString(mappingID) {
		return domain.AgentCredential{}, fmt.Errorf("agent: unsafe mapping id")
	}
	endpoint := c.resolve("/internal/agent/v1/mappings/"+url.PathEscape(mappingID)+"/credential", nil)
	request, err := c.request(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return domain.AgentCredential{}, err
	}
	var credential domain.AgentCredential
	if err := c.doJSON(request, 16<<10, &credential); err != nil {
		return domain.AgentCredential{}, fmt.Errorf("agent: fetch credential: %w", err)
	}
	return credential, nil
}

func (c *HTTPControl) Acknowledge(ctx context.Context, ack domain.AgentAck) error {
	payload, err := json.Marshal(ack)
	if err != nil {
		return fmt.Errorf("agent: encode ACK: %w", err)
	}
	request, err := c.request(ctx, http.MethodPost, c.resolve("/internal/agent/v1/ack", nil), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	var response domain.ReconcileState
	if err := c.doJSON(request, 32<<10, &response); err != nil {
		return fmt.Errorf("agent: send ACK: %w", err)
	}
	return nil
}

func (c *HTTPControl) request(ctx context.Context, method, endpoint string, body io.Reader) (*http.Request, error) {
	token, err := readServiceToken(c.tokenFile)
	if err != nil {
		return nil, err
	}
	defer zero(token)
	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+string(token))
	return request, nil
}

func (c *HTTPControl) doJSON(request *http.Request, limit int64, target any) error {
	response, err := c.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 32<<10))
		return fmt.Errorf("control plane returned HTTP %d", response.StatusCode)
	}
	if response.StatusCode == http.StatusNoContent {
		return nil
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, limit+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return ensureJSONEOF(decoder)
}

func (c *HTTPControl) resolve(path string, query url.Values) string {
	copyURL := *c.base
	copyURL.Path = strings.TrimRight(copyURL.Path, "/") + path
	copyURL.RawQuery = query.Encode()
	return copyURL.String()
}

func readServiceToken(path string) ([]byte, error) {
	token, err := readSecureTokenFile(path, 8<<10)
	if err != nil {
		return nil, err
	}
	token = bytes.TrimSpace(token)
	if len(token) == 0 || bytes.IndexAny(token, "\r\n\x00") >= 0 {
		zero(token)
		return nil, fmt.Errorf("agent: invalid service token")
	}
	return token, nil
}
