package types

import "time"

type ProxyStatus string

const (
	StatusOK      ProxyStatus = "OK"
	StatusDegraded            = "DEGRADED"
	StatusDown                = "DOWN"
)

type Proxy struct {
	ID            string      `json:"id"`
	Label         string      `json:"label,omitempty"`
	Type          string      `json:"type"` // "http" | "socks5"
	Host          string      `json:"host"`
	Port          int         `json:"port"`
	Username      *string     `json:"username,omitempty"`
	Password      *string     `json:"password,omitempty"`
	Enabled       bool        `json:"enabled"`
	Status        ProxyStatus `json:"status"`
	LatencyMs     *int        `json:"latency_ms,omitempty"`
	ExitIP        *string     `json:"exit_ip,omitempty"`
	LastCheckedAt *time.Time  `json:"last_checked_at,omitempty"`
}

type Client struct {
	ID      string `json:"id"`
	IPCidr  string `json:"ip_cidr"`
	Note    string `json:"note,omitempty"`
	Enabled bool   `json:"enabled"`
}

type Mapping struct {
	ID                string     `json:"id"`
	ClientID          string     `json:"client_id"`
	ProxyID           string     `json:"proxy_id"`
	Protocol          string     `json:"protocol"` // "http" | "socks5"
	LocalRedirectPort int        `json:"local_redirect_port"`
	State             string     `json:"state"` // "APPLIED" | "PENDING" | "FAILED"
	LastAppliedAt     *time.Time `json:"last_applied_at,omitempty"`
}

type MappingView struct {
	ID                string `json:"id"`
	Client            Client `json:"client"`
	Proxy             Proxy  `json:"proxy"`
	State             string `json:"state"`
	LocalRedirectPort int    `json:"local_redirect_port"`
}
