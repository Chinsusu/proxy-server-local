package check

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Chinsusu/proxy-server-local/pkg/types"
)

type Result struct {
	Status    types.ProxyStatus `json:"status"`
	LatencyMs int               `json:"latency_ms"`
	ExitIP    string            `json:"exit_ip"`
	Err       error             `json:"-"`
}

// Nhiều endpoint để tăng khả năng thành công
var endpoints = []string{
	"https://api.ipify.org?format=text",
	"https://ifconfig.me/ip",
	"https://icanhazip.com/",
}

func CheckHTTP(ctx context.Context, host string, port int, user, pass *string) Result {
	// proxy URL: http://user:pass@host:port
	u := &url.URL{Scheme: "http", Host: net.JoinHostPort(host, strconv.Itoa(port))}
	if user != nil && pass != nil {
		u.User = url.UserPassword(*user, *pass)
	}

	tr := &http.Transport{
		Proxy: http.ProxyURL(u),
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   7 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       15 * time.Second,
		MaxIdleConns:          32,
		MaxConnsPerHost:       32,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	client := &http.Client{Transport: tr}

	var lastErr error
	for _, ep := range endpoints {
		start := time.Now()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ep, nil)
		req.Header.Set("User-Agent", "pgw-health/1.0")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			lastErr = errors.New("non-200: " + resp.Status)
			continue
		}
		ip := strings.TrimSpace(string(b))
		elapsed := time.Since(start)
		return Result{
			Status:    classifyLatency(elapsed),
			LatencyMs: int(elapsed.Milliseconds()),
			ExitIP:    ip,
			Err:       nil,
		}
	}
	return Result{Status: types.StatusDown, Err: lastErr}
}

func classifyLatency(d time.Duration) types.ProxyStatus {
	switch ms := d.Milliseconds(); {
	case ms < 500:
		return types.StatusOK
	case ms < 900:
		return types.StatusDegraded
	default:
		return types.StatusDown
	}
}
