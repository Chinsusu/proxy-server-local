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

// CheckSOCKS5 kiểm tra proxy SOCKS5 bằng cách establish connection và test qua HTTP endpoint
func CheckSOCKS5(ctx context.Context, host string, port int, user, pass *string) Result {
	// Create SOCKS5 proxy dialer
	proxyAddr := net.JoinHostPort(host, strconv.Itoa(port))
	
	// Tạo custom dialer thông qua SOCKS5 proxy
	dialer := &socksDialer{
		proxyAddr: proxyAddr,
		username:  user,
		password:  pass,
	}
	
	// Test connectivity bằng cách connect tới test endpoint
	var lastErr error
	for _, ep := range endpoints {
		start := time.Now()
		
		// Parse URL để lấy host:port cho SOCKS5
		testURL, err := url.Parse(ep)
		if err != nil {
			lastErr = err
			continue
		}
		
		testHost := testURL.Host
		if !strings.Contains(testHost, ":") {
			// Add default port cho HTTPS
			testHost = testHost + ":443"
		}
		
		// Test SOCKS5 connection
		conn, err := dialer.dialWithContext(ctx, "tcp", testHost)
		if err != nil {
			lastErr = err
			continue
		}
		
		// Perform HTTP request qua SOCKS5 connection  
		client := &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialer.dialWithContext(ctx, network, addr)
				},
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
			Timeout: 10 * time.Second,
		}
		
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ep, nil)
		req.Header.Set("User-Agent", "pgw-socks5-health/1.0")
		
		resp, err := client.Do(req)
		if err != nil {
			conn.Close()
			lastErr = err
			continue
		}
		
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		conn.Close()
		
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

// socksDialer implements basic SOCKS5 dialer
type socksDialer struct {
	proxyAddr string
	username  *string
	password  *string
}

func (d *socksDialer) dialWithContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// Connect to SOCKS5 proxy
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", d.proxyAddr)
	if err != nil {
		return nil, err
	}
	
	// SOCKS5 handshake
	if err := d.socks5Handshake(conn); err != nil {
		conn.Close()
		return nil, err
	}
	
	// SOCKS5 connect request
	if err := d.socks5Connect(conn, addr); err != nil {
		conn.Close()
		return nil, err
	}
	
	return conn, nil
}

func (d *socksDialer) socks5Handshake(conn net.Conn) error {
	// Send greeting với auth methods
	greeting := []byte{0x05} // SOCKS version 5
	
	if d.username != nil && d.password != nil {
		// Support both no-auth và username/password auth
		greeting = append(greeting, 0x02, 0x00, 0x02) // 2 methods: no-auth, username/pass
	} else {
		// Chỉ support no-auth
		greeting = append(greeting, 0x01, 0x00) // 1 method: no-auth
	}
	
	if _, err := conn.Write(greeting); err != nil {
		return err
	}
	
	// Read server response
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	
	if resp[0] != 0x05 {
		return errors.New("invalid SOCKS5 version")
	}
	
	// Handle authentication method
	switch resp[1] {
	case 0x00: // No authentication required
		return nil
	case 0x02: // Username/password authentication
		if d.username == nil || d.password == nil {
			return errors.New("server requires authentication but no credentials provided")
		}
		return d.socks5Auth(conn)
	case 0xFF: // No acceptable methods
		return errors.New("no acceptable authentication methods")
	default:
		return errors.New("unsupported authentication method")
	}
}

func (d *socksDialer) socks5Auth(conn net.Conn) error {
	// Send username/password authentication
	user := *d.username
	pass := *d.password
	
	if len(user) > 255 || len(pass) > 255 {
		return errors.New("username or password too long")
	}
	
	req := []byte{0x01} // auth version
	req = append(req, byte(len(user)))
	req = append(req, []byte(user)...)
	req = append(req, byte(len(pass)))
	req = append(req, []byte(pass)...)
	
	if _, err := conn.Write(req); err != nil {
		return err
	}
	
	// Read auth response
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	
	if resp[0] != 0x01 {
		return errors.New("invalid auth response version")
	}
	
	if resp[1] != 0x00 {
		return errors.New("authentication failed")
	}
	
	return nil
}

func (d *socksDialer) socks5Connect(conn net.Conn, addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}
	
	// Build connect request
	req := []byte{0x05, 0x01, 0x00} // ver, cmd=connect, reserved
	
	// Address type và address
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			// IPv4
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			// IPv6
			req = append(req, 0x04)
			req = append(req, ip...)
		}
	} else {
		// Domain name
		if len(host) > 255 {
			return errors.New("domain name too long")
		}
		req = append(req, 0x03)
		req = append(req, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	
	// Port (2 bytes, big endian)
	req = append(req, byte(port>>8), byte(port&0xff))
	
	if _, err := conn.Write(req); err != nil {
		return err
	}
	
	// Read connect response
	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	
	if resp[0] != 0x05 {
		return errors.New("invalid SOCKS5 response version")
	}
	
	if resp[1] != 0x00 {
		return errors.New("SOCKS5 connect failed with code: " + strconv.Itoa(int(resp[1])))
	}
	
	// Skip bound address (we don't need it for our use case)
	switch resp[3] {
	case 0x01: // IPv4
		if _, err := io.ReadFull(conn, make([]byte, 4+2)); err != nil {
			return err
		}
	case 0x03: // Domain name
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, make([]byte, int(length[0])+2)); err != nil {
			return err
		}
	case 0x04: // IPv6
		if _, err := io.ReadFull(conn, make([]byte, 16+2)); err != nil {
			return err
		}
	}
	
	return nil
}
