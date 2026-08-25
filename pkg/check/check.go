package check

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
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

// tcpProbeTarget is the destination we attempt to establish a TCP tunnel to via the proxy.
const tcpProbeTarget = "google.com:443"
const maxConnectResponseHeaderBytes = 16 << 10

var httpConnectResponseTimeout = 10 * time.Second

// IP check endpoints (lightweight)
var ipCheckEndpoints = []string{
	"https://api.ipify.org?format=text",
	"https://ifconfig.me/ip",
	"https://icanhazip.com/",
}

func CheckHTTP(ctx context.Context, host string, port int, user *string, pass *[]byte) Result {
	// Measure latency to establish an HTTP CONNECT tunnel to tcpProbeTarget via the HTTP proxy.
	start := time.Now()
	conn, err := dialHTTPConnect(ctx, host, port, tcpProbeTarget, user, pass)
	if err != nil {
		return Result{Status: types.StatusDown, Err: err}
	}
	elapsed := time.Since(start)
	_ = conn.Close()

	// Fetch exit IP via separate connection through the proxy
	exitIP := fetchExitIPViaHTTPProxy(ctx, host, port, user, pass)

	return Result{
		Status:    classifyLatency(elapsed),
		LatencyMs: int(elapsed.Milliseconds()),
		ExitIP:    exitIP,
		Err:       nil,
	}
}

// dialHTTPConnect writes a CONNECT request itself instead of placing the
// credential in http.Header or Transport. Those APIs retain immutable header
// strings beyond the request lifetime. Every buffer containing credentials is
// mutable and cleared immediately after write.
func dialHTTPConnect(ctx context.Context, host string, port int, target string, user *string, pass *[]byte) (net.Conn, error) {
	proxyAddr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = conn.Close()
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(httpConnectResponseTimeout))
	request := make([]byte, 0, len(target)+256)
	request = append(request, "CONNECT "...)
	request = append(request, target...)
	request = append(request, " HTTP/1.1\r\nHost: "...)
	request = append(request, target...)
	request = append(request, "\r\nUser-Agent: pgw-tcp-health/1.0\r\n"...)
	if user != nil && pass != nil {
		request = append(request, "Proxy-Authorization: Basic "...)
		credential := make([]byte, 0, len(*user)+1+len(*pass))
		credential = append(credential, (*user)...)
		credential = append(credential, ':')
		credential = append(credential, (*pass)...)
		encodedAt := len(request)
		request = append(request, make([]byte, base64.StdEncoding.EncodedLen(len(credential)))...)
		base64.StdEncoding.Encode(request[encodedAt:], credential)
		wipeBytes(credential)
		request = append(request, "\r\n"...)
	}
	request = append(request, "\r\n"...)
	defer wipeBytes(request)
	if _, err := conn.Write(request); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(conn)
	if err := readHTTPConnectResponse(reader); err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	closeOnError = false
	return &bufferedConn{Conn: conn, reader: reader}, nil
}

// bufferedConn preserves bytes that bufio.Reader fetched together with a
// successful CONNECT response. A CONNECT tunnel has no HTTP response body;
// using http.ReadResponse and closing/draining Body can consume tunnel bytes
// when a standards-compliant 200 omits Content-Length.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (conn *bufferedConn) Read(value []byte) (int, error) { return conn.reader.Read(value) }

func readHTTPConnectResponse(reader *bufio.Reader) error {
	consumed := 0
	readLine := func() ([]byte, error) {
		line := make([]byte, 0, 128)
		for {
			if consumed >= maxConnectResponseHeaderBytes {
				return nil, errors.New("CONNECT response headers too large")
			}
			value, err := reader.ReadByte()
			if err != nil {
				return nil, err
			}
			consumed++
			line = append(line, value)
			if value == '\n' {
				break
			}
		}
		if len(line) < 2 || line[len(line)-2] != '\r' || line[len(line)-1] != '\n' {
			return nil, errors.New("malformed CONNECT response")
		}
		return line[:len(line)-2], nil
	}
	status, err := readLine()
	if err != nil {
		return err
	}
	parts := strings.Fields(string(status))
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return errors.New("malformed CONNECT response")
	}
	statusCode, err := strconv.Atoi(parts[1])
	if err != nil || statusCode < 100 || statusCode > 999 {
		return errors.New("malformed CONNECT response")
	}
	for {
		line, err := readLine()
		if err != nil {
			return err
		}
		if len(line) == 0 {
			break
		}
		if !bytes.Contains(line, []byte(":")) {
			return errors.New("malformed CONNECT response header")
		}
	}
	if statusCode != http.StatusOK {
		return errors.New("non-200 CONNECT response")
	}
	return nil
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

// CheckSOCKS5 kiểm tra proxy SOCKS5 bằng cách đo thời gian thiết lập kết nối TCP tới tcpProbeTarget qua proxy
func CheckSOCKS5(ctx context.Context, host string, port int, user *string, pass *[]byte) Result {
	// Create SOCKS5 proxy dialer
	proxyAddr := net.JoinHostPort(host, strconv.Itoa(port))

	dialer := &socksDialer{
		proxyAddr: proxyAddr,
		username:  user,
		password:  pass,
	}

	start := time.Now()
	conn, err := dialer.dialWithContext(ctx, "tcp", tcpProbeTarget)
	if err != nil {
		return Result{Status: types.StatusDown, Err: err}
	}

	elapsed := time.Since(start)
	_ = conn.Close()

	// Fetch exit IP via separate connection through the SOCKS5 proxy
	exitIP := fetchExitIPViaSOCKS5(ctx, host, port, user, pass)

	return Result{
		Status:    classifyLatency(elapsed),
		LatencyMs: int(elapsed.Milliseconds()),
		ExitIP:    exitIP,
		Err:       nil,
	}
}

// fetchExitIPViaHTTPProxy makes a separate HTTP request through the proxy to get the exit IP
func fetchExitIPViaHTTPProxy(ctx context.Context, host string, port int, user *string, pass *[]byte) string {
	for _, endpoint := range ipCheckEndpoints {
		endpointURL, err := url.Parse(endpoint)
		if err != nil {
			continue
		}
		target := endpointURL.Host
		if endpointURL.Port() == "" {
			target = net.JoinHostPort(endpointURL.Hostname(), "443")
		}
		conn, err := dialHTTPConnect(ctx, host, port, target, user, pass)
		if err != nil {
			continue
		}
		tlsConn := tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: endpointURL.Hostname()})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			continue
		}
		path := endpointURL.EscapedPath()
		if path == "" {
			path = "/"
		}
		if endpointURL.RawQuery != "" {
			path += "?" + endpointURL.RawQuery
		}
		req := &http.Request{Method: http.MethodGet, URL: &url.URL{Path: path}, Host: endpointURL.Host, Header: http.Header{"User-Agent": []string{"pgw-ip-check/1.0"}}}
		if err := req.Write(tlsConn); err != nil {
			_ = conn.Close()
			continue
		}
		resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
		if err != nil {
			_ = conn.Close()
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
		_ = resp.Body.Close()
		_ = conn.Close()

		if err != nil || resp.StatusCode != 200 {
			continue
		}

		ip := strings.TrimSpace(string(body))
		if ip != "" {
			return ip
		}
	}

	return ""
}

// fetchExitIPViaSOCKS5 makes a separate HTTP request through the SOCKS5 proxy to get the exit IP
func fetchExitIPViaSOCKS5(ctx context.Context, host string, port int, user *string, pass *[]byte) string {
	proxyAddr := net.JoinHostPort(host, strconv.Itoa(port))

	dialer := &socksDialer{
		proxyAddr: proxyAddr,
		username:  user,
		password:  pass,
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.dialWithContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   8 * time.Second,
	}

	for _, endpoint := range ipCheckEndpoints {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "pgw-ip-check/1.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()

		if err != nil || resp.StatusCode != 200 {
			continue
		}

		ip := strings.TrimSpace(string(body))
		if ip != "" {
			return ip
		}
	}

	return ""
}

// socksDialer implements basic SOCKS5 dialer
type socksDialer struct {
	proxyAddr string
	username  *string
	password  *[]byte
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

	req := make([]byte, 0, 3+len(user)+len(pass))
	req = append(req, 0x01) // auth version
	defer wipeSOCKSAuthRequest(req)
	req = append(req, byte(len(user)))
	req = append(req, user...)
	req = append(req, byte(len(pass)))
	req = append(req, pass...)

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

// socksAuthWipeHook is test-only evidence that the final backing slice—not
// merely its pre-append prefix—was erased. Production leaves it nil.
var socksAuthWipeHook func([]byte)

func wipeSOCKSAuthRequest(request []byte) {
	full := request[:cap(request)]
	wipeBytes(full)
	if socksAuthWipeHook != nil {
		socksAuthWipeHook(append([]byte(nil), full...))
	}
}

func wipeBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
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
