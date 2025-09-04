package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/Chinsusu/proxy-server-local/pkg/logging"
	"github.com/Chinsusu/proxy-server-local/pkg/types"
)

const SO_ORIGINAL_DST = 80

type upstream struct {
	Type string
	Host string
	Port int
	User string
	Pass string
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func resolveUpstream(apiBase string, localPort int) (*upstream, error) {
	req, _ := http.NewRequest(http.MethodGet, strings.TrimRight(apiBase, "/")+"/v1/mappings/active", nil)
	req.Header.Set("Accept", "application/json")
	if tok := os.Getenv("PGW_AGENT_TOKEN"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch mappings: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("mappings %s: %s", resp.Status, string(b))
	}
	var mvs []types.MappingView
	if err := json.NewDecoder(resp.Body).Decode(&mvs); err != nil {
		return nil, err
	}
	for _, mv := range mvs {
		if mv.LocalRedirectPort == localPort && mv.Proxy.Enabled {
			user := ""
			pass := ""
			if mv.Proxy.Username != nil {
				user = *mv.Proxy.Username
			}
			if mv.Proxy.Password != nil {
				pass = *mv.Proxy.Password
			}
			return &upstream{
				Type: mv.Proxy.Type,
				Host: mv.Proxy.Host,
				Port: mv.Proxy.Port,
				User: user,
				Pass: pass,
			}, nil
		}
	}
	return nil, fmt.Errorf("no mapping for local port %d", localPort)
}

func getOriginalDst(conn *net.TCPConn) (*net.TCPAddr, error) {
	var addr syscall.RawSockaddrInet4
	sz := uint32(unsafe.Sizeof(addr))
	var serr error
	rc, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	err = rc.Control(func(fd uintptr) {
		_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT,
			fd,
			uintptr(syscall.SOL_IP),
			uintptr(SO_ORIGINAL_DST),
			uintptr(unsafe.Pointer(&addr)),
			uintptr(unsafe.Pointer(&sz)),
			0,
		)
		if e != 0 {
			serr = e
		}
	})
	if err != nil {
		return nil, err
	}
	if serr != nil {
		return nil, serr
	}
	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	port := int(binary.BigEndian.Uint16((*(*[2]byte)(unsafe.Pointer(&addr.Port)))[:]))
	return &net.TCPAddr{IP: ip, Port: port}, nil
}

func dialViaProxy(up *upstream, dst *net.TCPAddr) (net.Conn, error) {
	proxyAddr := fmt.Sprintf("%s:%d", up.Host, up.Port)
	pc, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial proxy %s: %w", proxyAddr, err)
	}
	dstHP := net.JoinHostPort(dst.IP.String(), fmt.Sprintf("%d", dst.Port))
	auth := ""
	if up.User != "" || up.Pass != "" {
		b64 := base64.StdEncoding.EncodeToString([]byte(up.User + ":" + up.Pass))
		auth = "Proxy-Authorization: Basic " + b64 + "\r\n"
	}
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n%sProxy-Connection: Keep-Alive\r\nConnection: Keep-Alive\r\n\r\n",
		dstHP, dstHP, auth)
	if _, err := io.WriteString(pc, req); err != nil {
		pc.Close()
		return nil, fmt.Errorf("write CONNECT: %w", err)
	}
	br := bufio.NewReader(pc)
	status, err := br.ReadString('\n')
	if err != nil {
		pc.Close()
		return nil, fmt.Errorf("read CONNECT status: %w", err)
	}
	if !strings.HasPrefix(status, "HTTP/1.1 200") && !strings.HasPrefix(status, "HTTP/1.0 200") {
		// drain headers
		for {
			line, e := br.ReadString('\n')
			if e != nil || line == "\r\n" {
				break
			}
		}
		pc.Close()
		return nil, fmt.Errorf("proxy refused CONNECT: %s", strings.TrimSpace(status))
	}
	// consume remaining headers
	for {
		line, e := br.ReadString('\n')
		if e != nil {
			pc.Close()
			return nil, fmt.Errorf("read headers: %w", e)
		}
		if line == "\r\n" {
			break
		}
	}
	return pc, nil
}

func dialViaSOCKS5(up *upstream, dst *net.TCPAddr) (net.Conn, error) {
	proxyAddr := fmt.Sprintf("%s:%d", up.Host, up.Port)
	pc, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial SOCKS5 proxy %s: %w", proxyAddr, err)
	}

	// SOCKS5 handshake
	if err := socks5Handshake(pc, up.User, up.Pass); err != nil {
		pc.Close()
		return nil, fmt.Errorf("SOCKS5 handshake failed: %w", err)
	}

	// SOCKS5 connect request
	if err := socks5Connect(pc, dst.IP.String(), dst.Port); err != nil {
		pc.Close()
		return nil, fmt.Errorf("SOCKS5 connect failed: %w", err)
	}

	return pc, nil
}

func socks5Handshake(conn net.Conn, username, password string) error {
	// Send greeting with auth methods
	greeting := []byte{0x05} // SOCKS version 5
	
	if username != "" || password != "" {
		// Support both no-auth and username/password auth
		greeting = append(greeting, 0x02, 0x00, 0x02) // 2 methods: no-auth, username/pass
	} else {
		// Only support no-auth
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
		return fmt.Errorf("invalid SOCKS5 version: %d", resp[0])
	}
	
	// Handle authentication method
	switch resp[1] {
	case 0x00: // No authentication required
		return nil
	case 0x02: // Username/password authentication
		if username == "" && password == "" {
			return fmt.Errorf("server requires authentication but no credentials provided")
		}
		return socks5Auth(conn, username, password)
	case 0xFF: // No acceptable methods
		return fmt.Errorf("no acceptable authentication methods")
	default:
		return fmt.Errorf("unsupported authentication method: %d", resp[1])
	}
}

func socks5Auth(conn net.Conn, username, password string) error {
	if len(username) > 255 || len(password) > 255 {
		return fmt.Errorf("username or password too long")
	}
	
	req := []byte{0x01} // auth version
	req = append(req, byte(len(username)))
	req = append(req, []byte(username)...)
	req = append(req, byte(len(password)))
	req = append(req, []byte(password)...)
	
	if _, err := conn.Write(req); err != nil {
		return err
	}
	
	// Read auth response
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	
	if resp[0] != 0x01 {
		return fmt.Errorf("invalid auth response version: %d", resp[0])
	}
	
	if resp[1] != 0x00 {
		return fmt.Errorf("authentication failed")
	}
	
	return nil
}

func socks5Connect(conn net.Conn, host string, port int) error {
	// Build connect request
	req := []byte{0x05, 0x01, 0x00} // ver, cmd=connect, reserved
	
	// Address type and address
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
			return fmt.Errorf("domain name too long")
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
		return fmt.Errorf("invalid SOCKS5 response version: %d", resp[0])
	}
	
	if resp[1] != 0x00 {
		return fmt.Errorf("SOCKS5 connect failed with code: %d", resp[1])
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

func parseHTTPHost(b []byte) (string, bool) {
	// read up to first \r\n\r\n
	idx := bytes.Index(b, []byte("\r\n\r\n"))
	head := b
	if idx >= 0 {
		head = b[:idx]
	}
	// first line must look like "GET / HTTP/1.1" etc, not strict
	if !bytes.Contains(head, []byte(" HTTP/")) {
		return "", false
	}
	for _, line := range bytes.Split(head, []byte("\r\n")) {
		if len(line) == 0 {
			continue
		}
		// case-insensitive "Host:"
		if len(line) >= 5 && (line[0] == 'H' || line[0] == 'h') && bytes.HasPrefix(bytes.ToLower(line), []byte("host:")) {
			v := strings.TrimSpace(string(line[5:]))
			v = strings.TrimLeft(v, ": ")
			if v != "" {
				// strip port if any
				if h, _, err := net.SplitHostPort(v); err == nil {
					return h, true
				}
				return v, true
			}
		}
	}
	return "", false
}

// minimal TLS ClientHello SNI parser
func parseTLSSNI(b []byte) (string, bool) {
	// need at least record header (5) + handshake hdr (4)
	if len(b) < 9 {
		return "", false
	}
	// TLS record type 0x16 (handshake)
	if b[0] != 0x16 {
		return "", false
	}
	// handshake type 0x01 (ClientHello)
	if b[5] != 0x01 {
		return "", false
	}
	// skip: record(5) + hs_type(1) + hs_len(3) + version(2) + random(32)
	i := 5 + 1 + 3 + 2 + 32
	if len(b) < i+1 {
		return "", false
	}
	// session id
	sidLen := int(b[i])
	i += 1 + sidLen
	if len(b) < i+2 {
		return "", false
	}
	// cipher suites
	csLen := int(binary.BigEndian.Uint16(b[i : i+2]))
	i += 2 + csLen
	if len(b) < i+1 {
		return "", false
	}
	// compression methods
	compLen := int(b[i])
	i += 1 + compLen
	if len(b) < i+2 {
		return "", false
	}
	// extensions
	extLen := int(binary.BigEndian.Uint16(b[i : i+2]))
	i += 2
	if len(b) < i+extLen {
		extLen = len(b) - i
	}
	j := i
	for j+4 <= i+extLen {
		etype := binary.BigEndian.Uint16(b[j : j+2])
		elen := int(binary.BigEndian.Uint16(b[j+2 : j+4]))
		j += 4
		if etype == 0 { // server_name
			k := j
			if k+2 > j+elen {
				break
			}
			listLen := int(binary.BigEndian.Uint16(b[k : k+2]))
			k += 2
			end := k + listLen
			for k+3 <= end && k+3 <= len(b) {
				nameType := b[k]
				k += 1
				if k+2 > end {
					break
				}
				hostLen := int(binary.BigEndian.Uint16(b[k : k+2]))
				k += 2
				if k+hostLen > end || k+hostLen > len(b) {
					break
				}
				if nameType == 0 && hostLen > 0 {
					return string(b[k : k+hostLen]), true
				}
				k += hostLen
			}
		}
		j += elen
	}
	return "", false
}

func maskLabel(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 2 {
		return s[:1] + "*"
	}
	return s[:1] + strings.Repeat("*", len(s)-2) + s[len(s)-1:]
}

func maskHost(h string) string {
	if ip := net.ParseIP(h); ip != nil {
		return ip.String()
	}
	parts := strings.Split(h, ".")
	if len(parts) <= 1 {
		return maskLabel(h)
	}
	parts[0] = maskLabel(parts[0])
	return strings.Join(parts, ".")
}

func splice(dst, src net.Conn) {
	_ = dst.SetDeadline(time.Now().Add(10 * time.Minute))
	_ = src.SetDeadline(time.Now().Add(10 * time.Minute))
	io.Copy(dst, src)
}

func handleConn(c net.Conn, up *upstream) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		c.Close()
		return
	}
	defer c.Close()

	dst, err := getOriginalDst(tc)
	if err != nil {
		logging.Error.Printf("[fwd] SO_ORIGINAL_DST err: %v", err)
		return
	}

	var pc net.Conn
	if up.Type == "socks5" {
		pc, err = dialViaSOCKS5(up, dst)
	} else {
		pc, err = dialViaProxy(up, dst)
	}

	if err != nil {
		logging.Error.Printf("[fwd] CONNECT %s via %s %s:%d failed: %v", dst.String(), up.Type, up.Host, up.Port, err)
		return
	}

	// Peek a little from client to extract Host/SNI, forward those bytes to proxy, then splice
	var host string
	buf := make([]byte, 2048)
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	n, _ := c.Read(buf)
	_ = c.SetReadDeadline(time.Time{})
	if n > 0 {
		if h, ok := parseHTTPHost(buf[:n]); ok {
			host = h
		} else if h, ok := parseTLSSNI(buf[:n]); ok {
			host = h
		}
		// forward preface to proxy
		if _, err := pc.Write(buf[:n]); err != nil {
			logging.Error.Printf("[fwd] prewrite to proxy failed: %v", err)
			return
		}
	}

	if host != "" {
		logging.Info.Printf("[fwd] %s -> %s host=%s via %s %s:%d OK",
			c.RemoteAddr().String(), dst.String(), maskHost(host), up.Type, up.Host, up.Port)
	} else {
		logging.Info.Printf("[fwd] %s -> %s via %s %s:%d OK",
			c.RemoteAddr().String(), dst.String(), up.Type, up.Host, up.Port)
	}

	// splice both directions
	go splice(pc, c) // proxy -> client
	splice(c, pc)    // client -> proxy
}

func main() {
	addr := env("PGW_FWD_ADDR", ":15001")
	api := env("PGW_API_BASE", "http://127.0.0.1:8080")

	localPort := 15001
	if strings.HasPrefix(addr, ":") {
		fmt.Sscanf(addr, ":%d", &localPort)
	}
	up, err := resolveUpstream(api, localPort)
	if err != nil {
		logging.Error.Fatalf("[fwd] resolve upstream: %v", err)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logging.Error.Fatalf("[fwd] listen %s: %v", addr, err)
	}
	logging.Info.Printf("pgw-fwd listening %s (transparent CONNECT+SNI) → %s proxy %s:%d", addr, up.Type, up.Host, up.Port)

	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleConn(c, up)
	}
}
