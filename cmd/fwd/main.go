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


func dialViaHTTP(up *upstream, dst *net.TCPAddr) (net.Conn, error) {
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
    req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n%sProxy-Connection: Keep-Alive\r\nConnection: Keep-Alive\r\n\r\n", dstHP, dstHP, auth)
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
        for {
            line, e := br.ReadString('\n')
            if e != nil || line == "\r\n" {
                break
            }
        }
        pc.Close()
        return nil, fmt.Errorf("proxy refused CONNECT: %s", strings.TrimSpace(status))
    }
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
        return nil, fmt.Errorf("dial socks5 %s: %w", proxyAddr, err)
    }
    // greeting
    methods := []byte{0x00}
    if up.User != "" || up.Pass != "" { methods = []byte{0x00, 0x02} }
    if _, err := pc.Write([]byte{0x05, byte(len(methods))}); err != nil { pc.Close(); return nil, err }
    if _, err := pc.Write(methods); err != nil { pc.Close(); return nil, err }
    sel := make([]byte, 2)
    if _, err := io.ReadFull(pc, sel); err != nil { pc.Close(); return nil, err }
    if sel[0] != 0x05 { pc.Close(); return nil, fmt.Errorf("bad ver") }
    if sel[1] == 0xff { pc.Close(); return nil, fmt.Errorf("no acceptable auth") }
    if sel[1] == 0x02 {
        u := []byte(up.User); p := []byte(up.Pass)
        if len(u) > 255 || len(p) > 255 { pc.Close(); return nil, fmt.Errorf("cred too long") }
        pkt := append([]byte{0x01, byte(len(u))}, u...)
        pkt = append(pkt, byte(len(p)))
        pkt = append(pkt, p...)
        if _, err := pc.Write(pkt); err != nil { pc.Close(); return nil, err }
        rp := make([]byte, 2)
        if _, err := io.ReadFull(pc, rp); err != nil { pc.Close(); return nil, err }
        if rp[1] != 0x00 { pc.Close(); return nil, fmt.Errorf("auth failed") }
    }
    // connect to destination (IPv4 only)
    ip4 := dst.IP.To4()
    if ip4 == nil { pc.Close(); return nil, fmt.Errorf("only IPv4 dst supported") }
    req := []byte{0x05, 0x01, 0x00, 0x01, ip4[0], ip4[1], ip4[2], ip4[3], byte(dst.Port>>8), byte(dst.Port)}
    if _, err := pc.Write(req); err != nil { pc.Close(); return nil, err }
    hdr := make([]byte, 4)
    if _, err := io.ReadFull(pc, hdr); err != nil { pc.Close(); return nil, err }
    if hdr[1] != 0x00 { pc.Close(); return nil, fmt.Errorf("socks connect failed REP=0x%02x", hdr[1]) }
    var toRead int
    switch hdr[3] {
    case 0x01: toRead = 4 + 2
    case 0x03:
        lb := make([]byte,1); if _,err:=io.ReadFull(pc,lb); err!=nil { pc.Close(); return nil, err }
        toRead = int(lb[0]) + 2
    case 0x04: toRead = 16 + 2
    default: pc.Close(); return nil, fmt.Errorf("bad ATYP")
    }
    junk := make([]byte, toRead)
    if _, err := io.ReadFull(pc, junk); err != nil { pc.Close(); return nil, err }
    return pc, nil
}

func dialViaProxy(up *upstream, dst *net.TCPAddr) (net.Conn, error) {
    t := strings.ToLower(strings.TrimSpace(up.Type))
    if t == "socks5" || t == "socks" { return dialViaSOCKS5(up, dst) }
    return dialViaHTTP(up, dst)
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

	pc, err := dialViaProxy(up, dst)
	if err != nil {
		logging.Error.Printf("[fwd] CONNECT %s via %s:%d failed: %v", dst.String(), up.Host, up.Port, err)
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
		logging.Info.Printf("[fwd] %s -> %s host=%s via %s:%d OK",
			c.RemoteAddr().String(), dst.String(), maskHost(host), up.Type, up.Host, up.Port)
	} else {
		logging.Info.Printf("[fwd] %s -> %s via %s:%d OK",
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
	logging.Info.Printf("pgw-fwd listening %s (transparent CONNECT+SNI) → %s %s:%d", addr, up.Type, up.Host, up.Port)

	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleConn(c, up)
	}
}
