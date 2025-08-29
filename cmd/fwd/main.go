package main

import (
	"bufio"
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
	req, _ := http.NewRequest(http.MethodGet, strings.TrimRight(apiBase, "/")+"/v1/mappings", nil)
	req.Header.Set("Accept", "application/json")
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

func splice(a, b net.Conn) {
	defer a.Close()
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(10 * time.Minute))
	_ = b.SetDeadline(time.Now().Add(10 * time.Minute))
	io.Copy(a, b)
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
	logging.Info.Printf("[fwd] %s -> %s via %s:%d OK", c.RemoteAddr().String(), dst.String(), up.Host, up.Port)

	go splice(pc, c)
	splice(c, pc)
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
	logging.Info.Printf("pgw-fwd listening %s (transparent CONNECT) → proxy %s:%d", addr, up.Host, up.Port)

	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleConn(c, up)
	}
}
