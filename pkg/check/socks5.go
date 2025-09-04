package check

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/Chinsusu/proxy-server-local/pkg/types"
)

var socksTargets = []struct {
	host string
	port int
	path string
}{
	{"api.ipify.org", 80, "/?format=text"},
	{"ifconfig.me", 80, "/ip"},
	{"icanhazip.com", 80, "/"},
}

func CheckSOCKS5(ctx context.Context, host string, port int, user, pass *string) Result {
	var lastErr error
	for _, t := range socksTargets {
		start := time.Now()
		// dial proxy
		d := net.Dialer{Timeout: 8 * time.Second}
		pc, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
		if err != nil {
			lastErr = err
			continue
		}
		// deadline tie to context
		if dl, ok := ctx.Deadline(); ok {
			_ = pc.SetDeadline(dl)
		}
		// greeting
		methods := []byte{0x00}
		if user != nil && pass != nil && *user != "" || *pass != "" {
			methods = []byte{0x00, 0x02}
		}
		if _, err := pc.Write([]byte{0x05, byte(len(methods))}); err != nil {
			pc.Close()
			lastErr = err
			continue
		}
		if _, err := pc.Write(methods); err != nil {
			pc.Close()
			lastErr = err
			continue
		}
		sel := make([]byte, 2)
		if _, err := io.ReadFull(pc, sel); err != nil {
			pc.Close()
			lastErr = err
			continue
		}
		if sel[0] != 0x05 {
			pc.Close()
			lastErr = fmt.Errorf("bad ver")
			continue
		}
		if sel[1] == 0xff {
			pc.Close()
			lastErr = fmt.Errorf("no acceptable auth")
			continue
		}
		if sel[1] == 0x02 {
			u := ""
			p := ""
			if user != nil {
				u = *user
			}
			if pass != nil {
				p = *pass
			}
			if len(u) > 255 || len(p) > 255 {
				pc.Close()
				lastErr = fmt.Errorf("cred too long")
				continue
			}
			pkt := append([]byte{0x01, byte(len(u))}, []byte(u)...)
			pkt = append(pkt, byte(len(p)))
			pkt = append(pkt, []byte(p)...)
			if _, err := pc.Write(pkt); err != nil {
				pc.Close()
				lastErr = err
				continue
			}
			rp := make([]byte, 2)
			if _, err := io.ReadFull(pc, rp); err != nil {
				pc.Close()
				lastErr = err
				continue
			}
			if rp[1] != 0x00 {
				pc.Close()
				lastErr = fmt.Errorf("auth failed")
				continue
			}
		}
		// CONNECT to domain:port (ATYP=0x03)
		dom := []byte(t.host)
		if len(dom) > 255 {
			pc.Close()
			lastErr = fmt.Errorf("host too long")
			continue
		}
		req := append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(dom))}, dom...)
		req = append(req, byte(t.port>>8), byte(t.port))
		if _, err := pc.Write(req); err != nil {
			pc.Close()
			lastErr = err
			continue
		}
		hdr := make([]byte, 4)
		if _, err := io.ReadFull(pc, hdr); err != nil {
			pc.Close()
			lastErr = err
			continue
		}
		if hdr[1] != 0x00 {
			pc.Close()
			lastErr = fmt.Errorf("connect REP=0x%02x", hdr[1])
			continue
		}
		var toRead int
		switch hdr[3] {
		case 0x01:
			toRead = 4 + 2
		case 0x03:
			lb := make([]byte, 1)
			if _, err := io.ReadFull(pc, lb); err != nil {
				pc.Close()
				lastErr = err
				continue
			}
			toRead = int(lb[0]) + 2
		case 0x04:
			toRead = 16 + 2
		default:
			pc.Close()
			lastErr = fmt.Errorf("bad ATYP")
			continue
		}
		junk := make([]byte, toRead)
		if _, err := io.ReadFull(pc, junk); err != nil {
			pc.Close()
			lastErr = err
			continue
		}

		// HTTP GET to retrieve exit IP
		br := bufio.NewReadWriter(bufio.NewReader(pc), bufio.NewWriter(pc))
		reqLine := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: pgw-health/1.0\r\nConnection: close\r\n\r\n", t.path, t.host)
		if _, err := br.WriteString(reqLine); err != nil {
			pc.Close()
			lastErr = err
			continue
		}
		if err := br.Flush(); err != nil {
			pc.Close()
			lastErr = err
			continue
		}
		status, err := br.ReadString('\n')
		if err != nil {
			pc.Close()
			lastErr = err
			continue
		}
		if !strings.Contains(status, "200") {
			// drain headers anyway
			for {
				line, e := br.ReadString('\n')
				if e != nil || line == "\r\n" {
					break
				}
			}
			pc.Close()
			lastErr = fmt.Errorf("non-200: %s", strings.TrimSpace(status))
			continue
		}
		// read headers until CRLF
		for {
			line, e := br.ReadString('\n')
			if e != nil {
				pc.Close()
				lastErr = e
				break
			}
			if line == "\r\n" {
				break
			}
		}
		body, _ := io.ReadAll(br)
		pc.Close()
		ip := strings.TrimSpace(string(body))
		elapsed := time.Since(start)
		return Result{Status: classifyLatency(elapsed), LatencyMs: int(elapsed.Milliseconds()), ExitIP: ip, Err: nil}
	}
	return Result{Status: types.StatusDown, Err: lastErr}
}
