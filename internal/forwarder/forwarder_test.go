package forwarder

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Chinsusu/proxy-server-local/pkg/observability"
)

func validConfig(address string) Config {
	return Config{
		Version:       1,
		MappingID:     "mapping_01",
		ListenAddress: address,
		ProxyType:     "http",
		ProxyHost:     "198.51.100.30",
		ProxyPort:     443,
	}
}

func TestReadConfigRejectsSecretAndUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "forwarder.json")
	cfg := validConfig("127.0.0.1:15001")
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b[:len(b)-1], []byte(`,"password":"must-not-be-here"}`)...), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadConfig(path); err == nil {
		t.Fatal("secret-bearing config was accepted")
	}
}

func TestReadConfigRejectsMultiValueAndWritableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "forwarder.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"mapping_id":"mapping_01","listen_address":"127.0.0.1:15001","proxy_type":"http","proxy_host":"example.test","proxy_port":443} {}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadConfig(path); err == nil {
		t.Fatal("multiple JSON values were accepted")
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"mapping_id":"mapping_01","listen_address":"127.0.0.1:15001","proxy_type":"http","proxy_host":"example.test","proxy_port":443}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o666 {
		t.Fatalf("unsafe config mode = %04o, want 0666", got)
	}
	defer func() {
		if err := os.Chmod(path, 0o640); err != nil {
			t.Errorf("restore safe config mode: %v", err)
		}
	}()
	if _, err := ReadConfig(path); err == nil {
		t.Fatal("world-writable config was accepted")
	}
}

func TestReadConfigRejectsDuplicateJSONKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "forwarder.json")
	payload := `{"version":1,"mapping_id":"mapping_01","mapping_id":"mapping_02","listen_address":"127.0.0.1:15001","proxy_type":"http","proxy_host":"example.test","proxy_port":443}`
	if err := os.WriteFile(path, []byte(payload), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadConfig(path); err == nil {
		t.Fatal("duplicate config key was accepted")
	}
}

func TestReadCredentialsNoAuthExactBytesAndBounds(t *testing.T) {
	credentials, err := ReadCredentials("")
	if err != nil {
		t.Fatal(err)
	}
	if credentials.Configured || len(credentials.Username) != 0 || len(credentials.Password) != 0 {
		t.Fatal("empty credentials directory was not treated as no-auth")
	}
	dir := t.TempDir()
	credentials, err = ReadCredentials(dir)
	if err != nil {
		t.Fatal(err)
	}
	if credentials.Configured {
		t.Fatal("empty systemd credential directory was not treated as no-auth")
	}
	if err := os.WriteFile(filepath.Join(dir, "proxy_username"), []byte("user\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCredentials(dir); err == nil {
		t.Fatal("partial credential pair was accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "proxy_password"), []byte("secret-value\r\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	credentials, err = ReadCredentials(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !credentials.Configured || !bytes.Equal(credentials.Username, []byte("user\n")) || !bytes.Equal(credentials.Password, []byte("secret-value\r\n")) {
		t.Fatal("credentials were not read exactly")
	}
	passwordPath := filepath.Join(dir, "proxy_password")
	if err := os.Chmod(passwordPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(passwordPath, make([]byte, maxCredentialBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCredentials(dir); err == nil {
		t.Fatal("oversized credential was accepted")
	}
}

type fakeNotifier struct {
	mu       sync.Mutex
	ready    int
	stopping int
}

func (n *fakeNotifier) Ready(string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.ready++
	return nil
}

func (n *fakeNotifier) Stopping(string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.stopping++
	return nil
}

func TestServerReadinessAndGracefulDrain(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenAddress := probe.Addr().String()
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	runtime := RuntimeConfig{
		Config:       validConfig(listenAddress),
		DialTimeout:  time.Second,
		IdleTimeout:  time.Second,
		DrainTimeout: 100 * time.Millisecond,
	}
	notify := &fakeNotifier{}
	server, err := NewServer(runtime, Credentials{}, notify)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	notify.mu.Lock()
	ready := notify.ready
	notify.mu.Unlock()
	if ready != 1 {
		t.Fatalf("ready notifications = %d, want 1", ready)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve() }()

	client, peer := net.Pipe()
	defer peer.Close()
	upstream, upstreamPeer := net.Pipe()
	defer upstreamPeer.Close()
	server.track(client)
	if !server.trackUpstream(client, upstream) {
		t.Fatal("failed to register active upstream")
	}
	server.wg.Add(1)
	go func() {
		defer server.wg.Done()
		defer server.untrack(client)
		_, _ = client.Read(make([]byte, 1))
	}()
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	err = server.Shutdown(ctx)
	cancel()
	if err == nil {
		t.Fatal("blocked connection did not reach drain deadline")
	}
	if elapsed := time.Since(start); elapsed > 150*time.Millisecond {
		t.Fatalf("shutdown exceeded bounded drain: %s", elapsed)
	}
	if _, err := peer.Write([]byte("x")); err == nil {
		t.Fatal("drain deadline did not close active client")
	}
	if _, err := upstreamPeer.Write([]byte("x")); err == nil {
		t.Fatal("drain deadline did not close active upstream")
	}
	drained := make(chan struct{})
	go func() { server.wg.Wait(); close(drained) }()
	select {
	case <-drained:
		if active := server.ActiveConnections(); active != 0 {
			t.Fatalf("active connections after forced close = %d", active)
		}
	case <-time.After(time.Second):
		t.Fatal("forced drain leaked an active connection goroutine")
	}
	if err := <-serveDone; err != nil {
		t.Fatalf("serve: %v", err)
	}
	notify.mu.Lock()
	stopping := notify.stopping
	notify.mu.Unlock()
	if stopping != 1 {
		t.Fatalf("stopping notifications = %d, want 1", stopping)
	}
}

func TestHTTPConnectAdapter(t *testing.T) {
	wipeCount := 0
	restoreHook := setWipeHookForTest(func(length int) {
		if length > 0 {
			wipeCount++
		}
	})
	defer restoreHook()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	request := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		var lines []string
		for {
			line, err := reader.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
			lines = append(lines, line)
		}
		request <- strings.Join(lines, "")
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	upstream := upstream{typeName: "http", host: "127.0.0.1", port: port, creds: newCredentialStore(Credentials{Username: []byte("user"), Password: []byte("password"), Configured: true}), timeout: time.Second}
	defer upstream.creds.close()
	conn, err := upstream.dialHTTP(context.Background(), &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	got := <-request
	if !strings.Contains(got, "CONNECT 203.0.113.10:443 HTTP/1.1") || !strings.Contains(got, "Proxy-Authorization: Basic") {
		t.Fatalf("unexpected HTTP CONNECT request: %q", got)
	}
	if wipeCount < 5 {
		t.Fatalf("HTTP auth construction did not wipe all mutable buffers; wipe count = %d", wipeCount)
	}
}

func TestHTTPConnectResponseRequiresFullyParsed200(t *testing.T) {
	t.Run("valid response preserves tunnel bytes", func(t *testing.T) {
		reader := bufio.NewReader(strings.NewReader("HTTP/1.1 200 Connection Established\r\nProxy-Agent: test\r\n\r\ntunnel"))
		if err := readHTTPConnectResponse(reader); err != nil {
			t.Fatalf("valid CONNECT response: %v", err)
		}
		remaining, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		if string(remaining) != "tunnel" {
			t.Fatalf("tunnel bytes = %q, want %q", remaining, "tunnel")
		}
	})

	for name, response := range map[string]string{
		"non_200":             "HTTP/1.1 201 Created\r\n\r\n",
		"unsupported_version": "HTTP/2.0 200 Okay\r\n\r\n",
		"status_prefix":       "HTTP/1.1 200not-okay\r\n\r\n",
		"four_digit_status":   "HTTP/1.1 2000 Not Okay\r\n\r\n",
		"missing_terminator":  "HTTP/1.1 200 OK\r\nHeader: value\r\n",
		"lf_only":             "HTTP/1.1 200 OK\n\n",
		"malformed_header":    "HTTP/1.1 200 OK\r\nInvalid Header\r\n\r\n",
		"invalid_length":      "HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			err := readHTTPConnectResponse(bufio.NewReader(strings.NewReader(response)))
			if err == nil {
				t.Fatalf("invalid CONNECT response was accepted: %q", response)
			}
			if name == "non_200" && reasonCode(err) != "proxy_rejected" {
				t.Fatalf("non-200 reason = %q, want proxy_rejected", reasonCode(err))
			}
		})
	}
}

func TestSOCKS5AuthAndRemoteDNS(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	seenDomain := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		greeting := make([]byte, 4)
		_, _ = io.ReadFull(conn, greeting)
		_, _ = conn.Write([]byte{0x05, 0x02})
		authHeader := make([]byte, 2)
		_, _ = io.ReadFull(conn, authHeader)
		authPayload := make([]byte, int(authHeader[1]))
		_, _ = io.ReadFull(conn, authPayload)
		passLength := []byte{0}
		_, _ = io.ReadFull(conn, passLength)
		_, _ = io.ReadFull(conn, make([]byte, int(passLength[0])))
		_, _ = conn.Write([]byte{0x01, 0x00})
		header := make([]byte, 5)
		_, _ = io.ReadFull(conn, header)
		if header[3] != 0x03 {
			seenDomain <- ""
			return
		}
		domain := make([]byte, int(header[4]))
		_, _ = io.ReadFull(conn, domain)
		_, _ = io.ReadFull(conn, make([]byte, 2))
		seenDomain <- string(domain)
		_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80})
	}()
	rawConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer rawConn.Close()
	conn := &shortWriteConn{Conn: rawConn, maximum: 1}
	if err := socks5Handshake(conn, Credentials{Username: []byte("user"), Password: []byte("password"), Configured: true}); err != nil {
		t.Fatal(err)
	}
	if err := socks5Connect(conn, "remote.example.test", 443); err != nil {
		t.Fatal(err)
	}
	if got := <-seenDomain; got != "remote.example.test" {
		t.Fatalf("remote DNS host = %q", got)
	}
}

func TestWriteAllCompletesShortStreamWrites(t *testing.T) {
	forwarderConn, peer := net.Pipe()
	defer forwarderConn.Close()
	defer peer.Close()

	payload := []byte("partial-write-canary")
	received := make(chan []byte, 1)
	go func() {
		buffer := make([]byte, len(payload))
		_, _ = io.ReadFull(peer, buffer)
		received <- buffer
	}()
	conn := &shortWriteConn{Conn: forwarderConn, maximum: 1}
	if err := writeAll(conn, payload); err != nil {
		t.Fatal(err)
	}
	if got := <-received; !bytes.Equal(got, payload) {
		t.Fatalf("short-write payload = %q, want %q", got, payload)
	}
}

func TestRelayIdleTimeoutResetsForEveryActivity(t *testing.T) {
	clientForwarder, clientPeer := net.Pipe()
	proxyForwarderRaw, proxyPeer := net.Pipe()
	defer clientPeer.Close()
	defer proxyPeer.Close()

	client := &deadlineRecordingConn{Conn: clientForwarder}
	proxyRecorder := &deadlineRecordingConn{Conn: proxyForwarderRaw}
	proxy := &shortWriteConn{Conn: proxyRecorder, maximum: 1}
	done := make(chan [2]copyResult, 1)
	go func() {
		clientResult, proxyResult := relayWithIdleTimeout(client, proxy, time.Second)
		done <- [2]copyResult{clientResult, proxyResult}
	}()

	relayWriteAndRead(t, clientPeer, proxyPeer, []byte("abc"))
	relayWriteAndRead(t, proxyPeer, clientPeer, []byte("xy"))
	waitForDeadlineCount(t, client.deadlineCount, 7)
	waitForDeadlineCount(t, proxyRecorder.deadlineCount, 7)

	if err := clientPeer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := proxyPeer.Close(); err != nil {
		t.Fatal(err)
	}
	results := <-done
	if results[0].err != nil || results[1].err != nil {
		t.Fatalf("relay after clean close returned errors: %+v", results)
	}
}

func TestRelayIdleTimeoutAllowsActiveTrafficThenExpires(t *testing.T) {
	clientForwarder, clientPeer := net.Pipe()
	proxyForwarder, proxyPeer := net.Pipe()
	defer clientPeer.Close()
	defer proxyPeer.Close()

	const idleTimeout = 80 * time.Millisecond
	done := make(chan [2]copyResult, 1)
	go func() {
		clientResult, proxyResult := relayWithIdleTimeout(clientForwarder, proxyForwarder, idleTimeout)
		done <- [2]copyResult{clientResult, proxyResult}
	}()
	for attempt := 0; attempt < 5; attempt++ {
		relayWriteAndRead(t, clientPeer, proxyPeer, []byte("heartbeat"))
		if attempt < 4 {
			time.Sleep(idleTimeout / 4)
		}
	}
	select {
	case results := <-done:
		t.Fatalf("active relay timed out early: %+v", results)
	case <-time.After(idleTimeout / 8):
	}
	select {
	case results := <-done:
		if results[0].err == nil && results[1].err == nil {
			t.Fatalf("idle relay completed without timeout: %+v", results)
		}
	case <-time.After(5 * idleTimeout):
		t.Fatal("idle relay did not expire")
	}
}

type shortWriteConn struct {
	net.Conn
	maximum int
}

func (c *shortWriteConn) Write(payload []byte) (int, error) {
	if c.maximum > 0 && len(payload) > c.maximum {
		payload = payload[:c.maximum]
	}
	return c.Conn.Write(payload)
}

type deadlineRecordingConn struct {
	net.Conn
	mu        sync.Mutex
	deadlines int
}

func (c *deadlineRecordingConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadlines++
	c.mu.Unlock()
	return c.Conn.SetDeadline(deadline)
}

func (c *deadlineRecordingConn) deadlineCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadlines
}

func waitForDeadlineCount(t *testing.T, count func() int, minimum int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if count() >= minimum {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("deadline refreshes = %d, want at least %d", count(), minimum)
}

func relayWriteAndRead(t *testing.T, writer, reader net.Conn, payload []byte) {
	t.Helper()
	writeDone := make(chan error, 1)
	go func() {
		_, err := writer.Write(payload)
		writeDone <- err
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("relayed payload = %q, want %q", got, payload)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
}

func TestHTTPConnectHandshakeDeadlineAndHeaderCap(t *testing.T) {
	t.Run("stall", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		accepted := make(chan net.Conn, 1)
		go func() {
			conn, err := listener.Accept()
			if err == nil {
				accepted <- conn
			}
		}()
		upstream := upstream{typeName: "http", host: "127.0.0.1", port: listener.Addr().(*net.TCPAddr).Port, creds: newCredentialStore(Credentials{}), timeout: 40 * time.Millisecond}
		defer upstream.creds.close()
		start := time.Now()
		_, err = upstream.dialHTTP(context.Background(), &net.TCPAddr{IP: net.ParseIP("203.0.113.11"), Port: 443})
		if err == nil {
			t.Fatal("stalled HTTP handshake succeeded")
		}
		if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
			t.Fatalf("HTTP handshake deadline exceeded: %s", elapsed)
		}
		select {
		case conn := <-accepted:
			_ = conn.Close()
		case <-time.After(time.Second):
			t.Fatal("proxy did not accept test connection")
		}
	})
	t.Run("header_cap", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = io.CopyN(io.Discard, conn, 1)
			_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\nX-Long: "+strings.Repeat("a", maxHTTPConnectResponseHeaderBytes)+"\r\n")
		}()
		upstream := upstream{typeName: "http", host: "127.0.0.1", port: listener.Addr().(*net.TCPAddr).Port, creds: newCredentialStore(Credentials{}), timeout: time.Second}
		defer upstream.creds.close()
		if _, err := upstream.dialHTTP(context.Background(), &net.TCPAddr{IP: net.ParseIP("203.0.113.11"), Port: 443}); err == nil {
			t.Fatal("oversized HTTP CONNECT response headers were accepted")
		}
	})
}

func TestSOCKS5HandshakeDeadlineAndStartupCredentialLimits(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	upstream := upstream{typeName: "socks5", host: "127.0.0.1", port: listener.Addr().(*net.TCPAddr).Port, creds: newCredentialStore(Credentials{}), timeout: 40 * time.Millisecond}
	defer upstream.creds.close()
	start := time.Now()
	_, err = upstream.dialSOCKS5(context.Background(), &net.TCPAddr{IP: net.ParseIP("203.0.113.11"), Port: 443})
	if err == nil {
		t.Fatal("stalled SOCKS5 handshake succeeded")
	}
	if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
		t.Fatalf("SOCKS5 handshake deadline exceeded: %s", elapsed)
	}
	select {
	case conn := <-accepted:
		_ = conn.Close()
	case <-time.After(time.Second):
		t.Fatal("proxy did not accept test connection")
	}

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.Addr().String()
	_ = probe.Close()
	runtime := RuntimeConfig{Config: func() Config {
		cfg := validConfig(address)
		cfg.ProxyType = "socks5"
		return cfg
	}(), DialTimeout: time.Second, IdleTimeout: time.Second, DrainTimeout: time.Second}
	notify := &fakeNotifier{}
	if _, err := NewServer(runtime, Credentials{Username: []byte(strings.Repeat("u", 256)), Password: []byte("p"), Configured: true}, notify); err == nil {
		t.Fatal("oversized SOCKS5 credential passed readiness validation")
	}
	notify.mu.Lock()
	ready := notify.ready
	notify.mu.Unlock()
	if ready != 0 {
		t.Fatal("notifier was called before full startup validation")
	}
}

func TestParseHTTPHostAbsoluteForm(t *testing.T) {
	host, ok := ParseHTTPHost([]byte("GET http://absolute.example.test:8080/path HTTP/1.1\r\nUser-Agent: test\r\n\r\n"))
	if !ok || host != "absolute.example.test" {
		t.Fatalf("absolute-form host = %q, ok=%v", host, ok)
	}
}

func TestCredentialOwnershipWipeAndValidationErrorPath(t *testing.T) {
	username := []byte("forwarder-canary-user")
	password := []byte("forwarder-canary-password")
	wipeCount := 0
	restoreHook := setWipeHookForTest(func(length int) {
		if length > 0 {
			wipeCount++
		}
	})
	defer restoreHook()

	store := newCredentialStore(Credentials{Username: username, Password: password, Configured: true})
	session, err := store.acquire()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(session.Username, username) || !bytes.Equal(session.Password, password) {
		t.Fatal("session did not receive the configured credential bytes")
	}
	session.Username[0] ^= 0x01
	if username[0] == session.Username[0] {
		t.Fatal("session credential aliases the process-owned credential buffer")
	}
	session.Wipe()
	store.close()
	if !allZero(username) || !allZero(password) {
		t.Fatal("credential store did not wipe owned source buffers")
	}
	if wipeCount < 4 {
		t.Fatalf("wipe hook observed %d buffers, want at least 4", wipeCount)
	}

	invalidUser := []byte(strings.Repeat("x", 256))
	invalidPassword := []byte("p")
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.Addr().String()
	_ = probe.Close()
	runtime := RuntimeConfig{Config: func() Config {
		cfg := validConfig(address)
		cfg.ProxyType = "socks5"
		return cfg
	}(), DialTimeout: time.Second, IdleTimeout: time.Second, DrainTimeout: time.Second}
	if _, err := NewServer(runtime, Credentials{Username: invalidUser, Password: invalidPassword, Configured: true}, &fakeNotifier{}); err == nil {
		t.Fatal("invalid SOCKS credential was accepted")
	}
	if !allZero(invalidUser) || !allZero(invalidPassword) {
		t.Fatal("startup validation error retained credential bytes")
	}
}

func TestCredentialStoreConcurrentSessionCopies(t *testing.T) {
	username := []byte("concurrent-canary-user")
	password := []byte("concurrent-canary-password")
	store := newCredentialStore(Credentials{Username: username, Password: password, Configured: true})
	var workers sync.WaitGroup
	errors := make(chan error, 64)
	for range 64 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			credentials, err := store.acquire()
			if err != nil {
				errors <- err
				return
			}
			if !bytes.Equal(credentials.Username, []byte("concurrent-canary-user")) || !bytes.Equal(credentials.Password, []byte("concurrent-canary-password")) {
				errors <- io.ErrUnexpectedEOF
			}
			credentials.Wipe()
		}()
	}
	workers.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	store.close()
	if !allZero(username) || !allZero(password) {
		t.Fatal("concurrent credential store did not wipe source buffers")
	}
	if _, err := store.acquire(); err == nil {
		t.Fatal("closed credential store allowed a new session")
	}
}

func allZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

func TestMetricsBindsSeparateLoopbackListenerBeforeReady(t *testing.T) {
	address := availableLoopbackAddress(t, "127.0.0.1")
	runtime := RuntimeConfig{Config: validConfig(address), DialTimeout: time.Second, IdleTimeout: time.Second, DrainTimeout: time.Second}
	notify := &fakeNotifier{}
	server, err := NewServerWithObserver(runtime, Credentials{}, notify, observability.NewDiscard("pgw-fwd"))
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(t.Context())
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	metricsURL := "http://127.0.0.2:" + port + "/metrics"
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: time.Second}
	response, err := client.Get(metricsURL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "pgw_forwarder_ready") {
		t.Fatalf("metrics response status=%d body=%q", response.StatusCode, body)
	}
	headRequest, err := http.NewRequest(http.MethodHead, metricsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	headResponse, err := client.Do(headRequest)
	if err != nil {
		t.Fatal(err)
	}
	headBody, err := io.ReadAll(headResponse.Body)
	headResponse.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if headResponse.StatusCode != http.StatusOK || len(headBody) != 0 {
		t.Fatalf("metrics HEAD status=%d body length=%d", headResponse.StatusCode, len(headBody))
	}
	if server.metrics.counters[forwarderMetricKey{operation: "connection", outcome: "accepted", reason: "none"}] != 0 {
		t.Fatal("metrics request entered transparent data listener")
	}
	notify.mu.Lock()
	ready := notify.ready
	notify.mu.Unlock()
	if ready != 1 {
		t.Fatalf("readiness called %d times, want 1", ready)
	}
}

func TestMetricsAddressValidationAndUnavailableFailure(t *testing.T) {
	for _, address := range []string{"0.0.0.0:15001", "192.0.2.1:15001", "localhost:15001"} {
		if err := observability.ValidateLoopbackAddress(address); err == nil {
			t.Fatalf("non-loopback metrics address %q was accepted", address)
		}
	}
	if _, err := metricsAddress("192.168.2.1:15001"); err != nil {
		t.Fatalf("LAN data listener should be a valid metric derivation source: %v", err)
	}
	if _, err := metricsAddress("127.0.0.2:15001"); err == nil {
		t.Fatal("metrics/data listener collision was accepted")
	}

	address := availableLoopbackAddress(t, "127.0.0.1")
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	reservedMetrics, err := net.Listen("tcp", net.JoinHostPort("127.0.0.2", port))
	if err != nil {
		t.Fatal(err)
	}
	defer reservedMetrics.Close()
	runtime := RuntimeConfig{Config: validConfig(address), DialTimeout: time.Second, IdleTimeout: time.Second, DrainTimeout: time.Second}
	notify := &fakeNotifier{}
	server, err := NewServer(runtime, Credentials{}, notify)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err == nil {
		t.Fatal("metrics bind collision allowed READY")
	}
	notify.mu.Lock()
	ready := notify.ready
	notify.mu.Unlock()
	if ready != 0 {
		t.Fatal("notifier became ready after metrics bind failure")
	}
	if connection, err := net.DialTimeout("tcp", address, 50*time.Millisecond); err == nil {
		connection.Close()
		t.Fatal("data listener remained open after metrics bind failure")
	}
}

func TestForwarderObservabilityRedactsCanaryAndStaysBounded(t *testing.T) {
	var output bytes.Buffer
	observer := observability.New("pgw-fwd", &output)
	address := availableLoopbackAddress(t, "127.0.0.1")
	username := []byte("forwarder-observability-canary-user")
	password := []byte("forwarder-observability-canary-password")
	runtime := RuntimeConfig{Config: validConfig(address), DialTimeout: time.Second, IdleTimeout: time.Second, DrainTimeout: time.Second}
	server, err := NewServerWithObserver(runtime, Credentials{Username: username, Password: password, Configured: true}, &fakeNotifier{}, observer)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	server.metrics.observe("connection", "failure", "credential_unavailable")
	server.log("warn", "forwarder_connection", "failure", "credential_unavailable")
	metrics := server.metrics.render()
	server.CloseCredentials()
	_ = server.Shutdown(t.Context())
	combined := output.String() + metrics
	for _, prohibited := range []string{"forwarder-observability-canary-user", "forwarder-observability-canary-password", runtime.ProxyHost, runtime.ListenAddress} {
		if strings.Contains(combined, prohibited) {
			t.Fatalf("sensitive/high-cardinality value leaked: %q", prohibited)
		}
	}
	if !strings.Contains(combined, `proxy_type="http"`) || !strings.Contains(combined, `reason="credential_unavailable"`) || !strings.Contains(output.String(), `"event":"forwarder_ready"`) || !strings.Contains(output.String(), `"mapping_id":"mapping_01"`) {
		t.Fatalf("missing bounded observability values: %s", combined)
	}
	for _, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatal(err)
		}
		if entry["outcome"] == "failure" && entry["mapping_id"] != runtime.MappingID {
			t.Fatalf("failure log omitted mapping_id: %s", line)
		}
	}
}

func TestForwarderMetricsConcurrentStress(t *testing.T) {
	metrics := newForwarderMetrics("socks5")
	var group sync.WaitGroup
	for range 64 {
		group.Add(1)
		go func() {
			defer group.Done()
			for range 100 {
				metrics.observe("connection", "accepted", "none")
				metrics.observe("handshake", "failure", "handshake_timeout")
				metrics.addBytes(128)
			}
		}()
	}
	group.Wait()
	output := metrics.render()
	if !strings.Contains(output, `proxy_type="socks5"`) || strings.Contains(output, "canary") || !strings.Contains(output, "pgw_forwarder_events_total") {
		t.Fatalf("invalid concurrent metrics output: %s", output)
	}
}

func availableLoopbackAddress(t *testing.T, host string) string {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}
