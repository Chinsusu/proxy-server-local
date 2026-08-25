package check

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type fakeConn struct {
	writes   [][]byte
	read     *bytes.Reader
	writeErr error
	readErr  error
}

func (conn *fakeConn) Read(value []byte) (int, error) {
	if conn.readErr != nil {
		return 0, conn.readErr
	}
	return conn.read.Read(value)
}
func (conn *fakeConn) Write(value []byte) (int, error) {
	conn.writes = append(conn.writes, append([]byte(nil), value...))
	if conn.writeErr != nil {
		return 0, conn.writeErr
	}
	return len(value), nil
}
func (conn *fakeConn) Close() error                     { return nil }
func (conn *fakeConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (conn *fakeConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (conn *fakeConn) SetDeadline(time.Time) error      { return nil }
func (conn *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (conn *fakeConn) SetWriteDeadline(time.Time) error { return nil }

func TestDialHTTPConnectWritesCredentialOnlyFromWipeableRequestBuffer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan []byte, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		request := make([]byte, 0, 1024)
		for {
			line, readErr := reader.ReadBytes('\n')
			request = append(request, line...)
			if readErr != nil || bytes.Equal(line, []byte("\r\n")) {
				break
			}
		}
		received <- request
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n")
	}()
	address := listener.Addr().(*net.TCPAddr)
	username, password := "proxy-user", []byte("proxy-password")
	conn, err := dialHTTPConnect(context.Background(), "127.0.0.1", address.Port, "example.test:443", &username, &password)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	select {
	case request := <-received:
		if !bytes.Contains(request, []byte("Proxy-Authorization: Basic cHJveHktdXNlcjpwcm94eS1wYXNzd29yZA==")) {
			t.Fatalf("missing expected CONNECT authorization: %q", request)
		}
		if strings.Contains(string(request), "proxy-password") {
			t.Fatalf("CONNECT leaked plaintext password: %q", request)
		}
	case <-time.After(time.Second):
		t.Fatal("proxy did not receive CONNECT request")
	}
}

func TestDialHTTPConnectPreservesTunnelBytesWithoutContentLength(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, _ := reader.ReadBytes('\n')
			if bytes.Equal(line, []byte("\r\n")) {
				break
			}
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\nProxy-Agent: mock\r\n\r\ntunnel-data")
		buffer := make([]byte, 4)
		_, _ = io.ReadFull(conn, buffer)
		if string(buffer) == "ping" {
			_, _ = io.WriteString(conn, "pong")
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	conn, err := dialHTTPConnect(context.Background(), "127.0.0.1", port, "example.test:443", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	buffer := make([]byte, len("tunnel-data"))
	if _, err := io.ReadFull(conn, buffer); err != nil || string(buffer) != "tunnel-data" {
		t.Fatalf("tunnel prefix=%q err=%v", buffer, err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buffer = make([]byte, 4)
	if _, err := io.ReadFull(conn, buffer); err != nil || string(buffer) != "pong" {
		t.Fatalf("tunnel response=%q err=%v", buffer, err)
	}
}

func TestHTTPConnectResponseRejectsNon200AndOversizedHeaders(t *testing.T) {
	if err := readHTTPConnectResponse(bufio.NewReader(strings.NewReader("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))); err == nil {
		t.Fatal("non-200 CONNECT response accepted")
	}
	overflow := "HTTP/1.1 200 OK\r\nX-Test: " + strings.Repeat("a", maxConnectResponseHeaderBytes) + "\r\n\r\n"
	if err := readHTTPConnectResponse(bufio.NewReader(strings.NewReader(overflow))); err == nil {
		t.Fatal("oversized CONNECT response headers accepted")
	}
}

func TestDialHTTPConnectHonorsResponseDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, readErr := reader.ReadBytes('\n')
			if readErr != nil || bytes.Equal(line, []byte("\r\n")) {
				time.Sleep(100 * time.Millisecond) // deliberately send no response
				return
			}
		}
	}()
	original := httpConnectResponseTimeout
	httpConnectResponseTimeout = 20 * time.Millisecond
	defer func() { httpConnectResponseTimeout = original }()
	start := time.Now()
	_, err = dialHTTPConnect(context.Background(), "127.0.0.1", listener.Addr().(*net.TCPAddr).Port, "example.test:443", nil, nil)
	if err == nil {
		t.Fatal("missing CONNECT response accepted")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("CONNECT response deadline was not honored: %v", elapsed)
	}
}

func TestSOCKSAuthWipesFinalRequestSliceForAllOutcomes(t *testing.T) {
	original := socksAuthWipeHook
	defer func() { socksAuthWipeHook = original }()
	user, pass := "proxy-user", []byte("proxy-password")
	dialer := &socksDialer{username: &user, password: &pass}
	for _, scenario := range []struct {
		name string
		conn *fakeConn
	}{
		{"success", &fakeConn{read: bytes.NewReader([]byte{0x01, 0x00})}},
		{"write_failure", &fakeConn{read: bytes.NewReader(nil), writeErr: errors.New("write")}},
		{"read_failure", &fakeConn{read: bytes.NewReader(nil), readErr: errors.New("read")}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var observed []byte
			socksAuthWipeHook = func(value []byte) { observed = append([]byte(nil), value...) }
			_ = dialer.socks5Auth(scenario.conn)
			if len(observed) != 3+len(user)+len(pass) {
				t.Fatalf("wiped len=%d", len(observed))
			}
			for index, value := range observed {
				if value != 0 {
					t.Fatalf("request byte %d retained %x", index, value)
				}
			}
		})
	}
}
