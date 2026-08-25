package forwarder

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const maxHTTPConnectResponseHeaderBytes = 16 << 10

type upstream struct {
	typeName string
	host     string
	port     int
	creds    *credentialStore
	timeout  time.Duration
}

type forwarderFailure struct{ reason string }

func (e forwarderFailure) Error() string { return e.reason }

func fail(reason string) error { return forwarderFailure{reason: metricReason(reason)} }

func reasonCode(err error) string {
	var typed forwarderFailure
	if errors.As(err, &typed) {
		return typed.reason
	}
	if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
		return "handshake_timeout"
	}
	return "handshake_failed"
}

func (u upstream) address() string { return net.JoinHostPort(u.host, strconv.Itoa(u.port)) }

func (u upstream) dial(ctx context.Context, destination *net.TCPAddr) (net.Conn, error) {
	switch u.typeName {
	case "http":
		return u.dialHTTP(ctx, destination)
	case "socks5":
		return u.dialSOCKS5(ctx, destination)
	default:
		return nil, errors.New("unsupported proxy adapter")
	}
}

func (u upstream) dialConnection(ctx context.Context) (net.Conn, error) {
	dialer := net.Dialer{Timeout: u.timeout}
	connection, err := dialer.DialContext(ctx, "tcp", u.address())
	if err != nil {
		return nil, dialFailure(err)
	}
	return connection, nil
}

func dialFailure(err error) error {
	if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
		return fail("dial_timeout")
	}
	return fail("dial_failed")
}

func handshakeFailure(err error) error {
	if reasonCode(err) == "proxy_rejected" {
		return err
	}
	if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
		return fail("handshake_timeout")
	}
	return fail("handshake_failed")
}

func (u upstream) dialHTTP(ctx context.Context, destination *net.TCPAddr) (net.Conn, error) {
	credentials, err := u.creds.acquire()
	if err != nil {
		return nil, fail("credential_unavailable")
	}
	defer credentials.Wipe()
	proxyConn, err := u.dialConnection(ctx)
	if err != nil {
		return nil, err
	}
	if err := proxyConn.SetDeadline(time.Now().Add(u.timeout)); err != nil {
		proxyConn.Close()
		return nil, fail("handshake_failed")
	}
	defer proxyConn.SetDeadline(time.Time{})
	destinationHostPort := net.JoinHostPort(destination.IP.String(), strconv.Itoa(destination.Port))
	request := "CONNECT " + destinationHostPort + " HTTP/1.1\r\nHost: " + destinationHostPort + "\r\n"
	requestBuffer := make([]byte, 0, len(request)+base64.StdEncoding.EncodedLen(len(credentials.Username)+len(credentials.Password)+1)+64)
	defer func() { wipe(requestBuffer) }()
	requestBuffer = append(requestBuffer, request...)
	if credentials.Configured {
		requestBuffer = appendHTTPProxyAuthorization(requestBuffer, credentials)
	}
	requestBuffer = append(requestBuffer, "Proxy-Connection: Keep-Alive\r\nConnection: Keep-Alive\r\n\r\n"...)
	if err := writeAll(proxyConn, requestBuffer); err != nil {
		proxyConn.Close()
		return nil, handshakeFailure(err)
	}
	reader := bufio.NewReaderSize(proxyConn, maxHTTPConnectResponseHeaderBytes+1)
	if err := readHTTPConnectResponse(reader); err != nil {
		proxyConn.Close()
		return nil, handshakeFailure(err)
	}
	return &bufferedConn{Conn: proxyConn, reader: reader}, nil
}

func (u upstream) dialSOCKS5(ctx context.Context, destination *net.TCPAddr) (net.Conn, error) {
	credentials, err := u.creds.acquire()
	if err != nil {
		return nil, fail("credential_unavailable")
	}
	defer credentials.Wipe()
	proxyConn, err := u.dialConnection(ctx)
	if err != nil {
		return nil, err
	}
	if err := proxyConn.SetDeadline(time.Now().Add(u.timeout)); err != nil {
		proxyConn.Close()
		return nil, fail("handshake_failed")
	}
	defer proxyConn.SetDeadline(time.Time{})
	if err := socks5Handshake(proxyConn, credentials); err != nil {
		proxyConn.Close()
		return nil, handshakeFailure(err)
	}
	if err := socks5Connect(proxyConn, destination.IP.String(), destination.Port); err != nil {
		proxyConn.Close()
		return nil, handshakeFailure(err)
	}
	return proxyConn, nil
}

func socks5Handshake(conn net.Conn, credentials Credentials) error {
	greeting := []byte{0x05, 0x01, 0x00}
	if credentials.Configured {
		greeting = []byte{0x05, 0x02, 0x00, 0x02}
	}
	if err := writeAll(conn, greeting); err != nil {
		return err
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	if response[0] != 0x05 {
		return errors.New("invalid SOCKS5 version")
	}
	switch response[1] {
	case 0x00:
		return nil
	case 0x02:
		return socks5Authenticate(conn, credentials)
	case 0xFF:
		return fail("proxy_rejected")
	default:
		return fail("proxy_rejected")
	}
}

func socks5Authenticate(conn net.Conn, credentials Credentials) error {
	if !credentials.Configured {
		return errors.New("SOCKS5 requires credentials")
	}
	if len(credentials.Username) > 255 || len(credentials.Password) > 255 {
		return errors.New("SOCKS5 credential exceeds protocol limit")
	}
	request := make([]byte, 0, len(credentials.Username)+len(credentials.Password)+3)
	request = append(request, 0x01, byte(len(credentials.Username)))
	request = append(request, credentials.Username...)
	request = append(request, byte(len(credentials.Password)))
	request = append(request, credentials.Password...)
	defer wipe(request)
	if err := writeAll(conn, request); err != nil {
		return err
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	if response[0] != 0x01 || response[1] != 0x00 {
		return fail("proxy_rejected")
	}
	return nil
}

func appendHTTPProxyAuthorization(request []byte, credentials Credentials) []byte {
	rawLength := len(credentials.Username) + len(credentials.Password) + 1
	raw := make([]byte, rawLength)
	defer wipe(raw)
	copy(raw, credentials.Username)
	raw[len(credentials.Username)] = ':'
	copy(raw[len(credentials.Username)+1:], credentials.Password)
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	defer wipe(encoded)
	base64.StdEncoding.Encode(encoded, raw)
	request = append(request, "Proxy-Authorization: Basic "...)
	request = append(request, encoded...)
	return append(request, '\r', '\n')
}

func writeAll(conn net.Conn, payload []byte) error {
	for len(payload) > 0 {
		written, err := conn.Write(payload)
		if written < 0 || written > len(payload) {
			return errors.New("forwarder write returned invalid byte count")
		}
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

func readHTTPConnectResponse(reader *bufio.Reader) error {
	total := 0
	responseBytes := make([]byte, 0, 512)
	for {
		line, err := readHTTPHeaderLine(reader, &total)
		if err != nil {
			return errors.New("read HTTP CONNECT response")
		}
		responseBytes = append(responseBytes, line...)
		if bytes.Equal(line, []byte("\r\n")) {
			break
		}
	}

	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(responseBytes)), &http.Request{Method: http.MethodConnect})
	if err != nil {
		return errors.New("parse HTTP CONNECT response")
	}
	defer response.Body.Close()
	if response.Proto != "HTTP/1.0" && response.Proto != "HTTP/1.1" {
		return errors.New("unsupported HTTP CONNECT response version")
	}
	if response.StatusCode != http.StatusOK {
		return fail("proxy_rejected")
	}
	return nil
}

func readHTTPHeaderLine(reader *bufio.Reader, total *int) ([]byte, error) {
	line, err := reader.ReadSlice('\n')
	*total += len(line)
	if *total > maxHTTPConnectResponseHeaderBytes {
		return nil, errors.New("HTTP CONNECT response headers exceed limit")
	}
	if err != nil {
		return nil, err
	}
	if len(line) < 2 || !bytes.HasSuffix(line, []byte("\r\n")) {
		return nil, errors.New("HTTP CONNECT response line must end with CRLF")
	}
	return line, nil
}

// socks5Connect accepts an IP or DNS name. The domain branch deliberately
// emits ATYP=3 so callers that have a name retain remote-DNS semantics.
func socks5Connect(conn net.Conn, host string, port int) error {
	if port < 1 || port > 65535 {
		return errors.New("invalid SOCKS5 destination port")
	}
	request := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			request = append(request, 0x01)
			request = append(request, ip4...)
		} else {
			request = append(request, 0x04)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return errors.New("invalid SOCKS5 destination host")
		}
		request = append(request, 0x03, byte(len(host)))
		request = append(request, host...)
	}
	request = append(request, byte(port>>8), byte(port))
	if err := writeAll(conn, request); err != nil {
		return err
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != 0x05 || header[1] != 0x00 {
		return fail("proxy_rejected")
	}
	var remaining int
	switch header[3] {
	case 0x01:
		remaining = 4 + 2
	case 0x03:
		length := []byte{0}
		if _, err := io.ReadFull(conn, length); err != nil {
			return err
		}
		remaining = int(length[0]) + 2
	case 0x04:
		remaining = 16 + 2
	default:
		return errors.New("invalid SOCKS5 reply address type")
	}
	_, err := io.ReadFull(conn, make([]byte, remaining))
	return err
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// ParseHTTPHost supports both origin-form and absolute-form HTTP requests for
// non-sensitive sampled host logging. It does not make routing decisions.
func ParseHTTPHost(payload []byte) (string, bool) {
	lineEnd := strings.Index(string(payload), "\r\n")
	if lineEnd < 0 {
		return "", false
	}
	firstLine := strings.Fields(string(payload[:lineEnd]))
	if len(firstLine) != 3 || !strings.HasPrefix(firstLine[2], "HTTP/") {
		return "", false
	}
	if strings.HasPrefix(firstLine[1], "http://") || strings.HasPrefix(firstLine[1], "https://") {
		trimmed := strings.TrimPrefix(strings.TrimPrefix(firstLine[1], "http://"), "https://")
		if host, _, err := net.SplitHostPort(trimmed); err == nil {
			return host, true
		}
		if trimmed != "" && !strings.Contains(trimmed, "/") {
			return trimmed, true
		}
		if slash := strings.IndexByte(trimmed, '/'); slash > 0 {
			return strings.Split(trimmed[:slash], ":")[0], true
		}
	}
	headEnd := bytesIndexHeaderEnd(payload)
	if headEnd < 0 {
		headEnd = len(payload)
	}
	for _, line := range strings.Split(string(payload[:headEnd]), "\r\n") {
		if len(line) >= 5 && strings.EqualFold(line[:5], "host:") {
			value := strings.TrimSpace(line[5:])
			if host, _, err := net.SplitHostPort(value); err == nil {
				return host, true
			}
			return value, value != ""
		}
	}
	return "", false
}

func bytesIndexHeaderEnd(payload []byte) int {
	for i := 0; i+3 < len(payload); i++ {
		if payload[i] == '\r' && payload[i+1] == '\n' && payload[i+2] == '\r' && payload[i+3] == '\n' {
			return i
		}
	}
	return -1
}

func ParseTLSSNI(payload []byte) (string, bool) {
	if len(payload) < 9 || payload[0] != 0x16 || payload[5] != 0x01 {
		return "", false
	}
	i := 5 + 1 + 3 + 2 + 32
	if len(payload) < i+1 {
		return "", false
	}
	sessionLength := int(payload[i])
	i += 1 + sessionLength
	if len(payload) < i+2 {
		return "", false
	}
	cipherLength := int(binary.BigEndian.Uint16(payload[i : i+2]))
	i += 2 + cipherLength
	if len(payload) < i+1 {
		return "", false
	}
	compressionLength := int(payload[i])
	i += 1 + compressionLength
	if len(payload) < i+2 {
		return "", false
	}
	extensionsLength := int(binary.BigEndian.Uint16(payload[i : i+2]))
	i += 2
	end := i + extensionsLength
	if end > len(payload) {
		end = len(payload)
	}
	for i+4 <= end {
		extensionType := binary.BigEndian.Uint16(payload[i : i+2])
		extensionLength := int(binary.BigEndian.Uint16(payload[i+2 : i+4]))
		i += 4
		if i+extensionLength > end {
			return "", false
		}
		if extensionType == 0 && extensionLength >= 5 {
			j := i + 2
			listEnd := j + int(binary.BigEndian.Uint16(payload[i:i+2]))
			if listEnd > i+extensionLength {
				return "", false
			}
			for j+3 <= listEnd {
				nameType := payload[j]
				nameLength := int(binary.BigEndian.Uint16(payload[j+1 : j+3]))
				j += 3
				if j+nameLength > listEnd {
					return "", false
				}
				if nameType == 0 && nameLength > 0 {
					return string(payload[j : j+nameLength]), true
				}
				j += nameLength
			}
		}
		i += extensionLength
	}
	return "", false
}
