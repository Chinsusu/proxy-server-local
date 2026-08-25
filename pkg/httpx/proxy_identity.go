package httpx

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	ProxyClientIPHeader  = "X-PGW-Client-IP"
	ProxyTimestampHeader = "X-PGW-Proxy-Timestamp"
	ProxyNonceHeader     = "X-PGW-Proxy-Nonce"
	ProxySignatureHeader = "X-PGW-Proxy-Signature"
	proxyIdentityVersion = "v1"
	maxProxyNonceBytes   = 128
	minProxyNonceBytes   = 16
)

var ErrInvalidProxyIdentity = errors.New("httpx: invalid UI proxy identity")

// ProxyIdentity is the authenticated, replay-bounded identity sent by the
// trusted UI process to the private API login endpoint. It contains no user
// credential and must only be used on a loopback UI-to-API connection.
type ProxyIdentity struct {
	ClientIP  netip.Addr
	Timestamp time.Time
	Nonce     string
	Signature string
}

// SignProxyIdentity generates all four UI-to-API identity headers. timestamp
// is represented as Unix seconds and nonce must be unique for each attempt.
// The HMAC preimage is exactly: v1\n<canonical-ip>\n<unix-seconds>\n<nonce>.
func SignProxyIdentity(token []byte, clientIP netip.Addr, timestamp time.Time, nonce string) (http.Header, error) {
	if err := validateProxyToken(token); err != nil {
		return nil, err
	}
	if !clientIP.IsValid() || clientIP.IsUnspecified() || clientIP.Zone() != "" || !validProxyNonce(nonce) {
		return nil, ErrInvalidProxyIdentity
	}
	seconds := timestamp.UTC().Unix()
	signature := proxyIdentitySignature(token, clientIP.String(), seconds, nonce)
	header := make(http.Header, 4)
	header.Set(ProxyClientIPHeader, clientIP.String())
	header.Set(ProxyTimestampHeader, strconv.FormatInt(seconds, 10))
	header.Set(ProxyNonceHeader, nonce)
	header.Set(ProxySignatureHeader, hex.EncodeToString(signature))
	zero(signature)
	return header, nil
}

// NewProxyNonce returns a URL-header-safe random nonce suitable for
// SignProxyIdentity. The returned value is 32 lower-case hexadecimal bytes.
func NewProxyNonce() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate proxy identity nonce: %w", err)
	}
	return hex.EncodeToString(value), nil
}

// ProxyIdentityVerifier accepts one current HMAC key and optionally previous
// keys during a bounded credential rotation overlap. It owns copies of keys;
// Close wipes them on shutdown.
type ProxyIdentityVerifier struct {
	keys       [][]byte
	skew       time.Duration
	maxNonces  int
	now        func() time.Time
	mu         sync.Mutex
	usedNonces map[string]time.Time
}

func NewProxyIdentityVerifier(tokens ...[]byte) (*ProxyIdentityVerifier, error) {
	if len(tokens) == 0 || len(tokens) > 2 {
		return nil, ErrInvalidProxyIdentity
	}
	keys := make([][]byte, 0, len(tokens))
	for _, token := range tokens {
		if err := validateProxyToken(token); err != nil {
			for _, key := range keys {
				zero(key)
			}
			return nil, err
		}
		keys = append(keys, append([]byte(nil), token...))
	}
	return &ProxyIdentityVerifier{keys: keys, skew: time.Minute, maxNonces: 10000, now: time.Now, usedNonces: make(map[string]time.Time)}, nil
}

func (v *ProxyIdentityVerifier) Close() {
	if v == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, key := range v.keys {
		zero(key)
	}
	v.keys = nil
	v.usedNonces = nil
}

// Verify authenticates the headers, checks bounded skew and rejects a reused
// nonce. It must be called only after the API has verified a loopback peer.
func (v *ProxyIdentityVerifier) Verify(header http.Header) (netip.Addr, error) {
	if v == nil {
		return netip.Addr{}, ErrInvalidProxyIdentity
	}
	identity, err := parseProxyIdentity(header)
	if err != nil {
		return netip.Addr{}, err
	}
	now := v.now().UTC()
	if delta := now.Sub(identity.Timestamp); delta > v.skew || delta < -v.skew {
		return netip.Addr{}, ErrInvalidProxyIdentity
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.keys) == 0 || v.usedNonces == nil {
		return netip.Addr{}, ErrInvalidProxyIdentity
	}
	v.cleanupNonces(now)
	if _, duplicate := v.usedNonces[identity.Nonce]; duplicate {
		return netip.Addr{}, ErrInvalidProxyIdentity
	}
	matched := 0
	provided, decodeErr := hex.DecodeString(identity.Signature)
	if decodeErr != nil || len(provided) != sha256.Size {
		return netip.Addr{}, ErrInvalidProxyIdentity
	}
	defer zero(provided)
	for _, key := range v.keys {
		expected := proxyIdentitySignature(key, identity.ClientIP.String(), identity.Timestamp.Unix(), identity.Nonce)
		matched |= subtle.ConstantTimeCompare(provided, expected)
		zero(expected)
	}
	if matched != 1 {
		return netip.Addr{}, ErrInvalidProxyIdentity
	}
	if len(v.usedNonces) >= v.maxNonces {
		return netip.Addr{}, ErrInvalidProxyIdentity
	}
	v.usedNonces[identity.Nonce] = identity.Timestamp.Add(v.skew)
	return identity.ClientIP, nil
}

func (v *ProxyIdentityVerifier) cleanupNonces(now time.Time) {
	for nonce, expiresAt := range v.usedNonces {
		if !expiresAt.After(now) {
			delete(v.usedNonces, nonce)
		}
	}
}

// CanonicalLoginClientIP returns the verified end-client key for the login
// limiter. A proxy identity is accepted only from a numeric loopback TCP peer.
// Any partial or invalid X-PGW identity headers fail closed; a direct client
// with none of those headers uses its own numeric RemoteAddr instead.
func CanonicalLoginClientIP(r *http.Request, verifier *ProxyIdentityVerifier) (string, error) {
	if r == nil {
		return "", ErrInvalidProxyIdentity
	}
	peer, err := numericRemoteIP(r.RemoteAddr)
	if err != nil {
		return "", ErrInvalidProxyIdentity
	}
	if !peer.IsLoopback() {
		return "", ErrInvalidProxyIdentity
	}
	if !hasProxyIdentityHeaders(r.Header) {
		return peer.String(), nil
	}
	if verifier == nil {
		return "", ErrInvalidProxyIdentity
	}
	client, err := verifier.Verify(r.Header)
	if err != nil {
		return "", ErrInvalidProxyIdentity
	}
	return client.String(), nil
}

func hasProxyIdentityHeaders(header http.Header) bool {
	for _, key := range []string{ProxyClientIPHeader, ProxyTimestampHeader, ProxyNonceHeader, ProxySignatureHeader} {
		if len(header.Values(key)) != 0 {
			return true
		}
	}
	return false
}

func parseProxyIdentity(header http.Header) (ProxyIdentity, error) {
	for _, key := range []string{ProxyClientIPHeader, ProxyTimestampHeader, ProxyNonceHeader, ProxySignatureHeader} {
		if len(header.Values(key)) != 1 {
			return ProxyIdentity{}, ErrInvalidProxyIdentity
		}
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(header.Get(ProxyClientIPHeader)))
	if err != nil || !ip.IsValid() || ip.IsUnspecified() || ip.Zone() != "" {
		return ProxyIdentity{}, ErrInvalidProxyIdentity
	}
	rawTimestamp := header.Get(ProxyTimestampHeader)
	if len(rawTimestamp) < 1 || len(rawTimestamp) > 16 || strings.TrimSpace(rawTimestamp) != rawTimestamp {
		return ProxyIdentity{}, ErrInvalidProxyIdentity
	}
	seconds, err := strconv.ParseInt(rawTimestamp, 10, 64)
	if err != nil {
		return ProxyIdentity{}, ErrInvalidProxyIdentity
	}
	nonce := header.Get(ProxyNonceHeader)
	if !validProxyNonce(nonce) {
		return ProxyIdentity{}, ErrInvalidProxyIdentity
	}
	signature := header.Get(ProxySignatureHeader)
	if len(signature) != sha256.Size*2 || strings.ToLower(signature) != signature {
		return ProxyIdentity{}, ErrInvalidProxyIdentity
	}
	return ProxyIdentity{ClientIP: ip, Timestamp: time.Unix(seconds, 0).UTC(), Nonce: nonce, Signature: signature}, nil
}

func numericRemoteIP(remote string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return netip.Addr{}, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, ErrInvalidProxyIdentity
	}
	return ip, nil
}

func validProxyNonce(value string) bool {
	if len(value) < minProxyNonceBytes || len(value) > maxProxyNonceBytes {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' || character == '-') {
			return false
		}
	}
	return true
}
func validateProxyToken(value []byte) error {
	if len(value) < 32 || len(value) > 4096 {
		return ErrInvalidProxyIdentity
	}
	return nil
}
func proxyIdentitySignature(token []byte, clientIP string, seconds int64, nonce string) []byte {
	mac := hmac.New(sha256.New, token)
	_, _ = fmt.Fprintf(mac, "%s\n%s\n%d\n%s", proxyIdentityVersion, clientIP, seconds, nonce)
	return mac.Sum(nil)
}
func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
