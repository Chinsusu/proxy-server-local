// Package secret implements the small, auditable secret boundary used by the
// SQLite repository. Plaintext is accepted only at that boundary and is never
// represented in a public/read DTO.
package secret

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	KeySize           = 32 // AES-256
	EnvelopeVersion   = 1
	DefaultKeyPath    = "/etc/pgw/secrets.key"
	maxKeyFileBytes   = 256
	maxTokenFileBytes = 4096
)

// LoadTokenFile reads a service token from a no-follow, owner-validated file.
// Systemd credential files are intentionally read-only (0400), while fallback
// service files may be 0600. Neither permits group or world access. The token
// itself is not supplied through an environment variable, command-line
// argument, log, or database row.
func LoadTokenFile(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("secret: token path is required")
	}
	raw, err := secureReadTokenFile(path, maxTokenFileBytes)
	if err != nil {
		return nil, err
	}
	defer wipe(raw)
	token := bytes.TrimSpace(raw)
	if len(token) == 0 || bytes.IndexByte(token, 0) >= 0 {
		return nil, fmt.Errorf("secret: token file is empty or invalid")
	}
	return append([]byte(nil), token...), nil
}

var (
	ErrInvalidKey              = errors.New("secret: key must contain exactly 32 bytes")
	ErrUnsafeKeyFile           = errors.New("secret: key file must be a regular owner-only 0400 or 0600 file")
	ErrUnsafeTokenFile         = errors.New("secret: token file must be a regular owner-only 0400 or 0600 file")
	ErrUnsafeAdminPasswordFile = errors.New("secret: admin password file must be a root-owned regular 0400 or 0600 file below root-owned non-writable directories")
	ErrACLUnsupported          = errors.New("secret: Windows key-file ACL validation is not available")
	ErrUnknownEnvelope         = errors.New("secret: unsupported envelope version")
)

// KeyProvider allows the runtime key source to be supplied without coupling
// persistence to a particular deployment mechanism.
type KeyProvider interface {
	Key(context.Context) ([]byte, error)
}

type FileKeyProvider struct {
	Path string
}

func (p FileKeyProvider) Key(_ context.Context) ([]byte, error) {
	return LoadKeyFile(p.Path)
}

// LoadKeyFile loads a raw 32-byte master key. A systemd credential may be
// exact owner-only 0400; the persistent fallback may be exact owner-only 0600.
// The platform reader opens once, verifies the opened inode (not a prior path
// lookup), bounds the read, and validates the service-owned parent directory.
// Windows fails closed until an ACL-aware implementation is available.
func LoadKeyFile(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("secret: key path is required")
	}
	raw, err := secureReadKeyFile(path, maxKeyFileBytes)
	if err != nil {
		return nil, err
	}
	defer wipe(raw)
	key, err := decodeKey(raw)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func decodeKey(b []byte) ([]byte, error) {
	if len(b) == KeySize {
		return append([]byte(nil), b...), nil
	}
	// Do not turn key material into an immutable Go string: strings cannot be
	// wiped and can outlive this call in compiler/runtime storage.
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == KeySize*2 {
		out := make([]byte, KeySize)
		success := false
		defer func() {
			if !success {
				wipe(out)
				notifyDecodeKeyWiped(out)
			}
		}()
		for i := range out {
			var n byte
			for j := 0; j < 2; j++ {
				c := trimmed[i*2+j]
				var v byte
				switch {
				case c >= '0' && c <= '9':
					v = c - '0'
				case c >= 'a' && c <= 'f':
					v = c - 'a' + 10
				case c >= 'A' && c <= 'F':
					v = c - 'A' + 10
				default:
					return nil, ErrInvalidKey
				}
				n = n<<4 | v
				out[i] = n
			}
		}
		success = true
		return out, nil
	}
	return nil, ErrInvalidKey
}

// decodeKeyWipeHook is test-only proof that malformed hexadecimal input does
// not retain partially decoded bytes. It receives only an already-wiped copy.
// Production leaves it nil and never exposes key material.
var decodeKeyWipeHook func([]byte)

func notifyDecodeKeyWiped(value []byte) {
	if decodeKeyWipeHook == nil {
		return
	}
	decodeKeyWipeHook(append([]byte(nil), value...))
}

type AESGCM struct {
	aead cipher.AEAD
}

func NewAESGCM(key []byte) (*AESGCM, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secret: create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secret: create GCM: %w", err)
	}
	return &AESGCM{aead: aead}, nil
}

// Envelope records a format version and a fresh nonce for each secret. The
// proxy ID is used as AES-GCM associated data by the repository, binding a
// copied ciphertext to neither another proxy nor another database row.
type Envelope struct {
	Version    uint8
	Nonce      []byte
	Ciphertext []byte
}

func (c *AESGCM) Seal(plaintext, additionalData []byte) (Envelope, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Envelope{}, fmt.Errorf("secret: generate nonce: %w", err)
	}
	return Envelope{
		Version:    EnvelopeVersion,
		Nonce:      nonce,
		Ciphertext: c.aead.Seal(nil, nonce, plaintext, additionalData),
	}, nil
}

func (c *AESGCM) Open(envelope Envelope, additionalData []byte) ([]byte, error) {
	if envelope.Version != EnvelopeVersion {
		return nil, ErrUnknownEnvelope
	}
	if len(envelope.Nonce) != c.aead.NonceSize() {
		return nil, fmt.Errorf("secret: invalid nonce length")
	}
	plain, err := c.aead.Open(nil, envelope.Nonce, envelope.Ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("secret: decrypt: %w", err)
	}
	return plain, nil
}
