package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	maxArgonMemoryKiB   = 256 * 1024
	maxArgonIterations  = 10
	maxArgonParallelism = 8
)

var passwordWork = make(chan struct{}, 2)

// ErrPasswordWorkBusy indicates that the bounded global Argon2 budget is
// exhausted. Callers must return a deterministic overload response rather
// than queueing unbounded memory-hard work.
var ErrPasswordWorkBusy = errors.New("argon2id work budget exhausted")

// TryAcquirePasswordWork bounds concurrent Argon2 work globally. Callers must
// invoke the returned release exactly once; false means deterministic overload
// without allocating Argon2 memory.
func TryAcquirePasswordWork() (release func(), ok bool) {
	select {
	case passwordWork <- struct{}{}:
		return func() { <-passwordWork }, true
	default:
		return nil, false
	}
}

// Argon2id parameters (sane defaults for server-side hashing)
type ArgonParams struct {
	Memory      uint32 // KiB
	Iterations  uint32
	Parallelism uint8
	SaltLen     uint32
	KeyLen      uint32
}

func DefaultParams() ArgonParams {
	return ArgonParams{
		Memory:      64 * 1024, // 64 MiB
		Iterations:  3,
		Parallelism: 2,
		SaltLen:     16,
		KeyLen:      32,
	}
}

// HashPassword returns a PHC formatted Argon2id hash. Password is mutable so
// callers can wipe it; it is never converted to a Go string.
func HashPassword(password []byte, p ArgonParams) (string, error) {
	if len(password) == 0 {
		return "", errors.New("empty password")
	}
	if err := validateArgonParams(p); err != nil {
		return "", err
	}
	release, ok := TryAcquirePasswordWork()
	if !ok {
		return "", ErrPasswordWorkBusy
	}
	defer release()
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		wipe(salt)
		return "", err
	}
	defer wipe(salt)
	sum := argon2.IDKey(password, salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLen)
	defer wipe(sum)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Sum := base64.RawStdEncoding.EncodeToString(sum)
	phc := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", p.Memory, p.Iterations, p.Parallelism, b64Salt, b64Sum)
	return phc, nil
}

// HashPasswordBytes is a compatibility alias for byte-backed callers.
func HashPasswordBytes(password []byte, p ArgonParams) (string, error) {
	return HashPassword(password, p)
}

// VerifyPassword checks a PHC argon2id hash string against a plaintext password.
// VerifyPassword checks a PHC hash against a mutable plaintext password. It
// never converts password bytes to a Go string and wipes derived material.
func VerifyPassword(phc, password []byte) (bool, error) {
	p, salt, sum, err := parsePasswordHash(string(phc))
	if err != nil {
		return false, err
	}
	defer wipe(salt)
	defer wipe(sum)
	release, ok := TryAcquirePasswordWork()
	if !ok {
		return false, ErrPasswordWorkBusy
	}
	defer release()

	key := argon2.IDKey(password, salt, p.Iterations, p.Memory, p.Parallelism, uint32(len(sum)))
	defer wipe(key)
	return subtleConstantTimeEquals(key, sum), nil
}

func validateArgonParams(p ArgonParams) error {
	if p.Memory < 8 || p.Memory > maxArgonMemoryKiB || p.Iterations < 1 || p.Iterations > maxArgonIterations || p.Parallelism < 1 || p.Parallelism > maxArgonParallelism || p.SaltLen < 16 || p.SaltLen > 64 || p.KeyLen < 16 || p.KeyLen > 64 || p.Memory < 8*uint32(p.Parallelism) {
		return errors.New("invalid argon2id parameters")
	}
	return nil
}

// VerifyPasswordBytes is a compatibility alias for byte-backed callers.
func VerifyPasswordBytes(phc, password []byte) (bool, error) { return VerifyPassword(phc, password) }

// ValidatePasswordHash verifies that value is a bounded Argon2id PHC string
// accepted by VerifyPassword. It rejects malformed or resource-amplifying
// hashes during API startup rather than delaying failure until login traffic.
func ValidatePasswordHash(value string) error {
	_, salt, sum, err := parsePasswordHash(value)
	wipe(salt)
	wipe(sum)
	return err
}

func parsePasswordHash(phc string) (ArgonParams, []byte, []byte, error) {
	if !strings.HasPrefix(phc, "$argon2id$") {
		return ArgonParams{}, nil, nil, errors.New("unsupported hash format")
	}
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return ArgonParams{}, nil, nil, errors.New("invalid phc format")
	}
	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return ArgonParams{}, nil, nil, errors.New("invalid argon2id parameters")
	}
	memory, err := parsePHCParameter(params[0], "m=", 8, maxArgonMemoryKiB)
	if err != nil {
		return ArgonParams{}, nil, nil, err
	}
	iterations, err := parsePHCParameter(params[1], "t=", 1, maxArgonIterations)
	if err != nil {
		return ArgonParams{}, nil, nil, err
	}
	parallelism, err := parsePHCParameter(params[2], "p=", 1, maxArgonParallelism)
	if err != nil {
		return ArgonParams{}, nil, nil, err
	}
	if memory < 8*parallelism {
		return ArgonParams{}, nil, nil, errors.New("argon2id memory is too small for parallelism")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 16 || len(salt) > 64 {
		wipe(salt)
		return ArgonParams{}, nil, nil, errors.New("invalid argon2id salt")
	}
	sum, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(sum) < 16 || len(sum) > 64 {
		wipe(salt)
		wipe(sum)
		return ArgonParams{}, nil, nil, errors.New("invalid argon2id hash")
	}
	return ArgonParams{Memory: uint32(memory), Iterations: uint32(iterations), Parallelism: uint8(parallelism), SaltLen: uint32(len(salt)), KeyLen: uint32(len(sum))}, salt, sum, nil
}

func parsePHCParameter(value, prefix string, minimum, maximum uint64) (uint64, error) {
	if !strings.HasPrefix(value, prefix) || len(value) == len(prefix) {
		return 0, errors.New("invalid argon2id parameters")
	}
	parsed, err := strconv.ParseUint(strings.TrimPrefix(value, prefix), 10, 64)
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, errors.New("invalid argon2id parameters")
	}
	return parsed, nil
}

// subtleConstantTimeEquals compares two byte slices without leaking timing.
func subtleConstantTimeEquals(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
