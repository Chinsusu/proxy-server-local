package auth

import (
    "crypto/rand"
    "encoding/base64"
    "errors"
    "fmt"
    "strings"

    "golang.org/x/crypto/argon2"
)

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

// HashPassword returns a PHC formatted argon2id hash: $argon2id$v=19$m=...,t=...,p=...$salt$hash
func HashPassword(password string, p ArgonParams) (string, error) {
    if password == "" {
        return "", errors.New("empty password")
    }
    salt := make([]byte, p.SaltLen)
    if _, err := rand.Read(salt); err != nil {
        return "", err
    }
    sum := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLen)
    b64Salt := base64.RawStdEncoding.EncodeToString(salt)
    b64Sum := base64.RawStdEncoding.EncodeToString(sum)
    phc := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", p.Memory, p.Iterations, p.Parallelism, b64Salt, b64Sum)
    return phc, nil
}

// VerifyPassword checks a PHC argon2id hash string against a plaintext password.
func VerifyPassword(phc, password string) (bool, error) {
    if !strings.HasPrefix(phc, "$argon2id$") {
        return false, errors.New("unsupported hash format")
    }
    // $argon2id$v=19$m=65536,t=3,p=2$<salt>$<sum>
    parts := strings.Split(phc, "$")
    if len(parts) != 6 {
        return false, errors.New("invalid phc format")
    }
    params := parts[3] // m=..,t=..,p=..
    saltB64 := parts[4]
    sumB64 := parts[5]

    // defaults in case parse fails
    p := DefaultParams()
    for _, kv := range strings.Split(params, ",") {
        if strings.HasPrefix(kv, "m=") {
            var m uint32
            _, _ = fmt.Sscanf(kv, "m=%d", &m)
            if m > 0 { p.Memory = m }
        } else if strings.HasPrefix(kv, "t=") {
            var t uint32
            _, _ = fmt.Sscanf(kv, "t=%d", &t)
            if t > 0 { p.Iterations = t }
        } else if strings.HasPrefix(kv, "p=") {
            var par uint8
            _, _ = fmt.Sscanf(kv, "p=%d", &par)
            if par > 0 { p.Parallelism = par }
        }
    }

    salt, err := base64.RawStdEncoding.DecodeString(saltB64)
    if err != nil { return false, err }
    sum, err := base64.RawStdEncoding.DecodeString(sumB64)
    if err != nil { return false, err }

    key := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, uint32(len(sum)))
    return subtleConstantTimeEquals(key, sum), nil
}

// subtleConstantTimeEquals compares two byte slices without leaking timing.
func subtleConstantTimeEquals(a, b []byte) bool {
    if len(a) != len(b) { return false }
    var v byte
    for i := 0; i < len(a); i++ { v |= a[i] ^ b[i] }
    return v == 0
}
