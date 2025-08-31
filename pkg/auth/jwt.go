package auth

import (
    "errors"
    "time"

    jwt "github.com/golang-jwt/jwt/v5"
)

// Claims carries minimal identity + role.
type Claims struct {
    Role string `json:"role"`
    jwt.RegisteredClaims
}

func SignJWT(subject, role, secret string, ttl time.Duration) (string, time.Time, error) {
    if secret == "" {
        return "", time.Time{}, errors.New("empty secret")
    }
    now := time.Now()
    exp := now.Add(ttl)
    claims := Claims{
        Role: role,
        RegisteredClaims: jwt.RegisteredClaims{
            Subject:   subject,
            IssuedAt:  jwt.NewNumericDate(now),
            ExpiresAt: jwt.NewNumericDate(exp),
        },
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    s, err := token.SignedString([]byte(secret))
    return s, exp, err
}

func ParseJWT(tokenStr, secret string) (*Claims, error) {
    t, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, errors.New("unexpected signing method")
        }
        return []byte(secret), nil
    })
    if err != nil { return nil, err }
    if !t.Valid { return nil, errors.New("invalid token") }
    c, ok := t.Claims.(*Claims)
    if !ok { return nil, errors.New("invalid claims") }
    return c, nil
}
