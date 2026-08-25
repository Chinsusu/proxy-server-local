package auth

import (
	"errors"
	"fmt"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	JWTIssuer   = "pgw-api"
	JWTAudience = "pgw-admin"
	MaxJWTTTL   = 12 * time.Hour
	minKeyBytes = 32
)

// Claims contains only the authenticated subject and role. Registered claims
// are deliberately mandatory at verification time; accepting a token missing
// expiry, issued-at, issuer, or audience is a security failure.
type Claims struct {
	Role string `json:"role"`
	jwt.RegisteredClaims
}

func SignJWT(subject, role string, secret []byte, ttl time.Duration) (string, time.Time, error) {
	if len(secret) < minKeyBytes {
		return "", time.Time{}, errors.New("JWT signing key is too short")
	}
	if subject == "" || role == "" {
		return "", time.Time{}, errors.New("JWT subject and role are required")
	}
	if ttl <= 0 || ttl > MaxJWTTTL {
		return "", time.Time{}, fmt.Errorf("JWT TTL must be between 1ns and %s", MaxJWTTTL)
	}
	now := time.Now().UTC()
	expiresAt := now.Add(ttl)
	claims := Claims{
		Role: role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    JWTIssuer,
			Subject:   subject,
			Audience:  jwt.ClaimStrings{JWTAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(secret)
	return signed, expiresAt, err
}

// ParseJWT pins the exact HS256 algorithm and requires the issuer, audience,
// expiration, and issued-at claims emitted by SignJWT. No other HMAC variant
// or algorithm can cross this boundary.
func ParseJWT(tokenString string, secret []byte) (*Claims, error) {
	if len(secret) < minKeyBytes {
		return nil, errors.New("JWT signing key is too short")
	}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(JWTIssuer),
		jwt.WithAudience(JWTAudience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	claims := &Claims{}
	token, err := parser.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		if token.Method == nil || token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("unexpected JWT signing method")
		}
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	if token == nil || !token.Valid || claims.Subject == "" || claims.Role == "" || claims.IssuedAt == nil || claims.ExpiresAt == nil {
		return nil, errors.New("invalid JWT claims")
	}
	return claims, nil
}
