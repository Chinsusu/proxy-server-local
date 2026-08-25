package auth

import (
	"bytes"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

func jwtTestKey() []byte { return bytes.Repeat([]byte{7}, 32) }

func TestSignAndParseJWTRequiresPinnedClaims(t *testing.T) {
	secret := jwtTestKey()
	token, expiresAt, err := SignJWT("admin@example.test", "admin", secret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if expiresAt.IsZero() || expiresAt.After(time.Now().Add(MaxJWTTTL)) {
		t.Fatalf("invalid expiry %s", expiresAt)
	}
	claims, err := ParseJWT(token, secret)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "admin@example.test" || claims.Role != "admin" || claims.Issuer != JWTIssuer || !containsAudience(claims.Audience, JWTAudience) {
		t.Fatalf("claims=%+v", claims)
	}
}

func containsAudience(values jwt.ClaimStrings, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func TestSignJWTRejectsUnboundedTTLAndWeakKey(t *testing.T) {
	for _, testCase := range []struct {
		name string
		key  []byte
		ttl  time.Duration
	}{
		{"weak_key", []byte("short"), time.Hour},
		{"zero_ttl", jwtTestKey(), 0},
		{"negative_ttl", jwtTestKey(), -time.Second},
		{"unbounded_ttl", jwtTestKey(), MaxJWTTTL + time.Second},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, _, err := SignJWT("admin", "admin", testCase.key, testCase.ttl); err == nil {
				t.Fatal("unsafe signer input accepted")
			}
		})
	}
}

func TestParseJWTRejectsWrongAlgorithmAndRequiredClaims(t *testing.T) {
	secret := jwtTestKey()
	now := time.Now().UTC()
	validClaims := func() Claims {
		return Claims{Role: "admin", RegisteredClaims: jwt.RegisteredClaims{
			Issuer: JWTIssuer, Subject: "admin", Audience: jwt.ClaimStrings{JWTAudience},
			IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		}}
	}
	makeToken := func(method jwt.SigningMethod, claims Claims, signingKey []byte) string {
		t.Helper()
		token := jwt.NewWithClaims(method, claims)
		encoded, err := token.SignedString(signingKey)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	for _, testCase := range []struct {
		name  string
		token func() string
	}{
		{"hs384", func() string { return makeToken(jwt.SigningMethodHS384, validClaims(), secret) }},
		{"alg_none", func() string {
			token := jwt.NewWithClaims(jwt.SigningMethodNone, validClaims())
			encoded, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
			if err != nil {
				t.Fatal(err)
			}
			return encoded
		}},
		{"wrong_issuer", func() string {
			c := validClaims()
			c.Issuer = "other"
			return makeToken(jwt.SigningMethodHS256, c, secret)
		}},
		{"wrong_audience", func() string {
			c := validClaims()
			c.Audience = jwt.ClaimStrings{"other"}
			return makeToken(jwt.SigningMethodHS256, c, secret)
		}},
		{"missing_exp", func() string {
			c := validClaims()
			c.ExpiresAt = nil
			return makeToken(jwt.SigningMethodHS256, c, secret)
		}},
		{"missing_iat", func() string {
			c := validClaims()
			c.IssuedAt = nil
			return makeToken(jwt.SigningMethodHS256, c, secret)
		}},
		{"future_iat", func() string {
			c := validClaims()
			c.IssuedAt = jwt.NewNumericDate(now.Add(time.Hour))
			c.ExpiresAt = jwt.NewNumericDate(now.Add(2 * time.Hour))
			return makeToken(jwt.SigningMethodHS256, c, secret)
		}},
		{"expired", func() string {
			c := validClaims()
			c.ExpiresAt = jwt.NewNumericDate(now.Add(-time.Hour))
			return makeToken(jwt.SigningMethodHS256, c, secret)
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := ParseJWT(testCase.token(), secret); err == nil {
				t.Fatal("unsafe token was accepted")
			}
		})
	}
}

func TestParseJWTRejectsWrongKeyAndGarbage(t *testing.T) {
	token, _, err := SignJWT("admin", "admin", jwtTestKey(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseJWT(token, bytes.Repeat([]byte{8}, 32)); err == nil {
		t.Fatal("wrong key accepted")
	}
	if _, err := ParseJWT("not-a-jwt", jwtTestKey()); err == nil {
		t.Fatal("garbage token accepted")
	}
}
