package agent

import (
	"crypto/sha256"
	"crypto/subtle"
	"strings"
)

const maxAuthorizationHeaderBytes = 8 << 10

// BearerAuthenticator retains only a one-way digest of the scoped Agent
// service token. The raw token is wiped immediately after descriptor-bound
// loading and is never kept in the HTTP server's long-lived state.
type BearerAuthenticator struct {
	digest [sha256.Size]byte
}

func NewBearerAuthenticator(tokenFile string) (*BearerAuthenticator, error) {
	token, err := readServiceToken(tokenFile)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(token)
	zero(token)
	return &BearerAuthenticator{digest: digest}, nil
}

func (a *BearerAuthenticator) Authorized(header string) bool {
	if a == nil || len(header) <= len("Bearer ") || len(header) > maxAuthorizationHeaderBytes || !strings.HasPrefix(header, "Bearer ") {
		return false
	}
	provided := []byte(strings.TrimPrefix(header, "Bearer "))
	if len(provided) == 0 {
		return false
	}
	digest := sha256.Sum256(provided)
	zero(provided)
	return subtle.ConstantTimeCompare(digest[:], a.digest[:]) == 1
}
