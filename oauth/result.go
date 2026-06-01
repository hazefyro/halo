package oauth

import (
	"time"

	"github.com/hazefyro/halo"
)

// RawData is the raw JSON payload returned by a provider's userinfo endpoint.
type RawData map[string]any

// Credentials contains the OAuth tokens returned by a provider.
type Credentials struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// AuthResult is the full result of a completed OAuth callback: the normalized
// identity, the OAuth tokens, and the provider's raw userinfo payload.
type AuthResult struct {
	Identity    halo.Identity
	Credentials Credentials
	RawData     RawData
}
