package auth

import "time"

// RawData is the raw JSON payload returned by the provider's userinfo endpoint.
type RawData map[string]any

// Identity is the normalized user identity returned by a provider.
type Identity struct {
	ID        string
	Email     string
	Name      string
	Username  string // login name: Discord tag, GitHub login
	AvatarURL string
	Provider  string // "google", "discord", etc.
}

// Credentials contains OAuth credentials returned by a provider.
type Credentials struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// AuthResult is the full result of a completed OAuth callback.
type AuthResult struct {
	Identity    Identity
	Credentials Credentials
	RawData     RawData
}
