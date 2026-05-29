package goauth

import "time"

// RawData is the raw JSON payload returned by the provider's userinfo endpoint.
type RawData map[string]any

type User struct {
	ID        string
	Email     string
	Name      string
	Username  string // login name: Discord tag, GitHub login
	AvatarURL string
	Provider  string // "google", "discord", etc.
}

type Credentials struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

type Token struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

type AuthResult struct {
	User        User
	Credentials Credentials
	RawData     RawData
}
