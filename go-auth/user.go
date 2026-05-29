package goauth

import "time"

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
	RawData      map[string]any
}

type Token struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}
