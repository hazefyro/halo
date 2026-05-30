package session

import (
	"crypto/rand"
	"encoding/base64"
	"time"
)

type SessionID string

type Session struct {
	ID         SessionID
	UserID     string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastSeenAt time.Time
}

func (s *Session) isExpired(now time.Time) bool {
	return !s.ExpiresAt.After(now)
}

func generateID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
