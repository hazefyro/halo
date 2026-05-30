package session

import "time"

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
