package session

import "errors"

var (
	ErrMissingSigningKey = errors.New("session: missing signing key")
	ErrWeakSigningKey    = errors.New("session: signing key must be at least 32 bytes")
	ErrInvalidTTL        = errors.New("session: invalid ttl")
	ErrInvalidClock      = errors.New("session: invalid clock")
	ErrNilStore          = errors.New("session: store must be set")
	ErrSessionExpired    = errors.New("session: session expired")
	ErrSessionNotFound   = errors.New("session: session not found")
	ErrInvalidSession    = errors.New("session: invalid session")
	ErrNilClient         = errors.New("session: client must be set")
)
