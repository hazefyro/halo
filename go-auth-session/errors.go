package session

import "errors"

var (
	ErrMissingSigningKey = errors.New("go-auth-session: missing signing key")
	ErrInvalidTTL        = errors.New("go-auth-session: invalid ttl")
	ErrInvalidClock      = errors.New("go-auth-session: invalid clock")
	ErrNilStore          = errors.New("go-auth-session: store must be set")
	ErrSessionExpired    = errors.New("go-auth-session: session expired")
	ErrSessionNotFound   = errors.New("go-auth-session: session not found")
)
