package session

import (
	"context"
	"time"
)

type Store interface {
	Create(ctx context.Context, session *Session, ttl time.Duration) error
	Get(ctx context.Context, id SessionID) (*Session, error)
	Touch(ctx context.Context, id SessionID, now time.Time) error
	Delete(ctx context.Context, id SessionID) error
	Encode(s *Session) (string, error)
	TTL() time.Duration
}
