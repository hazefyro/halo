package session

import (
	"context"
	"time"
)

type Store interface {
	Save(ctx context.Context, session *Session) error
	Get(ctx context.Context, id SessionID) (*Session, error)
	Touch(ctx context.Context, sess *Session, now time.Time) error
	Delete(ctx context.Context, id SessionID) error
	Encode(s *Session) (string, error)
	TTL() time.Duration
}
