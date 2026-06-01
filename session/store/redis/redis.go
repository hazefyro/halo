package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hazefyro/halo/session"
	"github.com/redis/go-redis/v9"
)

// Store is a Redis-backed session store.
type Store struct {
	cfg Config
}

// New creates a Store from the given options. It requires a client and a
// positive TTL.
func New(opts ...Option) (*Store, error) {
	c := applyOption(opts)

	if err := c.validate(); err != nil {
		return nil, err
	}

	return &Store{
			cfg: c,
		},
		nil
}

// Save writes the session to Redis under its ID with the configured TTL.
func (s *Store) Save(ctx context.Context, sess *session.Session) error {
	data, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("redis: marshal session: %w", err)
	}

	if err := s.cfg.Client.Set(ctx, s.key(sess.ID), data, s.cfg.TTL).Err(); err != nil {
		return fmt.Errorf("redis: save session: %w", err)
	}

	return nil
}

// Get returns the session for id, or [session.ErrSessionNotFound] if absent.
func (s *Store) Get(ctx context.Context, id session.SessionID) (*session.Session, error) {
	data, err := s.cfg.Client.Get(ctx, s.key(id)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, session.ErrSessionNotFound
		}
		return nil, fmt.Errorf("redis: get session: %w", err)
	}

	var sess session.Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, fmt.Errorf("redis: unmarshal: %w", err)
	}

	return &sess, nil
}

// Touch extends the session's expiry and rewrites it with a fresh TTL.
func (s *Store) Touch(ctx context.Context, sess *session.Session, now time.Time) error {
	sess.LastSeenAt = now
	sess.ExpiresAt = now.Add(s.cfg.TTL)

	data, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("redis: marshal session: %w", err)
	}

	if err := s.cfg.Client.Set(ctx, s.key(sess.ID), data, s.cfg.TTL).Err(); err != nil {
		return fmt.Errorf("redis: touch session: %w", err)
	}

	return nil
}

// Delete removes the session for id; a missing key is not an error.
func (s *Store) Delete(ctx context.Context, id session.SessionID) error {
	if err := s.cfg.Client.Del(ctx, s.key(id)).Err(); err != nil {
		return fmt.Errorf("redis: delete session: %w", err)
	}

	return nil
}

// Encode returns the cookie value for the session: its opaque ID.
func (s *Store) Encode(sess *session.Session) (string, error) {
	return sess.ID.String(), nil
}

// TTL returns the configured session lifetime.
func (s *Store) TTL() time.Duration {
	return s.cfg.TTL
}

func (s *Store) key(id session.SessionID) string {
	return s.cfg.KeyPrefix + id.String()
}

var _ session.Store = (*Store)(nil)
