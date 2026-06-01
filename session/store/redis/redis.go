package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hazefyro/auth/session"
	"github.com/redis/go-redis/v9"
)

type Store struct {
	cfg Config
}

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

func (s *Store) Touch(ctx context.Context, sess *session.Session, now time.Time) error {
	sess.LastSeenAt = now
	sess.ExpiresAt = now.Add(s.cfg.TTL)

	if err := s.cfg.Client.Set(ctx, s.key(sess.ID), sess, s.cfg.TTL).Err(); err != nil {
		return fmt.Errorf("redis: touch session: %w", err)
	}

	return nil
}

func (s *Store) Delete(ctx context.Context, id session.SessionID) error {
	if err := s.cfg.Client.Del(ctx, s.key(id)).Err(); err != nil {
		return fmt.Errorf("redis: delete session: %w", err)
	}

	return nil
}

func (s *Store) Encode(sess *session.Session) (string, error) {
	return sess.ID.String(), nil
}

func (s *Store) TTL() time.Duration {
	return s.cfg.TTL
}

func (s *Store) key(id session.SessionID) string {
	return s.cfg.KeyPrefix + id.String()
}

var _ session.Store = (*Store)(nil)
