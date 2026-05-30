package cookie

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
	session "github.com/hazefyro/go-auth/session"
)

type Store struct {
	cfg Config
}

type Claims struct {
	jwt.RegisteredClaims
	UserID     string `json:"user_id"`
	CreatedAt  int64  `json:"created_at"`
	LastSeenAt int64  `json:"last_seen_at"`
}

func New(opts ...Option) (*Store, error) {
	c := applyOptions(opts)

	if err := c.validate(); err != nil {
		return nil, err
	}

	return &Store{
		cfg: c,
	}, nil
}

func (s *Store) Save(ctx context.Context, session *session.Session) error {
	return nil
}

func (s *Store) Delete(ctx context.Context, id session.SessionID) error {
	return nil
}

func (s *Store) Encode(sess *session.Session) (string, error) {
	c := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        sess.ID.String(),
			Issuer:    s.cfg.Issuer,
			ExpiresAt: jwt.NewNumericDate(sess.ExpiresAt),
			IssuedAt:  jwt.NewNumericDate(sess.CreatedAt),
		},
		UserID:     sess.UserID,
		CreatedAt:  sess.CreatedAt.Unix(),
		LastSeenAt: sess.LastSeenAt.Unix(),
	}

	t := jwt.NewWithClaims(jwt.SigningMethodHS256, c)

	return t.SignedString(s.cfg.SigningKey)
}

func (s *Store) Get(_ context.Context, id session.SessionID) (*session.Session, error) {
	t, err := jwt.ParseWithClaims(id.String(), &Claims{}, s.keyFunc,
		jwt.WithIssuer(s.cfg.Issuer),
		jwt.WithExpirationRequired())

	if err != nil || !t.Valid {
		return nil, session.ErrInvalidSession
	}

	c, ok := t.Claims.(*Claims)
	if !ok {
		return nil, session.ErrInvalidSession
	}

	return &session.Session{
		ID:         session.SessionID(c.ID),
		UserID:     c.UserID,
		CreatedAt:  time.Unix(c.CreatedAt, 0),
		ExpiresAt:  c.ExpiresAt.Time,
		LastSeenAt: time.Unix(c.LastSeenAt, 0),
	}, nil
}

func (s *Store) TTL() time.Duration {
	return s.cfg.TTL
}

func (s *Store) Touch(ctx context.Context, sess *session.Session, now time.Time) error {
	sess.LastSeenAt = now
	sess.ExpiresAt = now.Add(s.cfg.TTL)
	return nil
}

func (s *Store) keyFunc(t *jwt.Token) (any, error) {
	if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, session.ErrInvalidSession
	}
	return s.cfg.SigningKey, nil
}

var _ session.Store = (*Store)(nil)
