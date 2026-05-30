package cookie

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
	session "github.com/haze/go-auth-session"
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


var _ session.Store = (*Store)(nil)
