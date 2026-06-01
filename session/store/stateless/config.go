package stateless

import (
	"net/http"
	"time"

	session "github.com/hazefyro/auth/session"
)

type Config struct {
	session.Config
	SigningKey []byte
	TTL        time.Duration
	Issuer     string
}

type Option func(*Config)

func WithSigningKey(key []byte) Option {
	return func(c *Config) { c.SigningKey = key }
}

func WithTTL(ttl time.Duration) Option {
	return func(c *Config) { c.TTL = ttl }
}

func WithIssuer(issuer string) Option {
	return func(c *Config) { c.Issuer = issuer }
}

func defaultConfig() Config {
	return Config{
		Config: session.Config{
			CookieName: "session",
			Secure:     true,
			HttpOnly:   true,
			SameSite:   http.SameSiteLaxMode,
			Path:       "/",
			Now:        time.Now,
		},
		TTL:    24 * time.Hour,
		Issuer: "session",
	}
}

func applyOptions(opts []Option) Config {
	c := defaultConfig()
	for _, opt := range opts {
		opt(&c)
	}
	return c
}

func (c Config) validate() error {
	if len(c.SigningKey) == 0 {
		return session.ErrMissingSigningKey
	}
	if c.TTL <= 0 {
		return session.ErrInvalidTTL
	}

	return nil
}
