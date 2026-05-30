package session

import (
	"net/http"
	"time"
)

type Config struct {
	CookieName string
	Secure     bool
	HttpOnly   bool
	SameSite   http.SameSite
	Path       string
	Now        func() time.Time
}

type Option func(*Config)

func WithCookieName(name string) Option {
	return func(c *Config) { c.CookieName = name }
}

func WithSecure(secure bool) Option {
	return func(c *Config) { c.Secure = secure }
}

func WithHTTPOnly(httpOnly bool) Option {
	return func(c *Config) { c.HttpOnly = httpOnly }
}

func WithSameSite(sameSite http.SameSite) Option {
	return func(c *Config) { c.SameSite = sameSite }
}

func WithPath(path string) Option {
	return func(c *Config) { c.Path = path }
}

func WithNow(now func() time.Time) Option {
	return func(c *Config) { c.Now = now }
}

func defaultConfig() Config {
	return Config{
		CookieName: "session",
		HttpOnly:   true,
		SameSite:   http.SameSiteLaxMode,
		Path:       "/",
		Now:        time.Now,
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
	if c.Now == nil {
		return ErrInvalidClock
	}
	return nil
}
