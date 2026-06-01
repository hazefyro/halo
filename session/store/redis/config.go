package redis

import (
	"time"

	"github.com/hazefyro/halo/session"
	"github.com/redis/go-redis/v9"
)

type Config struct {
	Client    redis.Cmdable
	TTL       time.Duration
	KeyPrefix string
}

type Option func(*Config)

func WithClient(client redis.Cmdable) Option {
	return func(c *Config) { c.Client = client }
}

func WithTTL(ttl time.Duration) Option {
	return func(c *Config) { c.TTL = ttl }
}

func WithKeyPrefix(keyPrefix string) Option {
	return func(c *Config) { c.KeyPrefix = keyPrefix }
}

func defaultConfig() Config {
	return Config{
		TTL:       24 * time.Hour,
		KeyPrefix: "sess:",
	}
}

func applyOption(opts []Option) Config {
	c := defaultConfig()

	for _, opt := range opts {
		opt(&c)
	}

	return c
}

func (c Config) validate() error {
	if c.Client == nil {
		return session.ErrNilClient
	}
	if c.TTL <= 0 {
		return session.ErrInvalidTTL
	}

	return nil
}
