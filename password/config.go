package password

import "github.com/hazefyro/halo/password/hasher"

type Config struct {
	Hasher          hasher.Hasher
	CollectName     bool
	CollectUsername bool
	CollectAvatar   bool
}

type Option func(*Config)

// WithHasher sets the password hasher. When unset, the Manager uses
// hasher.Default() (bcrypt).
func WithHasher(h hasher.Hasher) Option {
	return func(c *Config) { c.Hasher = h }
}

func WithName() Option {
	return func(c *Config) { c.CollectName = true }
}

func WithUsername() Option {
	return func(c *Config) { c.CollectUsername = true }
}

func WithAvatar() Option {
	return func(c *Config) { c.CollectAvatar = true }
}

func applyOptions(opts []Option) Config {
	c := Config{Hasher: hasher.Default()}
	for _, opt := range opts {
		opt(&c)
	}
	return c
}
