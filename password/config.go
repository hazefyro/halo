package password

type Config struct {
	CollectName     bool
	CollectUsername bool
	CollectAvatar   bool
}

type Option func(*Config)

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
	c := Config{}
	for _, opt := range opts {
		opt(&c)
	}
	return c
}
