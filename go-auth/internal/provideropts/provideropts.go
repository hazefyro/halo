package provideropts

import "golang.org/x/oauth2"

type Config struct {
	Scopes          []string
	AuthCodeOptions []oauth2.AuthCodeOption
}

type Option func(*Config)

func WithScopes(scopes ...string) Option {
	return func(c *Config) { c.Scopes = scopes }
}

func WithAuthCodeOptions(opts ...oauth2.AuthCodeOption) Option {
	return func(c *Config) { c.AuthCodeOptions = append(c.AuthCodeOptions, opts...) }
}

func Apply(opts []Option) Config {
	c := Config{}
	for _, opt := range opts {
		opt(&c)
	}
	return c
}
