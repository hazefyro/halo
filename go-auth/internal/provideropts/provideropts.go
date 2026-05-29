package provideropts

import (
	"net/http"

	"golang.org/x/oauth2"
)

type Config struct {
	Scopes           []string
	AdditionalScopes []string
	AuthCodeOptions  []oauth2.AuthCodeOption
	HTTPClient       *http.Client
	UserInfoURL      string
	Endpoint         *oauth2.Endpoint
}

type Option func(*Config)

func WithScopes(scopes ...string) Option {
	return func(c *Config) { c.Scopes = scopes }
}

func WithAdditionalScopes(scopes ...string) Option {
	return func(c *Config) { c.AdditionalScopes = append(c.AdditionalScopes, scopes...) }
}

func WithAuthCodeOptions(opts ...oauth2.AuthCodeOption) Option {
	return func(c *Config) { c.AuthCodeOptions = append(c.AuthCodeOptions, opts...) }
}

func WithHTTPClient(client *http.Client) Option {
	return func(c *Config) { c.HTTPClient = client }
}

func WithUserInfoURL(url string) Option {
	return func(c *Config) { c.UserInfoURL = url }
}

func WithEndpoint(e oauth2.Endpoint) Option {
	return func(c *Config) { c.Endpoint = &e }
}

func Apply(opts []Option) Config {
	c := Config{}
	for _, opt := range opts {
		opt(&c)
	}
	return c
}
