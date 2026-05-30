package provideropts

import (
	"net/http"

	"golang.org/x/oauth2"
)

// Config is the applied provider option set.
type Config struct {
	Scopes           []string
	AdditionalScopes []string
	AuthCodeOptions  []oauth2.AuthCodeOption
	HTTPClient       *http.Client
	UserInfoURL      string
	Endpoint         *oauth2.Endpoint
}

// Option configures provider construction.
type Option func(*Config)

// WithScopes replaces a provider's default scopes.
func WithScopes(scopes ...string) Option {
	return func(c *Config) { c.Scopes = scopes }
}

// WithAdditionalScopes appends scopes to a provider's defaults.
func WithAdditionalScopes(scopes ...string) Option {
	return func(c *Config) { c.AdditionalScopes = append(c.AdditionalScopes, scopes...) }
}

// WithAuthCodeOptions adds OAuth authorization URL options.
func WithAuthCodeOptions(opts ...oauth2.AuthCodeOption) Option {
	return func(c *Config) { c.AuthCodeOptions = append(c.AuthCodeOptions, opts...) }
}

// WithHTTPClient configures the HTTP client used for OAuth requests.
func WithHTTPClient(client *http.Client) Option {
	return func(c *Config) { c.HTTPClient = client }
}

// WithUserInfoURL overrides the provider userinfo endpoint.
func WithUserInfoURL(url string) Option {
	return func(c *Config) { c.UserInfoURL = url }
}

// WithEndpoint overrides the provider OAuth endpoint.
func WithEndpoint(e oauth2.Endpoint) Option {
	return func(c *Config) { c.Endpoint = &e }
}

// Apply applies options and returns the resulting Config.
func Apply(opts []Option) Config {
	c := Config{}
	for _, opt := range opts {
		opt(&c)
	}
	return c
}
