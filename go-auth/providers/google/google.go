package google

import (
	"context"
	"net/http"

	goauth "github.com/haze/go-auth"
	"github.com/haze/go-auth/internal/maputil"
	"github.com/haze/go-auth/internal/oauthutil"
	"github.com/haze/go-auth/internal/provideropts"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// WithHTTPClient configures the HTTP client used for token and userinfo calls.
var WithHTTPClient = provideropts.WithHTTPClient

// WithUserInfoURL overrides the Google userinfo endpoint.
var WithUserInfoURL = provideropts.WithUserInfoURL

// WithEndpoint overrides the Google OAuth endpoint.
var WithEndpoint = provideropts.WithEndpoint

const userInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"

// Option configures a Provider.
type Option = provideropts.Option

// WithScopes replaces the default OAuth scopes.
var WithScopes = provideropts.WithScopes

// WithAdditionalScopes appends scopes to the defaults.
var WithAdditionalScopes = provideropts.WithAdditionalScopes

// WithAuthCodeOptions adds options to the authorization URL.
var WithAuthCodeOptions = provideropts.WithAuthCodeOptions

// Provider implements Google OpenID Connect authentication.
type Provider struct {
	config          *oauth2.Config
	userInfoURL     string
	httpClient      *http.Client
	authCodeOptions []oauth2.AuthCodeOption
}

// New creates a Google provider.
func New(clientID, clientSecret, redirectURL string, opts ...Option) *Provider {
	cfg := provideropts.Apply(opts)
	scopes := []string{"openid", "email", "profile"}
	if len(cfg.Scopes) > 0 {
		scopes = cfg.Scopes
	} else {
		scopes = append(scopes, cfg.AdditionalScopes...)
	}
	endpoint := google.Endpoint
	if cfg.Endpoint != nil {
		endpoint = *cfg.Endpoint
	}
	infoURL := userInfoURL
	if cfg.UserInfoURL != "" {
		infoURL = cfg.UserInfoURL
	}
	return &Provider{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       scopes,
			Endpoint:     endpoint,
		},
		userInfoURL:     infoURL,
		httpClient:      cfg.HTTPClient,
		authCodeOptions: cfg.AuthCodeOptions,
	}
}

// Name returns the provider name.
func (p *Provider) Name() string { return "google" }

// BeginAuth returns the Google authorization URL.
func (p *Provider) BeginAuth(state string) (string, error) {
	opts := append([]oauth2.AuthCodeOption{oauth2.AccessTypeOffline}, p.authCodeOptions...)
	return p.config.AuthCodeURL(state, opts...), nil
}

// CompleteAuth exchanges a callback request for identity and credentials.
func (p *Provider) CompleteAuth(r *http.Request) (goauth.AuthResult, error) {
	code := r.URL.Query().Get("code")
	if code == "" {
		return goauth.AuthResult{}, goauth.ErrMissingCode
	}

	ctx := r.Context()
	if p.httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)
	}

	raw, token, err := oauthutil.FetchUserInfo(ctx, p.config, code, p.userInfoURL)
	if err != nil {
		return goauth.AuthResult{}, err
	}

	id := maputil.GetID(raw, "sub")
	if id == "" {
		return goauth.AuthResult{}, goauth.ErrMissingUserID
	}

	return goauth.AuthResult{
		Identity: goauth.Identity{
			ID:        id,
			Email:     maputil.GetString(raw, "email"),
			Name:      maputil.GetString(raw, "name"),
			AvatarURL: maputil.GetString(raw, "picture"),
			Provider:  p.Name(),
		},
		Credentials: goauth.Credentials{
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			ExpiresAt:    token.Expiry,
		},
		RawData: raw,
	}, nil
}

// RefreshToken refreshes Google OAuth credentials.
func (p *Provider) RefreshToken(ctx context.Context, refreshToken string) (goauth.Credentials, error) {
	if p.httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)
	}
	return oauthutil.RefreshToken(ctx, p.config, refreshToken)
}
