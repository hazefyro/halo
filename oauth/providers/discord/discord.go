package discord

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hazefyro/halo"
	"github.com/hazefyro/halo/oauth"
	"github.com/hazefyro/halo/oauth/internal/maputil"
	"github.com/hazefyro/halo/oauth/internal/oauthutil"
	"github.com/hazefyro/halo/oauth/internal/provideropts"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

// WithHTTPClient configures the HTTP client used for token and userinfo calls.
var WithHTTPClient = provideropts.WithHTTPClient

// WithUserInfoURL overrides the Discord userinfo endpoint.
var WithUserInfoURL = provideropts.WithUserInfoURL

// WithEndpoint overrides the Discord OAuth endpoint.
var WithEndpoint = provideropts.WithEndpoint

const userInfoURL = "https://discord.com/api/users/@me"

// Option configures a Provider.
type Option = provideropts.Option

// WithScopes replaces the default OAuth scopes.
var WithScopes = provideropts.WithScopes

// WithAdditionalScopes appends scopes to the defaults.
var WithAdditionalScopes = provideropts.WithAdditionalScopes

// WithAuthCodeOptions adds options to the authorization URL.
var WithAuthCodeOptions = provideropts.WithAuthCodeOptions

// Provider implements Discord OAuth2 authentication.
type Provider struct {
	config          *oauth2.Config
	userInfoURL     string
	httpClient      *http.Client
	authCodeOptions []oauth2.AuthCodeOption
}

// New creates a Discord provider.
func New(clientID, clientSecret, redirectURL string, opts ...Option) *Provider {
	cfg := provideropts.Apply(opts)
	scopes := []string{"identify", "email"}
	if len(cfg.Scopes) > 0 {
		scopes = cfg.Scopes
	} else {
		scopes = append(scopes, cfg.AdditionalScopes...)
	}
	endpoint := endpoints.Discord
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
func (p *Provider) Name() string { return "discord" }

// BeginAuth returns the Discord authorization URL.
func (p *Provider) BeginAuth(state string) (string, error) {
	return p.config.AuthCodeURL(state, p.authCodeOptions...), nil
}

// CompleteAuth exchanges a callback request for identity and credentials.
func (p *Provider) CompleteAuth(r *http.Request) (oauth.AuthResult, error) {
	code := r.URL.Query().Get("code")
	if code == "" {
		return oauth.AuthResult{}, oauth.ErrMissingCode
	}

	ctx := r.Context()
	if p.httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)
	}

	raw, token, err := oauthutil.FetchUserInfo(ctx, p.config, code, p.userInfoURL)
	if err != nil {
		return oauth.AuthResult{}, err
	}

	id := maputil.GetID(raw, "id")
	if id == "" {
		return oauth.AuthResult{}, oauth.ErrMissingUserID
	}

	avatarHash := maputil.GetString(raw, "avatar")
	avatarURL := ""
	if avatarHash != "" {
		avatarURL = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", id, avatarHash)
	}

	return oauth.AuthResult{
		Identity: halo.Identity{
			ID:            id,
			Email:         maputil.GetString(raw, "email"),
			EmailVerified: maputil.GetBool(raw, "verified"),
			Username:      maputil.GetString(raw, "username"),
			Name:          maputil.GetString(raw, "global_name"),
			AvatarURL:     avatarURL,
			Provider:      p.Name(),
		},
		Credentials: oauth.Credentials{
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			ExpiresAt:    token.Expiry,
		},
		RawData: raw,
	}, nil
}

// RefreshToken refreshes Discord OAuth credentials.
func (p *Provider) RefreshToken(ctx context.Context, refreshToken string) (oauth.Credentials, error) {
	if p.httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)
	}
	return oauthutil.RefreshToken(ctx, p.config, refreshToken)
}
