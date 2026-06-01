package google

import (
	"context"
	"net/http"

	"github.com/hazefyro/halo"
	"github.com/hazefyro/halo/oauth"
	"github.com/hazefyro/halo/oauth/internal/maputil"
	"github.com/hazefyro/halo/oauth/internal/oauthutil"
	"github.com/hazefyro/halo/oauth/internal/provideropts"
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
func (p *Provider) BeginAuth(state, verifier string) (string, error) {
	opts := []oauth2.AuthCodeOption{oauth2.AccessTypeOffline}
	if verifier != "" {
		opts = append(opts, oauth2.S256ChallengeOption(verifier))
	}
	opts = append(opts, p.authCodeOptions...)
	return p.config.AuthCodeURL(state, opts...), nil
}

// CompleteAuth exchanges a callback request for identity and credentials.
func (p *Provider) CompleteAuth(r *http.Request, verifier string) (oauth.AuthResult, error) {
	code := r.URL.Query().Get("code")
	if code == "" {
		return oauth.AuthResult{}, oauth.ErrMissingCode
	}

	ctx := r.Context()
	if p.httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)
	}

	var exchangeOpts []oauth2.AuthCodeOption
	if verifier != "" {
		exchangeOpts = append(exchangeOpts, oauth2.VerifierOption(verifier))
	}

	raw, token, err := oauthutil.FetchUserInfo(ctx, p.config, code, p.userInfoURL, exchangeOpts...)
	if err != nil {
		return oauth.AuthResult{}, err
	}

	id := maputil.GetID(raw, "sub")
	if id == "" {
		return oauth.AuthResult{}, oauth.ErrMissingUserID
	}

	return oauth.AuthResult{
		Identity: halo.Identity{
			ID:            id,
			Email:         maputil.GetString(raw, "email"),
			EmailVerified: maputil.GetBool(raw, "email_verified"),
			Name:          maputil.GetString(raw, "name"),
			AvatarURL:     maputil.GetString(raw, "picture"),
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

// RefreshToken refreshes Google OAuth credentials.
func (p *Provider) RefreshToken(ctx context.Context, refreshToken string) (oauth.Credentials, error) {
	if p.httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)
	}
	return oauthutil.RefreshToken(ctx, p.config, refreshToken)
}
