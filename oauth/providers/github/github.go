package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/hazefyro/halo"
	"github.com/hazefyro/halo/oauth"
	"github.com/hazefyro/halo/oauth/internal/maputil"
	"github.com/hazefyro/halo/oauth/internal/oauthutil"
	"github.com/hazefyro/halo/oauth/internal/provideropts"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// WithHTTPClient configures the HTTP client used for token and userinfo calls.
var WithHTTPClient = provideropts.WithHTTPClient

// WithUserInfoURL overrides the GitHub user endpoint.
var WithUserInfoURL = provideropts.WithUserInfoURL

// WithEndpoint overrides the GitHub OAuth endpoint.
var WithEndpoint = provideropts.WithEndpoint

const userInfoURL = "https://api.github.com/user"
const userEmailURL = "https://api.github.com/user/emails"

// Option configures a Provider.
type Option = provideropts.Option

// WithScopes replaces the default OAuth scopes.
var WithScopes = provideropts.WithScopes

// WithAdditionalScopes appends scopes to the defaults.
var WithAdditionalScopes = provideropts.WithAdditionalScopes

// WithAuthCodeOptions adds options to the authorization URL.
var WithAuthCodeOptions = provideropts.WithAuthCodeOptions

// Provider implements GitHub OAuth2 authentication.
type Provider struct {
	config          *oauth2.Config
	userInfoURL     string
	httpClient      *http.Client
	authCodeOptions []oauth2.AuthCodeOption
}

// New creates a GitHub provider.
func New(clientID, clientSecret, redirectURL string, opts ...Option) *Provider {
	cfg := provideropts.Apply(opts)
	scopes := []string{"read:user", "user:email"}
	if len(cfg.Scopes) > 0 {
		scopes = cfg.Scopes
	} else {
		scopes = append(scopes, cfg.AdditionalScopes...)
	}
	endpoint := github.Endpoint
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
func (p *Provider) Name() string { return "github" }

// BeginAuth returns the GitHub authorization URL.
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

	// GitHub's profile email carries no verification signal, so the authoritative
	// verified address lives in the emails endpoint. Prefer it; fall back to the
	// (unverified) profile email only when the emails endpoint yields none.
	email := maputil.GetString(raw, "email")
	emailVerified := false
	primary, verified, err := fetchPrimaryEmail(p.config.Client(ctx, token))
	if err != nil {
		return oauth.AuthResult{}, err
	}
	if primary != "" {
		email, emailVerified = primary, verified
	}

	return oauth.AuthResult{
		Identity: halo.Identity{
			ID:            id,
			Email:         email,
			EmailVerified: emailVerified,
			Username:      maputil.GetString(raw, "login"),
			Name:          maputil.GetString(raw, "name"),
			AvatarURL:     maputil.GetString(raw, "avatar_url"),
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

// fetchPrimaryEmail returns the user's primary email and whether GitHub has
// verified it. It returns an empty email when the account has no primary.
func fetchPrimaryEmail(client *http.Client) (email string, verified bool, err error) {
	res, err := client.Get(userEmailURL)
	if err != nil {
		return "", false, err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", false, fmt.Errorf("emails request failed with status %d", res.StatusCode)
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}

	dec := json.NewDecoder(io.LimitReader(res.Body, 1<<20))
	dec.UseNumber()
	if err := dec.Decode(&emails); err != nil {
		return "", false, err
	}

	for _, e := range emails {
		if e.Primary {
			return e.Email, e.Verified, nil
		}
	}

	return "", false, nil
}
