package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	goauth "github.com/haze/go-auth"
	"github.com/haze/go-auth/internal/maputil"
	"github.com/haze/go-auth/internal/oauthutil"
	"github.com/haze/go-auth/internal/provideropts"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

var WithHTTPClient = provideropts.WithHTTPClient
var WithUserInfoURL = provideropts.WithUserInfoURL
var WithEndpoint = provideropts.WithEndpoint

const userInfoURL = "https://api.github.com/user"
const userEmailURL = "https://api.github.com/user/emails"

type Option = provideropts.Option

var WithScopes = provideropts.WithScopes
var WithAdditionalScopes = provideropts.WithAdditionalScopes
var WithAuthCodeOptions = provideropts.WithAuthCodeOptions

type Provider struct {
	config          *oauth2.Config
	userInfoURL     string
	httpClient      *http.Client
	authCodeOptions []oauth2.AuthCodeOption
}

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

func (p *Provider) Name() string { return "github" }

func (p *Provider) BeginAuth(state string) (string, error) {
	return p.config.AuthCodeURL(state, p.authCodeOptions...), nil
}

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

	email := maputil.GetString(raw, "email")
	if email == "" {
		email, err = fetchPrimaryEmail(p.config.Client(r.Context(), token))
		if err != nil {
			return goauth.AuthResult{}, err
		}
	}

	id := maputil.GetID(raw, "id")
	if id == "" {
		return goauth.AuthResult{}, goauth.ErrMissingUserID
	}

	return goauth.AuthResult{
		User: goauth.User{
			ID:        id,
			Email:     email,
			Username:  maputil.GetString(raw, "login"),
			Name:      maputil.GetString(raw, "name"),
			AvatarURL: maputil.GetString(raw, "avatar_url"),
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

func fetchPrimaryEmail(client *http.Client) (string, error) {
	res, err := client.Get(userEmailURL)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", fmt.Errorf("emails request failed with status %d", res.StatusCode)
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}

	if err := json.NewDecoder(res.Body).Decode(&emails); err != nil {
		return "", err
	}

	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}

	return "", nil
}
