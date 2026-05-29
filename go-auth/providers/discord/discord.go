package discord

import (
	"context"
	"fmt"
	"net/http"

	goauth "github.com/haze/go-auth"
	"github.com/haze/go-auth/internal/maputil"
	"github.com/haze/go-auth/internal/oauthutil"
	"github.com/haze/go-auth/internal/provideropts"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

var WithHTTPClient = provideropts.WithHTTPClient
var WithUserInfoURL = provideropts.WithUserInfoURL
var WithEndpoint = provideropts.WithEndpoint

const userInfoURL = "https://discord.com/api/users/@me"

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

func (p *Provider) Name() string { return "discord" }

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

	id := maputil.GetID(raw, "id")
	if id == "" {
		return goauth.AuthResult{}, goauth.ErrMissingUserID
	}

	avatarHash := maputil.GetString(raw, "avatar")
	avatarURL := ""
	if avatarHash != "" {
		avatarURL = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", id, avatarHash)
	}

	return goauth.AuthResult{
		User: goauth.User{
			ID:        id,
			Email:     maputil.GetString(raw, "email"),
			Username:  maputil.GetString(raw, "username"),
			Name:      maputil.GetString(raw, "global_name"),
			AvatarURL: avatarURL,
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

func (p *Provider) RefreshToken(ctx context.Context, refreshToken string) (goauth.Token, error) {
	if p.httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)
	}
	return oauthutil.RefreshToken(ctx, p.config, refreshToken)
}
