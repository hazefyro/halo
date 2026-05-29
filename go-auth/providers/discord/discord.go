package discord

import (
	"context"
	"fmt"
	"net/http"

	goauth "github.com/haze/go-auth"
	"github.com/haze/go-auth/internal/maputil"
	"github.com/haze/go-auth/internal/oauthutil"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

const userInfoURL = "https://discord.com/api/users/@me"

type Provider struct {
	config          *oauth2.Config
	userInfoURL     string
	authCodeOptions []oauth2.AuthCodeOption
}

type Option func(*Provider)

func WithScopes(scopes ...string) Option {
	return func(p *Provider) { p.config.Scopes = scopes }
}

func WithAuthCodeOptions(opts ...oauth2.AuthCodeOption) Option {
	return func(p *Provider) { p.authCodeOptions = append(p.authCodeOptions, opts...) }
}

func New(clientID, clientSecret, redirectURL string, opts ...Option) *Provider {
	p := &Provider{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"identify", "email"},
			Endpoint:     endpoints.Discord,
		},
		userInfoURL: userInfoURL,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func (p *Provider) Name() string { return "discord" }

func (p *Provider) BeginAuth(state string) (string, error) {
	return p.config.AuthCodeURL(state, p.authCodeOptions...), nil
}

func (p *Provider) CompleteAuth(r *http.Request) (goauth.User, goauth.Credentials, error) {
	code := r.URL.Query().Get("code")
	if code == "" {
		return goauth.User{}, goauth.Credentials{}, goauth.ErrMissingCode
	}

	raw, token, err := oauthutil.FetchUserInfo(r.Context(), p.config, code, p.userInfoURL)
	if err != nil {
		return goauth.User{}, goauth.Credentials{}, err
	}

	id := maputil.GetID(raw, "id")
	avatarHash := maputil.GetString(raw, "avatar")
	avatarURL := ""
	if avatarHash != "" {
		avatarURL = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", id, avatarHash)
	}

	user := goauth.User{
		ID:        id,
		Email:     maputil.GetString(raw, "email"),
		Username:  maputil.GetString(raw, "username"),
		Name:      maputil.GetString(raw, "global_name"),
		AvatarURL: avatarURL,
		Provider:  p.Name(),
	}
	creds := goauth.Credentials{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    token.Expiry,
		RawData:      raw,
	}
	return user, creds, nil
}

func (p *Provider) RefreshToken(ctx context.Context, refreshToken string) (goauth.Token, error) {
	return oauthutil.RefreshToken(ctx, p.config, refreshToken)
}
