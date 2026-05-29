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

const userInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"

type Option = provideropts.Option

var WithScopes = provideropts.WithScopes
var WithAdditionalScopes = provideropts.WithAdditionalScopes
var WithAuthCodeOptions = provideropts.WithAuthCodeOptions

type Provider struct {
	config          *oauth2.Config
	userInfoURL     string
	authCodeOptions []oauth2.AuthCodeOption
}

func New(clientID, clientSecret, redirectURL string, opts ...Option) *Provider {
	cfg := provideropts.Apply(opts)
	scopes := []string{"openid", "email", "profile"}
	if len(cfg.Scopes) > 0 {
		scopes = cfg.Scopes
	} else {
		scopes = append(scopes, cfg.AdditionalScopes...)
	}
	return &Provider{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       scopes,
			Endpoint:     google.Endpoint,
		},
		userInfoURL:     userInfoURL,
		authCodeOptions: cfg.AuthCodeOptions,
	}
}

func (p *Provider) Name() string { return "google" }

func (p *Provider) BeginAuth(state string) (string, error) {
	opts := append([]oauth2.AuthCodeOption{oauth2.AccessTypeOffline}, p.authCodeOptions...)
	return p.config.AuthCodeURL(state, opts...), nil
}

func (p *Provider) CompleteAuth(r *http.Request) (goauth.User, goauth.Credentials, goauth.RawData, error) {
	code := r.URL.Query().Get("code")
	if code == "" {
		return goauth.User{}, goauth.Credentials{}, nil, goauth.ErrMissingCode
	}

	raw, token, err := oauthutil.FetchUserInfo(r.Context(), p.config, code, p.userInfoURL)
	if err != nil {
		return goauth.User{}, goauth.Credentials{}, nil, err
	}

	user := goauth.User{
		ID:        maputil.GetID(raw, "sub"),
		Email:     maputil.GetString(raw, "email"),
		Name:      maputil.GetString(raw, "name"),
		AvatarURL: maputil.GetString(raw, "picture"),
		Provider:  p.Name(),
	}
	creds := goauth.Credentials{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    token.Expiry,
	}
	return user, creds, raw, nil
}

func (p *Provider) RefreshToken(ctx context.Context, refreshToken string) (goauth.Token, error) {
	return oauthutil.RefreshToken(ctx, p.config, refreshToken)
}
