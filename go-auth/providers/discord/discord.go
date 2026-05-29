package discord

import (
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
	config      *oauth2.Config
	userInfoURL string
}

func New(clientID, clientSecret, redirectURL string) *Provider {
	return &Provider{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"identify", "email"},
			Endpoint:     endpoints.Discord,
		},
		userInfoURL: userInfoURL,
	}
}

func (p *Provider) Name() string { return "discord" }

func (p *Provider) BeginAuth(state string) (string, error) {
	return p.config.AuthCodeURL(state), nil
}

func (p *Provider) CompleteAuth(r *http.Request) (goauth.User, error) {
	code := r.URL.Query().Get("code")
	if code == "" {
		return goauth.User{}, goauth.ErrMissingCode
	}

	raw, token, err := oauthutil.FetchUserInfo(r.Context(), p.config, code, p.userInfoURL)
	if err != nil {
		return goauth.User{}, err
	}

	id := maputil.GetID(raw, "id")
	avatarHash := maputil.GetString(raw, "avatar")
	avatarURL := ""
	if avatarHash != "" {
		avatarURL = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", id, avatarHash)
	}

	return goauth.User{
		ID:           id,
		Email:        maputil.GetString(raw, "email"),
		Username:     maputil.GetString(raw, "username"),
		Name:         maputil.GetString(raw, "global_name"),
		AvatarURL:    avatarURL,
		Provider:     p.Name(),
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    token.Expiry,
		RawData:      raw,
	}, nil

}

func (p *Provider) RefreshToken(refreshToken string) (goauth.Token, error) {
	return oauthutil.RefreshToken(p.config, refreshToken)
}
