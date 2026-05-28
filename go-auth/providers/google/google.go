package google

import (
	"encoding/json"
	"net/http"

	goauth "github.com/haze/go-auth"
	"github.com/haze/go-auth/internal/maputil"
	oauthsutil "github.com/haze/go-auth/internal/oauthutil"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const userInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"

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
			Scopes:       []string{"openid", "email", "profile"},
			Endpoint:     google.Endpoint,
		},
		userInfoURL: userInfoURL,
	}
}

func (p *Provider) Name() string { return "google" }

func (p *Provider) BeginAuth(state string) (string, error) {
	return p.config.AuthCodeURL(state, oauth2.AccessTypeOffline), nil
}

func (p *Provider) CompleteAuth(r *http.Request) (goauth.User, error) {
	code := r.URL.Query().Get("code")
	if code == "" {
		return goauth.User{}, goauth.ErrMissingCode
	}

	token, err := p.config.Exchange(r.Context(), code)

	if err != nil {
		return goauth.User{}, err
	}

	client := p.config.Client(r.Context(), token)
	res, err := client.Get(p.userInfoURL)
	if err != nil {
		return goauth.User{}, err
	}

	defer res.Body.Close()

	var raw map[string]any
	if err := json.NewDecoder(res.Body).Decode(&raw); err != nil {
		return goauth.User{}, err
	}

	return goauth.User{
		ID:           maputil.GetString(raw, "sub"),
		Email:        maputil.GetString(raw, "email"),
		Name:         maputil.GetString(raw, "name"),
		AvatarURL:    maputil.GetString(raw, "picture"),
		Provider:     p.Name(),
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    token.Expiry,
		RawData:      raw,
	}, nil
}

func (p *Provider) RefreshToken(refreshToken string) (goauth.Token, error) {
	return oauthsutil.RefreshToken(p.config, refreshToken)
}
