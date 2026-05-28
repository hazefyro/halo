package google

import (
	"context"
	"encoding/json"
	"net/http"

	goauth "github.com/haze/go-auth"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

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
		userInfoURL: "https://openidconnect.googleapis.com/v1/userinfo",
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

	getString := func(key string) string {
		if v, ok := raw[key].(string); ok {
			return v
		}
		return ""
	}

	return goauth.User{
		ID:           getString("sub"),
		Email:        getString("email"),
		Name:         getString("name"),
		AvatarURL:    getString("picture"),
		Provider:     p.Name(),
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    token.Expiry,
		RawData:      raw,
	}, nil
}

func (p *Provider) RefreshToken(refreshToken string) (goauth.Token, error) {
	token, err := p.config.TokenSource(context.Background(), &oauth2.Token{
		RefreshToken: refreshToken,
	}).Token()
	if err != nil {
		return goauth.Token{}, err
	}
	return goauth.Token{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    token.Expiry,
	}, nil
}
