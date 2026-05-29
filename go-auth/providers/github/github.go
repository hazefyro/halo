package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	goauth "github.com/haze/go-auth"
	"github.com/haze/go-auth/internal/maputil"
	"github.com/haze/go-auth/internal/oauthutil"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

const userInfoURL = "https://api.github.com/user"
const userEmailURL = "https://api.github.com/user/emails"

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
			Scopes:       []string{"read:user", "user:email"},
			Endpoint:     github.Endpoint,
		},
		userInfoURL: userInfoURL,
	}
}

func (p *Provider) Name() string { return "github" }

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

	email := maputil.GetString(raw, "email")
	if email == "" {
		email, err = fetchPrimaryEmail(p.config.Client(r.Context(), token))
		if err != nil {
			return goauth.User{}, err
		}
	}

	return goauth.User{
		ID:           maputil.GetID(raw, "id"),
		Email:        email,
		Username:     maputil.GetString(raw, "login"),
		Name:         maputil.GetString(raw, "name"),
		AvatarURL:    maputil.GetString(raw, "avatar_url"),
		Provider:     p.Name(),
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    token.Expiry,
		RawData:      raw,
	}, nil

}

func (p *Provider) RefreshToken(ctx context.Context, refreshToken string) (goauth.Token, error) {
	return oauthutil.RefreshToken(ctx, p.config, refreshToken)
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
