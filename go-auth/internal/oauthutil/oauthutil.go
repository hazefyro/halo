package oauthutil

import (
	"context"

	goauth "github.com/haze/go-auth"
	"golang.org/x/oauth2"
)

func RefreshToken(config *oauth2.Config, refreshToken string) (goauth.Token, error) {
	token, err := config.TokenSource(context.Background(), &oauth2.Token{
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
