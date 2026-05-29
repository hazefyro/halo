package oauthutil

import (
	"context"
	"encoding/json"
	"fmt"

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

func FetchUserInfo(ctx context.Context, config *oauth2.Config, code, url string) (map[string]any, *oauth2.Token, error) {
	token, err := config.Exchange(ctx, code)
	if err != nil {
		return nil, nil, err
	}

	client := config.Client(ctx, token)
	res, err := client.Get(url)
	if err != nil {
		return nil, nil, err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("userinfo request failed with status %d", res.StatusCode)
	}

	var raw map[string]any
	if err := json.NewDecoder(res.Body).Decode(&raw); err != nil {
		return nil, nil, err
	}

	return raw, token, nil
}
