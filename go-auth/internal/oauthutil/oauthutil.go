package oauthutil

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	goauth "github.com/haze/go-auth"
	"golang.org/x/oauth2"
)

const maxBodyBytes = 1 << 20 // 1 MB

func RefreshToken(ctx context.Context, config *oauth2.Config, refreshToken string) (goauth.Credentials, error) {
	token, err := config.TokenSource(ctx, &oauth2.Token{
		RefreshToken: refreshToken,
	}).Token()
	if err != nil {
		return goauth.Credentials{}, err
	}
	newRefresh := token.RefreshToken
	if newRefresh == "" {
		newRefresh = refreshToken
	}
	return goauth.Credentials{
		AccessToken:  token.AccessToken,
		RefreshToken: newRefresh,
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

	dec := json.NewDecoder(io.LimitReader(res.Body, maxBodyBytes))
	dec.UseNumber()
	var raw map[string]any
	if err := dec.Decode(&raw); err != nil {
		return nil, nil, err
	}

	return raw, token, nil
}
