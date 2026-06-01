package oauthutil

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/hazefyro/halo/oauth"
	"golang.org/x/oauth2"
)

const maxBodyBytes = 1 << 20 // 1 MB

// RefreshToken refreshes OAuth credentials with a refresh token.
func RefreshToken(ctx context.Context, config *oauth2.Config, refreshToken string) (oauth.Credentials, error) {
	token, err := config.TokenSource(ctx, &oauth2.Token{
		RefreshToken: refreshToken,
	}).Token()
	if err != nil {
		return oauth.Credentials{}, err
	}
	newRefresh := token.RefreshToken
	if newRefresh == "" {
		newRefresh = refreshToken
	}
	return oauth.Credentials{
		AccessToken:  token.AccessToken,
		RefreshToken: newRefresh,
		ExpiresAt:    token.Expiry,
	}, nil
}

// FetchUserInfo exchanges an auth code and fetches provider userinfo JSON.
// exchangeOpts are passed to the token exchange (e.g. a PKCE code verifier).
func FetchUserInfo(ctx context.Context, config *oauth2.Config, code, url string, exchangeOpts ...oauth2.AuthCodeOption) (map[string]any, *oauth2.Token, error) {
	token, err := config.Exchange(ctx, code, exchangeOpts...)
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
