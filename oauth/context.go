package oauth

import (
	"context"
	"errors"
)

type tokensKey struct{}

// oauthData is the OAuth-specific part of a completed callback that rides in the
// request context. Identity is deliberately absent — it lives under the root
// auth package's key via [auth.StoreIdentityInContext].
type oauthData struct {
	Credentials Credentials
	RawData     RawData
}

func storeTokensInContext(ctx context.Context, d oauthData) context.Context {
	return context.WithValue(ctx, tokensKey{}, d)
}

func tokensFromContext(ctx context.Context) (oauthData, bool) {
	d, ok := ctx.Value(tokensKey{}).(oauthData)
	return d, ok
}

// CredentialsFromContext returns the OAuth credentials stored by [Registry.Callback].
func CredentialsFromContext(ctx context.Context) (Credentials, error) {
	d, ok := tokensFromContext(ctx)
	if !ok || d.Credentials.AccessToken == "" {
		return Credentials{}, errors.New("oauth: no credentials in context")
	}
	return d.Credentials, nil
}

// RawDataFromContext returns the provider's raw userinfo stored by [Registry.Callback].
func RawDataFromContext(ctx context.Context) (RawData, error) {
	d, ok := tokensFromContext(ctx)
	if !ok || d.RawData == nil {
		return nil, errors.New("oauth: no raw data in context")
	}
	return d.RawData, nil
}
