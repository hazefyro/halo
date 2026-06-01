package oauth

import (
	"context"
	"errors"
)

type resultKey struct{}

func storeResultInContext(ctx context.Context, result AuthResult) context.Context {
	return context.WithValue(ctx, resultKey{}, result)
}

func resultFromContext(ctx context.Context) (AuthResult, bool) {
	r, ok := ctx.Value(resultKey{}).(AuthResult)
	return r, ok
}

// CredentialsFromContext returns the OAuth credentials stored by [Registry.Callback].
func CredentialsFromContext(ctx context.Context) (Credentials, error) {
	r, ok := resultFromContext(ctx)
	if !ok || r.Credentials.AccessToken == "" {
		return Credentials{}, errors.New("oauth: no credentials in context")
	}
	return r.Credentials, nil
}

// RawDataFromContext returns the provider's raw userinfo stored by [Registry.Callback].
func RawDataFromContext(ctx context.Context) (RawData, error) {
	r, ok := resultFromContext(ctx)
	if !ok || r.RawData == nil {
		return nil, errors.New("oauth: no raw data in context")
	}
	return r.RawData, nil
}
