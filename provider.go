package auth

import (
	"context"
	"net/http"
)

// Provider describes an OAuth provider implementation.
type Provider interface {
	// Name returns the provider name used for registration and callback routing.
	Name() string
	// BeginAuth returns the provider authorization URL for a generated state.
	BeginAuth(state string) (string, error)
	// CompleteAuth exchanges the callback request for identity and credentials.
	CompleteAuth(r *http.Request) (AuthResult, error)
}

// TokenRefresher is an optional capability a Provider may implement.
// Use a type assertion to check: tr, ok := p.(goauth.TokenRefresher)
type TokenRefresher interface {
	RefreshToken(ctx context.Context, token string) (Credentials, error)
}
