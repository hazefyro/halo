package oauth

import (
	"context"
	"net/http"
)

// Provider describes an OAuth provider implementation.
type Provider interface {
	// Name returns the provider name used for registration and callback routing.
	Name() string
	// BeginAuth returns the provider authorization URL for a generated state.
	// A non-empty verifier adds a PKCE S256 code challenge to the URL.
	BeginAuth(state, verifier string) (string, error)
	// CompleteAuth exchanges the callback request for identity and credentials.
	// A non-empty verifier is sent as the PKCE code_verifier on the exchange.
	CompleteAuth(r *http.Request, verifier string) (AuthResult, error)
}

// TokenRefresher is an optional capability a Provider may implement.
// Use a type assertion to check: tr, ok := p.(goauth.TokenRefresher)
type TokenRefresher interface {
	RefreshToken(ctx context.Context, token string) (Credentials, error)
}
