package goauth

import (
	"context"
	"net/http"
)

type Provider interface {
	Name() string
	BeginAuth(state string) (string, error)
	CompleteAuth(r *http.Request) (AuthResult, error)
}

// TokenRefresher is an optional capability a Provider may implement.
// Use a type assertion to check: tr, ok := p.(goauth.TokenRefresher)
type TokenRefresher interface {
	RefreshToken(ctx context.Context, token string) (Token, error)
}
