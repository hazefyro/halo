package goauth

import (
	"context"
	"net/http"
)

type Provider interface {
	Name() string
	BeginAuth(state string) (string, error)     // returns redirect URL
	CompleteAuth(r *http.Request) (User, Credentials, map[string]any, error) // exchanges code for user
	RefreshToken(ctx context.Context, token string) (Token, error)
}
