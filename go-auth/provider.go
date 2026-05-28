package goauth

import "net/http"

type Provider interface {
	Name() string
	BeginAuth(state string) (string, error)     // returns redirect URL
	CompleteAuth(r *http.Request) (User, error) // exchanges code for user
	RefreshToken(token string) (Token, error)
}
