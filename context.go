package auth

import (
	"context"
	"errors"
	"net/http"
)

type identityKey struct{}

// StoreIdentityInContext returns a copy of ctx carrying the given identity.
// Login methods call this once authentication succeeds; downstream handlers
// read it back with [IdentityFromContext].
func StoreIdentityInContext(ctx context.Context, identity Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, identity)
}

// IdentityFromContext returns the authenticated identity stored in ctx.
func IdentityFromContext(ctx context.Context) (Identity, error) {
	id, ok := ctx.Value(identityKey{}).(Identity)
	if !ok {
		return Identity{}, errors.New("auth: no identity in context")
	}
	return id, nil
}

// ProviderFromContext returns the name of the login method that authenticated
// the request, or "" if the request is unauthenticated.
func ProviderFromContext(ctx context.Context) string {
	id, _ := ctx.Value(identityKey{}).(Identity)
	return id.Provider
}

// AuthRequired returns middleware that rejects requests that carry no identity.
func AuthRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, err := IdentityFromContext(req.Context()); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, req)
	})
}
