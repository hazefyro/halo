package session

import (
	"context"
	"net/http"
)

type sessionKey struct{}

// FromContext returns the session that [Manager.RequireAuth] loaded for the
// request, if the request passed through that middleware.
func FromContext(ctx context.Context) (*Session, bool) {
	s, ok := ctx.Value(sessionKey{}).(*Session)
	return s, ok
}

// authConfig is the per-middleware configuration assembled from AuthOptions.
type authConfig struct {
	unauthorized  http.Handler
	slidingExpiry bool
}

// AuthOption configures the [Manager.RequireAuth] middleware.
type AuthOption func(*authConfig)

// WithUnauthorized sets the handler invoked when a request carries no valid
// session, replacing the default 401 response. Use it for custom error pages,
// JSON error bodies, or any other unauthenticated behavior.
func WithUnauthorized(h http.Handler) AuthOption {
	return func(c *authConfig) { c.unauthorized = h }
}

// WithLoginRedirect responds to unauthenticated requests with a 303 redirect to
// loginURL. It is a convenience wrapper over [WithUnauthorized].
func WithLoginRedirect(loginURL string) AuthOption {
	return WithUnauthorized(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, loginURL, http.StatusSeeOther)
	}))
}

// WithSlidingExpiry extends the session and refreshes its cookie on every
// authenticated request. The refresh is best-effort: if it fails the request
// still proceeds, since the session was already valid.
func WithSlidingExpiry() AuthOption {
	return func(c *authConfig) { c.slidingExpiry = true }
}

// RequireAuth returns middleware that admits only requests carrying a valid
// session. On success the loaded *Session is placed in the request context for
// downstream handlers to read with [FromContext]. Requests without a valid
// session are handed to the configured unauthorized handler — a 401 by default,
// or whatever [WithUnauthorized] / [WithLoginRedirect] specify.
//
// The middleware deals only in sessions and never in identities, so it gates
// routes regardless of how the user originally logged in.
func (m *Manager) RequireAuth(opts ...AuthOption) func(http.Handler) http.Handler {
	cfg := authConfig{
		unauthorized: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}),
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, err := m.Load(r)
			if err != nil {
				cfg.unauthorized.ServeHTTP(w, r)
				return
			}

			if cfg.slidingExpiry {
				_ = m.refresh(w, r, sess)
			}

			ctx := context.WithValue(r.Context(), sessionKey{}, sess)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
