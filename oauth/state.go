package oauth

import (
	"errors"
	"net/http"

	"github.com/hazefyro/auth/oauth/internal/hmacutil"
)

// StateStore stores and verifies OAuth state values.
type StateStore interface {
	// Store persists a state value for a provider.
	Store(w http.ResponseWriter, r *http.Request, state, provider string) error
	// Verify checks a callback state value for a provider.
	Verify(r *http.Request, state, provider string) error
	// Clear removes a stored provider state value.
	Clear(w http.ResponseWriter, provider string)
}

// CookieStateStore stores signed OAuth state values in HTTP cookies.
type CookieStateStore struct {
	secret []byte
	secure bool
}

// CookieOption configures a CookieStateStore.
type CookieOption func(*CookieStateStore)

// WithSecure sets the Secure flag on the state cookie (default true).
func WithSecure(secure bool) CookieOption {
	return func(s *CookieStateStore) { s.secure = secure }
}

// NewCookieStateStore creates a cookie-backed state store with Secure cookies
// by default.
func NewCookieStateStore(secret string, opts ...CookieOption) (*CookieStateStore, error) {
	if len(secret) < 32 {
		return nil, errors.New("oauth: CookieStateStore secret must be at least 32 bytes")
	}
	s := &CookieStateStore{secret: []byte(secret), secure: true}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

func (s *CookieStateStore) cookieName(provider string) string {
	return "goauth_state_" + provider
}

// Store writes a signed state cookie for a provider.
func (s *CookieStateStore) Store(w http.ResponseWriter, r *http.Request, state, provider string) error {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(provider),
		Value:    hmacutil.Sign(s.secret, state),
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})
	return nil
}

// Verify checks a signed state cookie for a provider.
func (s *CookieStateStore) Verify(r *http.Request, state, provider string) error {
	cookie, err := r.Cookie(s.cookieName(provider))
	if err != nil {
		return ErrStateMismatch
	}
	if !hmacutil.Verify(s.secret, state, cookie.Value) {
		return ErrStateMismatch
	}
	return nil
}

// Clear expires the state cookie for a provider.
func (s *CookieStateStore) Clear(w http.ResponseWriter, provider string) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(provider),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}
