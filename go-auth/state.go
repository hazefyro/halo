package goauth

import (
	"errors"
	"net/http"

	"github.com/haze/go-auth/internal/hmacutil"
	"github.com/haze/go-auth/internal/randstate"
)

type StateStore interface {
	Generate(w http.ResponseWriter, r *http.Request, provider string) (string, error)
	Verify(r *http.Request, state, provider string) error
	Clear(w http.ResponseWriter, provider string)
}

type CookieStateStore struct {
	secret []byte
	secure bool
}

func NewCookieStateStore(secret string) (*CookieStateStore, error) {
	if len(secret) < 32 {
		return nil, errors.New("goauth: CookieStateStore secret must be at least 32 bytes")
	}
	return &CookieStateStore{secret: []byte(secret), secure: true}, nil
}

func NewInsecureCookieStateStore(secret string) (*CookieStateStore, error) {
	if len(secret) < 32 {
		return nil, errors.New("goauth: CookieStateStore secret must be at least 32 bytes")
	}
	return &CookieStateStore{secret: []byte(secret), secure: false}, nil
}

func (s *CookieStateStore) cookieName(provider string) string {
	return "goauth_state_" + provider
}

func (s *CookieStateStore) Generate(w http.ResponseWriter, r *http.Request, provider string) (string, error) {
	state, err := randstate.RandomState()
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(provider),
		Value:    hmacutil.Sign(s.secret, state),
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})
	return state, nil
}

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
