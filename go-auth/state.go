package goauth

import (
	"net/http"

	"github.com/haze/go-auth/internal/hmacutil"
	"github.com/haze/go-auth/internal/randstate"
)

type StateStore interface {
	Generate(w http.ResponseWriter, r *http.Request) (string, error)
	Verify(r *http.Request, state string) error
	Clear(w http.ResponseWriter)
}

type CookieStateStore struct {
	secret []byte
	secure bool
}

type CookieStateOption func(*CookieStateStore)

func NewCookieStateStore(secret string) *CookieStateStore {
	if secret == "" {
		panic("goauth: CookieStateStore secret must not be empty")
	}
	return &CookieStateStore{secret: []byte(secret), secure: true}
}

func NewInsecureCookieStateStore(secret string) *CookieStateStore {
	if secret == "" {
		panic("goauth: CookieStateStore secret must not be empty")
	}
	return &CookieStateStore{secret: []byte(secret), secure: false}
}

func (s *CookieStateStore) Generate(w http.ResponseWriter, r *http.Request) (string, error) {
	state, err := randstate.RandomState()
	if err != nil {
		return "", err
	}

	signed := hmacutil.Sign(s.secret, state)

	http.SetCookie(w, &http.Cookie{
		Name:     "goauth_state",
		Value:    signed,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
	})

	return state, nil
}
func (s *CookieStateStore) Verify(r *http.Request, state string) error {
	cookie, err := r.Cookie("goauth_state")
	if err != nil {
		return ErrStateMismatch
	}
	if !hmacutil.Verify(s.secret, state, cookie.Value) {
		return ErrStateMismatch
	}

	return nil
}

func (s *CookieStateStore) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "goauth_state",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}
