package goauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"

	"github.com/haze/go-auth/internal/randstate"
)

type StateStore interface {
	Generate(w http.ResponseWriter, r *http.Request) (string, error)
	Verify(r *http.Request, state string) error
	Clear(w http.ResponseWriter)
}

type CookieStateStore struct {
	secret []byte
}

func NewCookieStateStore(secret string) *CookieStateStore {
	return &CookieStateStore{secret: []byte(secret)}
}

func (s *CookieStateStore) Generate(w http.ResponseWriter, r *http.Request) (string, error) {
	state, err := randstate.RandomState()
	if err != nil {
		return "", err
	}

	signed := s.sign(state)

	http.SetCookie(w, &http.Cookie{
		Name:     "goauth_state",
		Value:    signed,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	return state, nil
}
func (s *CookieStateStore) Verify(r *http.Request, state string) error {
	cookie, err := r.Cookie("goauth_state")
	if err != nil {
		return ErrStateMismatch
	}
	if cookie.Value != s.sign(state) {
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

func (s *CookieStateStore) sign(state string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(state))
	return hex.EncodeToString(mac.Sum(nil))
}
