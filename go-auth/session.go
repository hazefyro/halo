package goauth

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type SessionStore interface {
	Save(w http.ResponseWriter, user User) error
	Get(r *http.Request) (User, bool)
	Delete(w http.ResponseWriter, r *http.Request) error
}

type CookieSessionStore struct {
	secret     []byte
	secure     bool
	cookieName string
	maxAge     int
}

type CookieSessionOption func(*CookieSessionStore)

func WithSessionCookieName(name string) CookieSessionOption {
	return func(s *CookieSessionStore) { s.cookieName = name }
}

func WithSessionMaxAge(seconds int) CookieSessionOption {
	return func(s *CookieSessionStore) { s.maxAge = seconds }
}

func WithSessionSecure(secure bool) CookieSessionOption {
	return func(s *CookieSessionStore) { s.secure = secure }
}

func NewCookieSessionStore(secret string, opts ...CookieSessionOption) *CookieSessionStore {
	if secret == "" {
		panic("goauth: CookieSessionStore secret must not be empty")
	}
	s := &CookieSessionStore{
		secret:     []byte(secret),
		cookieName: "goauth_session",
		secure:     true,
		maxAge:     86400,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func NewInsecureCookieSessionStore(secret string, opts ...CookieSessionOption) *CookieSessionStore {
	if secret == "" {
		panic("goauth: CookieSessionStore secret must not be empty")
	}
	s := &CookieSessionStore{
		secret:     []byte(secret),
		cookieName: "goauth_session",
		secure:     false,
		maxAge:     86400,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

type sessionClaims struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	Username  string `json:"username"`
	AvatarURL string `json:"avatar"`
	Provider  string `json:"provider"`
	jwt.RegisteredClaims
}

func (s *CookieSessionStore) Save(w http.ResponseWriter, user User) error {
	claims := sessionClaims{
		ID:        user.ID,
		Email:     user.Email,
		Name:      user.Name,
		Username:  user.Username,
		AvatarURL: user.AvatarURL,
		Provider:  user.Provider,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(s.maxAge) * time.Second)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(s.secret)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    signed,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   s.maxAge,
	})
	return nil
}

func (s *CookieSessionStore) parseClaims(r *http.Request) (*sessionClaims, bool) {
	cookie, err := r.Cookie(s.cookieName)
	if err != nil {
		return nil, false
	}
	claims := &sessionClaims{}
	token, err := jwt.ParseWithClaims(cookie.Value, claims, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, jwt.ErrSignatureInvalid
		}
		return s.secret, nil
	})
	if err != nil || !token.Valid {
		return nil, false
	}
	return claims, true
}

func userFromClaims(c *sessionClaims) User {
	return User{
		ID:        c.ID,
		Email:     c.Email,
		Name:      c.Name,
		Username:  c.Username,
		AvatarURL: c.AvatarURL,
		Provider:  c.Provider,
	}
}

func (s *CookieSessionStore) Get(r *http.Request) (User, bool) {
	claims, ok := s.parseClaims(r)
	if !ok {
		return User{}, false
	}
	return userFromClaims(claims), true
}

func (s *CookieSessionStore) GetWithExpiry(r *http.Request) (User, time.Time, bool) {
	claims, ok := s.parseClaims(r)
	if !ok {
		return User{}, time.Time{}, false
	}
	return userFromClaims(claims), claims.ExpiresAt.Time, true
}

func (s *CookieSessionStore) Delete(w http.ResponseWriter, r *http.Request) error {
	http.SetCookie(w, &http.Cookie{
		Name:   s.cookieName,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	return nil
}
