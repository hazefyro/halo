package session

import (
	"fmt"
	"net/http"
)

type Manager struct {
	store Store
	cfg   Config
}

func New(store Store, opts ...Option) (*Manager, error) {
	if store == nil {
		return nil, ErrNilStore
	}

	c := applyOptions(opts)

	if err := c.validate(); err != nil {
		return nil, err
	}

	return &Manager{
		store: store,
		cfg:   c,
	}, nil
}

func (m *Manager) LoadFromRequest(r *http.Request) (*Session, error) {
	c, err := r.Cookie(m.cfg.CookieName)
	if err != nil {
		return nil, ErrSessionNotFound
	}

	s, err := m.store.Get(r.Context(), SessionID(c.Value))
	if err != nil {
		return nil, fmt.Errorf("session: get failed: %w", err)
	}

	if s.isExpired(m.cfg.Now()) {
		return nil, ErrSessionExpired
	}

	return s, nil
}

func (m *Manager) SaveToResponse(w http.ResponseWriter, s *Session) error {
	v, err := m.store.Encode(s)
	if err != nil {
		return fmt.Errorf("session: save failed: %w", err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     m.cfg.CookieName,
		Value:    v,
		Path:     m.cfg.Path,
		MaxAge:   int(m.store.TTL().Seconds()),
		Secure:   m.cfg.Secure,
		HttpOnly: m.cfg.HttpOnly,
		SameSite: m.cfg.SameSite,
	})

	return nil
}

func (m *Manager) DeleteFromResponse(w http.ResponseWriter, r *http.Request) error {
	c, err := r.Cookie(m.cfg.CookieName)
	if err != nil {
		return nil
	}

	if err := m.store.Delete(r.Context(), SessionID(c.Value)); err != nil {
		return fmt.Errorf("session: delete failed: %w", err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     m.cfg.CookieName,
		Value:    "",
		Path:     m.cfg.Path,
		MaxAge:   -1,
		Secure:   m.cfg.Secure,
		HttpOnly: m.cfg.HttpOnly,
		SameSite: m.cfg.SameSite,
	})

	return nil
}
