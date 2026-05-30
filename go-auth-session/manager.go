package session

import (
	"context"
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

func (m *Manager) Create(ctx context.Context, w http.ResponseWriter, userID string) (*Session, error) {
	sess := &Session{
		ID:         SessionID(generateID()),
		UserID:     userID,
		CreatedAt:  m.cfg.Now(),
		ExpiresAt:  m.cfg.Now().Add(m.store.TTL()),
		LastSeenAt: m.cfg.Now(),
	}
	if err := m.store.Save(ctx, sess); err != nil {
		return nil, fmt.Errorf("session: create failed: %w", err)
	}
	v, err := m.store.Encode(sess)
	if err != nil {
		return nil, fmt.Errorf("session: create failed: %w", err)
	}
	m.setCookie(w, v)
	return sess, nil
}

func (m *Manager) Load(r *http.Request) (*Session, error) {
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

func (m *Manager) Touch(w http.ResponseWriter, r *http.Request) error {
	s, err := m.Load(r)
	if err != nil {
		return err
	}

	c, err := r.Cookie(m.cfg.CookieName)
	if err != nil {
		return ErrSessionNotFound
	}

	if err := m.store.Touch(r.Context(), s, m.cfg.Now()); err != nil {
		return fmt.Errorf("session: touch failed: %w", err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     m.cfg.CookieName,
		Value:    c.Value,
		Path:     m.cfg.Path,
		MaxAge:   int(m.store.TTL().Seconds()),
		Secure:   m.cfg.Secure,
		HttpOnly: m.cfg.HttpOnly,
		SameSite: m.cfg.SameSite,
	})
	return nil
}

func (m *Manager) Delete(w http.ResponseWriter, r *http.Request) error {
	c, err := r.Cookie(m.cfg.CookieName)
	if err != nil {
		return nil
	}

	if err := m.store.Delete(r.Context(), SessionID(c.Value)); err != nil {
		return fmt.Errorf("session: delete failed: %w", err)
	}

	m.clearCookie(w)

	return nil
}

func (m *Manager) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.cfg.CookieName,
		Value:    "",
		Path:     m.cfg.Path,
		MaxAge:   -1,
		Secure:   m.cfg.Secure,
		HttpOnly: m.cfg.HttpOnly,
		SameSite: m.cfg.SameSite,
	})
}

func (m *Manager) setCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.cfg.CookieName,
		Value:    value,
		Path:     m.cfg.Path,
		MaxAge:   int(m.store.TTL().Seconds()),
		Secure:   m.cfg.Secure,
		HttpOnly: m.cfg.HttpOnly,
		SameSite: m.cfg.SameSite,
	})
}
