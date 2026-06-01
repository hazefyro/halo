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
	return m.refresh(w, r, s)
}

// refresh extends an already-loaded session in the store and rewrites its
// cookie. Callers that have just loaded the session (such as RequireAuth) use
// this to avoid a redundant store read.
//
// The cookie is re-encoded from the touched session rather than reused: a
// stateless store carries its expiry inside the cookie value, so reusing the
// old value would leave the embedded expiry unchanged and make sliding expiry
// a silent no-op. Opaque-ID stores simply re-emit the same identifier.
func (m *Manager) refresh(w http.ResponseWriter, r *http.Request, s *Session) error {
	if err := m.store.Touch(r.Context(), s, m.cfg.Now()); err != nil {
		return fmt.Errorf("session: touch failed: %w", err)
	}

	value, err := m.store.Encode(s)
	if err != nil {
		return fmt.Errorf("session: touch failed: %w", err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     m.cfg.CookieName,
		Value:    value,
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
