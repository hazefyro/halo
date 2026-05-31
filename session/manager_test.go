package session_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hazefyro/auth/session"
)

type fakeStore struct {
	saved      *session.Session
	gotID      session.SessionID
	touched    *session.Session
	touchedAt  time.Time
	deletedID  session.SessionID
	encoded    string
	ttl        time.Duration
	getSession *session.Session
	saveErr    error
	getErr     error
	touchErr   error
	deleteErr  error
	encodeErr  error
}

func (s *fakeStore) Save(ctx context.Context, sess *session.Session) error {
	s.saved = sess
	return s.saveErr
}

func (s *fakeStore) Get(_ context.Context, id session.SessionID) (*session.Session, error) {
	s.gotID = id
	if s.getErr != nil {
		return nil, s.getErr
	}
	if s.getSession != nil {
		return s.getSession, nil
	}
	return nil, session.ErrSessionNotFound
}

func (s *fakeStore) Touch(_ context.Context, sess *session.Session, now time.Time) error {
	s.touched = sess
	s.touchedAt = now
	return s.touchErr
}

func (s *fakeStore) Delete(_ context.Context, id session.SessionID) error {
	s.deletedID = id
	return s.deleteErr
}

func (s *fakeStore) Encode(sess *session.Session) (string, error) {
	if s.encodeErr != nil {
		return "", s.encodeErr
	}
	if s.encoded != "" {
		return s.encoded, nil
	}
	return sess.ID.String(), nil
}

func (s *fakeStore) TTL() time.Duration {
	return s.ttl
}

func newManager(t *testing.T, store *fakeStore, opts ...session.Option) *session.Manager {
	t.Helper()
	manager, err := session.New(store, opts...)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return manager
}

func firstCookie(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies len = %d, want 1", len(cookies))
	}
	return cookies[0]
}

func TestSessionIDString(t *testing.T) {
	if got := session.SessionID("session-id").String(); got != "session-id" {
		t.Fatalf("String() = %q, want session-id", got)
	}
}

func TestNewRejectsNilStore(t *testing.T) {
	manager, err := session.New(nil)
	if !errors.Is(err, session.ErrNilStore) {
		t.Fatalf("New() error = %v, want %v", err, session.ErrNilStore)
	}
	if manager != nil {
		t.Fatalf("New() manager = %#v, want nil", manager)
	}
}

func TestNewRejectsInvalidClock(t *testing.T) {
	manager, err := session.New(&fakeStore{ttl: time.Hour}, session.WithNow(nil))
	if !errors.Is(err, session.ErrInvalidClock) {
		t.Fatalf("New() error = %v, want %v", err, session.ErrInvalidClock)
	}
	if manager != nil {
		t.Fatalf("New() manager = %#v, want nil", manager)
	}
}

func TestManagerCreateGeneratesSessionID(t *testing.T) {
	store := &fakeStore{ttl: time.Hour}
	manager := newManager(t, store)

	sess, err := manager.Create(context.Background(), httptest.NewRecorder(), "user-1")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if sess.ID == "" {
		t.Fatal("session ID is empty")
	}
	if _, err := base64.RawURLEncoding.DecodeString(sess.ID.String()); err != nil {
		t.Errorf("session ID is not valid base64url: %v", err)
	}
	if store.saved.ID != sess.ID {
		t.Fatal("saved session ID does not match returned session ID")
	}
}

func TestManagerCreateSetsSessionFields(t *testing.T) {
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	store := &fakeStore{ttl: 30 * time.Minute}
	manager := newManager(t, store, session.WithNow(func() time.Time { return now }))

	sess, err := manager.Create(context.Background(), httptest.NewRecorder(), "user-1")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if sess.UserID != "user-1" {
		t.Fatalf("UserID = %q, want user-1", sess.UserID)
	}
	if !sess.CreatedAt.Equal(now) {
		t.Fatalf("CreatedAt = %v, want %v", sess.CreatedAt, now)
	}
	if !sess.LastSeenAt.Equal(now) {
		t.Fatalf("LastSeenAt = %v, want %v", sess.LastSeenAt, now)
	}
	if want := now.Add(store.ttl); !sess.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want %v", sess.ExpiresAt, want)
	}
}

func TestManagerCreateSetsCookie(t *testing.T) {
	store := &fakeStore{ttl: time.Hour, encoded: "encoded-session"}
	manager := newManager(t, store,
		session.WithCookieName("auth_session"),
		session.WithSecure(true),
		session.WithHTTPOnly(true),
		session.WithSameSite(http.SameSiteStrictMode),
		session.WithPath("/app"),
	)
	w := httptest.NewRecorder()

	if _, err := manager.Create(context.Background(), w, "user-1"); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	cookie := firstCookie(t, w)
	if cookie.Name != "auth_session" || cookie.Value != "encoded-session" || cookie.Path != "/app" || cookie.MaxAge != 3600 {
		t.Fatalf("cookie = %#v", cookie)
	}
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie attributes = %#v", cookie)
	}
}

func TestManagerCreateReturnsSaveError(t *testing.T) {
	want := errors.New("save failed")
	store := &fakeStore{ttl: time.Hour, saveErr: want}
	manager := newManager(t, store)

	_, err := manager.Create(context.Background(), httptest.NewRecorder(), "user-1")
	if !errors.Is(err, want) {
		t.Fatalf("Create() error = %v, want %v", err, want)
	}
}

func TestManagerCreateReturnsEncodeError(t *testing.T) {
	want := errors.New("encode failed")
	store := &fakeStore{ttl: time.Hour, encodeErr: want}
	manager := newManager(t, store)

	_, err := manager.Create(context.Background(), httptest.NewRecorder(), "user-1")
	if !errors.Is(err, want) {
		t.Fatalf("Create() error = %v, want %v", err, want)
	}
}

func TestManagerLoadRequiresCookie(t *testing.T) {
	manager := newManager(t, &fakeStore{ttl: time.Hour})

	_, err := manager.Load(httptest.NewRequest(http.MethodGet, "/", nil))
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("Load() error = %v, want %v", err, session.ErrSessionNotFound)
	}
}

func TestManagerLoadReturnsSession(t *testing.T) {
	want := &session.Session{
		ID:        "raw-id",
		UserID:    "user-1",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	store := &fakeStore{ttl: time.Hour, getSession: want}
	manager := newManager(t, store, session.WithCookieName("auth_session"))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "auth_session", Value: "encoded-session"})

	got, err := manager.Load(req)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got != want {
		t.Fatalf("Load() session = %#v, want %#v", got, want)
	}
	if store.gotID != "encoded-session" {
		t.Fatalf("Get() id = %q, want encoded-session", store.gotID)
	}
}

func TestManagerLoadReturnsStoreError(t *testing.T) {
	want := errors.New("get failed")
	store := &fakeStore{ttl: time.Hour, getErr: want}
	manager := newManager(t, store)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "encoded-session"})

	_, err := manager.Load(req)
	if !errors.Is(err, want) {
		t.Fatalf("Load() error = %v, want %v", err, want)
	}
}

func TestManagerLoadRejectsExpiredSession(t *testing.T) {
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	store := &fakeStore{
		ttl:        time.Hour,
		getSession: &session.Session{ID: "raw-id", ExpiresAt: now},
	}
	manager := newManager(t, store, session.WithNow(func() time.Time { return now }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "encoded-session"})

	_, err := manager.Load(req)
	if !errors.Is(err, session.ErrSessionExpired) {
		t.Fatalf("Load() error = %v, want %v", err, session.ErrSessionExpired)
	}
}

func TestManagerTouchUpdatesStoreAndCookie(t *testing.T) {
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	sess := &session.Session{ID: "raw-id", ExpiresAt: now.Add(time.Hour)}
	store := &fakeStore{ttl: 2 * time.Hour, getSession: sess}
	manager := newManager(t, store,
		session.WithNow(func() time.Time { return now }),
		session.WithCookieName("auth_session"),
		session.WithSecure(true),
		session.WithPath("/app"),
	)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "auth_session", Value: "encoded-session"})
	w := httptest.NewRecorder()

	if err := manager.Touch(w, req); err != nil {
		t.Fatalf("Touch() error = %v", err)
	}

	if store.touched != sess || !store.touchedAt.Equal(now) {
		t.Fatalf("Touch() store touched session=%#v at=%v", store.touched, store.touchedAt)
	}
	cookie := firstCookie(t, w)
	if cookie.Name != "auth_session" || cookie.Value != "encoded-session" || cookie.Path != "/app" || cookie.MaxAge != 7200 || !cookie.Secure {
		t.Fatalf("cookie = %#v", cookie)
	}
}

func TestManagerTouchReturnsStoreError(t *testing.T) {
	want := errors.New("touch failed")
	store := &fakeStore{
		ttl:        time.Hour,
		getSession: &session.Session{ID: "raw-id", ExpiresAt: time.Now().Add(time.Hour)},
		touchErr:   want,
	}
	manager := newManager(t, store)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "encoded-session"})

	err := manager.Touch(httptest.NewRecorder(), req)
	if !errors.Is(err, want) {
		t.Fatalf("Touch() error = %v, want %v", err, want)
	}
}

func TestManagerDeleteIgnoresMissingCookie(t *testing.T) {
	store := &fakeStore{ttl: time.Hour}
	manager := newManager(t, store)

	if err := manager.Delete(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil)); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if store.deletedID != "" {
		t.Fatalf("Delete() deleted id = %q, want empty", store.deletedID)
	}
}

func TestManagerDeleteDeletesStoreAndClearsCookie(t *testing.T) {
	store := &fakeStore{ttl: time.Hour}
	manager := newManager(t, store,
		session.WithCookieName("auth_session"),
		session.WithSecure(true),
		session.WithPath("/app"),
	)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "auth_session", Value: "encoded-session"})
	w := httptest.NewRecorder()

	if err := manager.Delete(w, req); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if store.deletedID != "encoded-session" {
		t.Fatalf("Delete() id = %q, want encoded-session", store.deletedID)
	}
	cookie := firstCookie(t, w)
	if cookie.Name != "auth_session" || cookie.Value != "" || cookie.Path != "/app" || cookie.MaxAge != -1 || !cookie.Secure {
		t.Fatalf("clear cookie = %#v", cookie)
	}
}

func TestManagerDeleteReturnsStoreError(t *testing.T) {
	want := errors.New("delete failed")
	store := &fakeStore{ttl: time.Hour, deleteErr: want}
	manager := newManager(t, store)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "encoded-session"})

	err := manager.Delete(httptest.NewRecorder(), req)
	if !errors.Is(err, want) {
		t.Fatalf("Delete() error = %v, want %v", err, want)
	}
}
