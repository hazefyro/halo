package session_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hazefyro/halo/session"
)

var errArbitrary = errors.New("boom")

// authedRequest returns a request carrying a cookie that the given store will
// resolve to a valid session.
func authedRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "encoded-session"})
	return req
}

func validSessionStore() *fakeStore {
	return &fakeStore{
		ttl:        time.Hour,
		getSession: &session.Session{ID: "raw-id", UserID: "user-1", ExpiresAt: time.Now().Add(time.Hour)},
	}
}

func okHandler(called *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*called = true
		w.WriteHeader(http.StatusOK)
	})
}

func TestRequireAuthAllowsValidSession(t *testing.T) {
	manager := newManager(t, validSessionStore())
	called := false
	w := httptest.NewRecorder()

	manager.RequireAuth()(okHandler(&called)).ServeHTTP(w, authedRequest())

	if !called {
		t.Fatal("next handler was not called")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestRequireAuthInjectsSession(t *testing.T) {
	manager := newManager(t, validSessionStore())
	var got *session.Session
	var ok bool
	handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, ok = session.FromContext(r.Context())
	})

	manager.RequireAuth()(handler).ServeHTTP(httptest.NewRecorder(), authedRequest())

	if !ok {
		t.Fatal("FromContext() ok = false, want true")
	}
	if got.UserID != "user-1" {
		t.Fatalf("session UserID = %q, want user-1", got.UserID)
	}
}

func TestRequireAuthRejectsMissingSessionWith401(t *testing.T) {
	manager := newManager(t, &fakeStore{ttl: time.Hour})
	called := false
	w := httptest.NewRecorder()

	// No cookie -> Load fails -> default unauthorized handler.
	manager.RequireAuth()(okHandler(&called)).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if called {
		t.Fatal("next handler called for unauthenticated request")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestRequireAuthWithLoginRedirect(t *testing.T) {
	manager := newManager(t, &fakeStore{ttl: time.Hour})
	called := false
	w := httptest.NewRecorder()

	mw := manager.RequireAuth(session.WithLoginRedirect("/login"))
	mw(okHandler(&called)).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if called {
		t.Fatal("next handler called for unauthenticated request")
	}
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}
	if loc := w.Header().Get("Location"); loc != "/login" {
		t.Fatalf("Location = %q, want /login", loc)
	}
}

func TestRequireAuthWithUnauthorized(t *testing.T) {
	manager := newManager(t, &fakeStore{ttl: time.Hour})
	w := httptest.NewRecorder()

	custom := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	})
	mw := manager.RequireAuth(session.WithUnauthorized(custom))
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
		ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestRequireAuthSlidingExpiryTouchesSession(t *testing.T) {
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	store := validSessionStore()
	store.getSession.ExpiresAt = now.Add(time.Hour)
	manager := newManager(t, store, session.WithNow(func() time.Time { return now }))
	w := httptest.NewRecorder()

	mw := manager.RequireAuth(session.WithSlidingExpiry())
	called := false
	mw(okHandler(&called)).ServeHTTP(w, authedRequest())

	if !called {
		t.Fatal("next handler was not called")
	}
	if store.touched != store.getSession || !store.touchedAt.Equal(now) {
		t.Fatalf("sliding expiry did not Touch session: touched=%#v at=%v", store.touched, store.touchedAt)
	}
	if c := firstCookie(t, w); c.MaxAge != 3600 {
		t.Fatalf("refreshed cookie MaxAge = %d, want 3600", c.MaxAge)
	}
}

func TestRequireAuthWithoutSlidingExpiryDoesNotTouch(t *testing.T) {
	store := validSessionStore()
	manager := newManager(t, store)
	called := false

	manager.RequireAuth()(okHandler(&called)).ServeHTTP(httptest.NewRecorder(), authedRequest())

	if store.touched != nil {
		t.Fatalf("session was touched without WithSlidingExpiry: %#v", store.touched)
	}
}

func TestRequireAuthSlidingExpiryProceedsOnTouchError(t *testing.T) {
	store := validSessionStore()
	store.touchErr = errArbitrary
	manager := newManager(t, store)
	called := false
	w := httptest.NewRecorder()

	manager.RequireAuth(session.WithSlidingExpiry())(okHandler(&called)).ServeHTTP(w, authedRequest())

	if !called {
		t.Fatal("next handler was not called despite valid session (Touch error must not fail the request)")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
}
