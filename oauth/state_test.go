package oauth_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hazefyro/halo/oauth"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func storedCookie(t *testing.T, store *oauth.CookieStateStore, state, provider string) *http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	if err := store.Store(w, httptest.NewRequest(http.MethodGet, "/", nil), state, provider); err != nil {
		t.Fatalf("Store() error = %v", err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies len = %d, want 1", len(cookies))
	}
	return cookies[0]
}

func TestNewCookieStateStoreRejectsShortSecret(t *testing.T) {
	store, err := oauth.NewCookieStateStore("short")
	if err == nil {
		t.Fatal("NewCookieStateStore() error = nil, want error")
	}
	if store != nil {
		t.Fatalf("store = %#v, want nil", store)
	}
}

func TestNewCookieStateStoreCreatesSecureStore(t *testing.T) {
	store, err := oauth.NewCookieStateStore(testSecret)
	if err != nil {
		t.Fatalf("NewCookieStateStore() error = %v", err)
	}
	cookie := storedCookie(t, store, "state", "google")
	if !cookie.Secure {
		t.Fatal("cookie Secure = false, want true")
	}
}

func TestNewCookieStateStoreWithSecureFalse(t *testing.T) {
	store, err := oauth.NewCookieStateStore(testSecret, oauth.WithSecure(false))
	if err != nil {
		t.Fatalf("NewCookieStateStore() error = %v", err)
	}
	cookie := storedCookie(t, store, "state", "google")
	if cookie.Secure {
		t.Fatal("cookie Secure = true, want false")
	}
}

func TestCookieStateStoreStoreUsesProviderCookieName(t *testing.T) {
	store, err := oauth.NewCookieStateStore(testSecret)
	if err != nil {
		t.Fatalf("NewCookieStateStore() error = %v", err)
	}
	cookie := storedCookie(t, store, "state", "google")
	if cookie.Name != "goauth_state_google" {
		t.Fatalf("cookie name = %q, want goauth_state_google", cookie.Name)
	}
}

func TestCookieStateStoreStoreSignsState(t *testing.T) {
	store, err := oauth.NewCookieStateStore(testSecret)
	if err != nil {
		t.Fatalf("NewCookieStateStore() error = %v", err)
	}
	cookie := storedCookie(t, store, "state", "google")
	if cookie.Value == "state" {
		t.Fatal("cookie stored raw state")
	}
	if len(cookie.Value) != 64 {
		t.Fatalf("signature length = %d, want 64", len(cookie.Value))
	}
}

func TestCookieStateStoreStoreSetsCookieAttributes(t *testing.T) {
	store, err := oauth.NewCookieStateStore(testSecret)
	if err != nil {
		t.Fatalf("NewCookieStateStore() error = %v", err)
	}
	cookie := storedCookie(t, store, "state", "google")
	if cookie.Path != "/" || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge != 300 {
		t.Fatalf("cookie attributes = %#v", cookie)
	}
}

func TestCookieStateStoreStoreSetsSecureFlag(t *testing.T) {
	store, err := oauth.NewCookieStateStore(testSecret)
	if err != nil {
		t.Fatalf("NewCookieStateStore() error = %v", err)
	}
	if cookie := storedCookie(t, store, "state", "google"); !cookie.Secure {
		t.Fatal("Secure = false, want true")
	}
}

func TestCookieStateStoreStoreClearsSecureFlagForInsecureStore(t *testing.T) {
	store, err := oauth.NewCookieStateStore(testSecret, oauth.WithSecure(false))
	if err != nil {
		t.Fatalf("NewCookieStateStore() error = %v", err)
	}
	if cookie := storedCookie(t, store, "state", "google"); cookie.Secure {
		t.Fatal("Secure = true, want false")
	}
}

func TestCookieStateStoreVerifyAcceptsMatchingState(t *testing.T) {
	store, err := oauth.NewCookieStateStore(testSecret)
	if err != nil {
		t.Fatalf("NewCookieStateStore() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(storedCookie(t, store, "state", "google"))
	if err := store.Verify(req, "state", "google"); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestCookieStateStoreVerifyRejectsMissingCookie(t *testing.T) {
	store, err := oauth.NewCookieStateStore(testSecret)
	if err != nil {
		t.Fatalf("NewCookieStateStore() error = %v", err)
	}
	err = store.Verify(httptest.NewRequest(http.MethodGet, "/", nil), "state", "google")
	if !errors.Is(err, oauth.ErrStateMismatch) {
		t.Fatalf("Verify() error = %v, want %v", err, oauth.ErrStateMismatch)
	}
}

func TestCookieStateStoreVerifyRejectsWrongProvider(t *testing.T) {
	store, err := oauth.NewCookieStateStore(testSecret)
	if err != nil {
		t.Fatalf("NewCookieStateStore() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(storedCookie(t, store, "state", "google"))
	err = store.Verify(req, "state", "discord")
	if !errors.Is(err, oauth.ErrStateMismatch) {
		t.Fatalf("Verify() error = %v, want %v", err, oauth.ErrStateMismatch)
	}
}

func TestCookieStateStoreVerifyRejectsWrongState(t *testing.T) {
	store, err := oauth.NewCookieStateStore(testSecret)
	if err != nil {
		t.Fatalf("NewCookieStateStore() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(storedCookie(t, store, "state", "google"))
	err = store.Verify(req, "other", "google")
	if !errors.Is(err, oauth.ErrStateMismatch) {
		t.Fatalf("Verify() error = %v, want %v", err, oauth.ErrStateMismatch)
	}
}

func TestCookieStateStoreVerifyRejectsTamperedSignature(t *testing.T) {
	store, err := oauth.NewCookieStateStore(testSecret)
	if err != nil {
		t.Fatalf("NewCookieStateStore() error = %v", err)
	}
	cookie := storedCookie(t, store, "state", "google")
	cookie.Value = "tampered"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	err = store.Verify(req, "state", "google")
	if !errors.Is(err, oauth.ErrStateMismatch) {
		t.Fatalf("Verify() error = %v, want %v", err, oauth.ErrStateMismatch)
	}
}

func TestCookieStateStoreClearExpiresCookie(t *testing.T) {
	store, err := oauth.NewCookieStateStore(testSecret)
	if err != nil {
		t.Fatalf("NewCookieStateStore() error = %v", err)
	}
	w := httptest.NewRecorder()
	store.Clear(w, "google")
	cookie := w.Result().Cookies()[0]
	if cookie.Name != "goauth_state_google" || cookie.Value != "" || cookie.MaxAge != -1 {
		t.Fatalf("clear cookie = %#v", cookie)
	}
}

func TestCookieStateStoreClearPreservesCookieAttributes(t *testing.T) {
	store, err := oauth.NewCookieStateStore(testSecret)
	if err != nil {
		t.Fatalf("NewCookieStateStore() error = %v", err)
	}
	w := httptest.NewRecorder()
	store.Clear(w, "google")
	cookie := w.Result().Cookies()[0]
	if cookie.Path != "/" || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("clear cookie attributes = %#v", cookie)
	}
}
