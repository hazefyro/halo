package oauth_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hazefyro/halo/oauth"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func storedCookie(t *testing.T, store *oauth.CookieStateStore, state, verifier, provider string) *http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	if err := store.Store(w, httptest.NewRequest(http.MethodGet, "/", nil), state, verifier, provider); err != nil {
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
	cookie := storedCookie(t, store, "state", "verifier", "google")
	if !cookie.Secure {
		t.Fatal("cookie Secure = false, want true")
	}
}

func TestNewCookieStateStoreWithSecureFalse(t *testing.T) {
	store, err := oauth.NewCookieStateStore(testSecret, oauth.WithSecure(false))
	if err != nil {
		t.Fatalf("NewCookieStateStore() error = %v", err)
	}
	cookie := storedCookie(t, store, "state", "verifier", "google")
	if cookie.Secure {
		t.Fatal("cookie Secure = true, want false")
	}
}

func TestCookieStateStoreStoreUsesProviderCookieName(t *testing.T) {
	store, err := oauth.NewCookieStateStore(testSecret)
	if err != nil {
		t.Fatalf("NewCookieStateStore() error = %v", err)
	}
	cookie := storedCookie(t, store, "state", "verifier", "google")
	if cookie.Name != "goauth_state_google" {
		t.Fatalf("cookie name = %q, want goauth_state_google", cookie.Name)
	}
}

func TestCookieStateStoreStoreSignsState(t *testing.T) {
	store, err := oauth.NewCookieStateStore(testSecret)
	if err != nil {
		t.Fatalf("NewCookieStateStore() error = %v", err)
	}
	cookie := storedCookie(t, store, "state", "verifier", "google")
	if cookie.Value == "state" {
		t.Fatal("cookie stored raw state")
	}
	verifier, sig, ok := strings.Cut(cookie.Value, ".")
	if !ok || verifier != "verifier" {
		t.Fatalf("cookie value = %q, want verifier.<sig>", cookie.Value)
	}
	if len(sig) != 64 {
		t.Fatalf("signature length = %d, want 64", len(sig))
	}
}

func TestCookieStateStoreStoreSetsCookieAttributes(t *testing.T) {
	store, err := oauth.NewCookieStateStore(testSecret)
	if err != nil {
		t.Fatalf("NewCookieStateStore() error = %v", err)
	}
	cookie := storedCookie(t, store, "state", "verifier", "google")
	if cookie.Path != "/" || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge != 300 {
		t.Fatalf("cookie attributes = %#v", cookie)
	}
}

func TestCookieStateStoreStoreSetsSecureFlag(t *testing.T) {
	store, err := oauth.NewCookieStateStore(testSecret)
	if err != nil {
		t.Fatalf("NewCookieStateStore() error = %v", err)
	}
	if cookie := storedCookie(t, store, "state", "verifier", "google"); !cookie.Secure {
		t.Fatal("Secure = false, want true")
	}
}

func TestCookieStateStoreStoreClearsSecureFlagForInsecureStore(t *testing.T) {
	store, err := oauth.NewCookieStateStore(testSecret, oauth.WithSecure(false))
	if err != nil {
		t.Fatalf("NewCookieStateStore() error = %v", err)
	}
	if cookie := storedCookie(t, store, "state", "verifier", "google"); cookie.Secure {
		t.Fatal("Secure = true, want false")
	}
}

func TestCookieStateStoreVerifyAcceptsMatchingState(t *testing.T) {
	store, err := oauth.NewCookieStateStore(testSecret)
	if err != nil {
		t.Fatalf("NewCookieStateStore() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(storedCookie(t, store, "state", "verifier", "google"))
	if _, err := store.Verify(req, "state", "google"); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestCookieStateStoreVerifyRejectsMissingCookie(t *testing.T) {
	store, err := oauth.NewCookieStateStore(testSecret)
	if err != nil {
		t.Fatalf("NewCookieStateStore() error = %v", err)
	}
	_, err = store.Verify(httptest.NewRequest(http.MethodGet, "/", nil), "state", "google")
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
	req.AddCookie(storedCookie(t, store, "state", "verifier", "google"))
	_, err = store.Verify(req, "state", "discord")
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
	req.AddCookie(storedCookie(t, store, "state", "verifier", "google"))
	_, err = store.Verify(req, "other", "google")
	if !errors.Is(err, oauth.ErrStateMismatch) {
		t.Fatalf("Verify() error = %v, want %v", err, oauth.ErrStateMismatch)
	}
}

func TestCookieStateStoreVerifyRejectsTamperedSignature(t *testing.T) {
	store, err := oauth.NewCookieStateStore(testSecret)
	if err != nil {
		t.Fatalf("NewCookieStateStore() error = %v", err)
	}
	cookie := storedCookie(t, store, "state", "verifier", "google")
	cookie.Value = "tampered"
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	_, err = store.Verify(req, "state", "google")
	if !errors.Is(err, oauth.ErrStateMismatch) {
		t.Fatalf("Verify() error = %v, want %v", err, oauth.ErrStateMismatch)
	}
}

func TestCookieStateStoreVerifyReturnsVerifier(t *testing.T) {
	store, err := oauth.NewCookieStateStore(testSecret)
	if err != nil {
		t.Fatalf("NewCookieStateStore() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(storedCookie(t, store, "state", "pkce-verifier", "google"))
	got, err := store.Verify(req, "state", "google")
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if got != "pkce-verifier" {
		t.Fatalf("verifier = %q, want pkce-verifier", got)
	}
}

func TestCookieStateStoreVerifyRejectsTamperedVerifier(t *testing.T) {
	store, err := oauth.NewCookieStateStore(testSecret)
	if err != nil {
		t.Fatalf("NewCookieStateStore() error = %v", err)
	}
	cookie := storedCookie(t, store, "state", "verifier", "google")
	// Swap the verifier but keep the original signature; the HMAC binds both,
	// so verification must fail.
	_, sig, _ := strings.Cut(cookie.Value, ".")
	cookie.Value = "evil-verifier." + sig
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	if _, err := store.Verify(req, "state", "google"); !errors.Is(err, oauth.ErrStateMismatch) {
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
