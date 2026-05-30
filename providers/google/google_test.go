package google

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	goauth "github.com/hazefyro/auth"
	"golang.org/x/oauth2"
)

func newGoogleOAuthServer(t *testing.T, userInfoStatus int, userInfoBody string) (*httptest.Server, oauth2.Endpoint) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth":
			w.WriteHeader(http.StatusNoContent)
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Fatalf("ParseForm() error = %v", err)
			}
			if r.Form.Get("code") == "bad" || r.Form.Get("refresh_token") == "bad" {
				http.Error(w, "bad token", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "access-token",
				"refresh_token": "refresh-token",
				"token_type":    "Bearer",
				"expires_in":    3600,
			})
		case "/userinfo":
			w.WriteHeader(userInfoStatus)
			_, _ = w.Write([]byte(userInfoBody))
		default:
			http.NotFound(w, r)
		}
	}))
	return server, oauth2.Endpoint{AuthURL: server.URL + "/auth", TokenURL: server.URL + "/token"}
}

func newGoogleTestProvider(t *testing.T, body string, opts ...Option) (*Provider, *httptest.Server) {
	t.Helper()
	server, endpoint := newGoogleOAuthServer(t, http.StatusOK, body)
	allOpts := append([]Option{WithEndpoint(endpoint), WithUserInfoURL(server.URL + "/userinfo"), WithHTTPClient(server.Client())}, opts...)
	return New("client-id", "client-secret", "http://example.com/callback", allOpts...), server
}

func TestGoogleNewDefaultScopes(t *testing.T) {
	p := New("id", "secret", "redirect")
	want := []string{"openid", "email", "profile"}
	if !reflect.DeepEqual(p.config.Scopes, want) {
		t.Fatalf("Scopes = %#v, want %#v", p.config.Scopes, want)
	}
}

func TestGoogleNewWithScopes(t *testing.T) {
	p := New("id", "secret", "redirect", WithScopes("custom"))
	if !reflect.DeepEqual(p.config.Scopes, []string{"custom"}) {
		t.Fatalf("Scopes = %#v", p.config.Scopes)
	}
}

func TestGoogleNewWithAdditionalScopes(t *testing.T) {
	p := New("id", "secret", "redirect", WithAdditionalScopes("calendar"))
	want := []string{"openid", "email", "profile", "calendar"}
	if !reflect.DeepEqual(p.config.Scopes, want) {
		t.Fatalf("Scopes = %#v, want %#v", p.config.Scopes, want)
	}
}

func TestGoogleNewWithEndpoint(t *testing.T) {
	endpoint := oauth2.Endpoint{AuthURL: "https://example.com/auth", TokenURL: "https://example.com/token"}
	p := New("id", "secret", "redirect", WithEndpoint(endpoint))
	if p.config.Endpoint != endpoint {
		t.Fatalf("Endpoint = %#v, want %#v", p.config.Endpoint, endpoint)
	}
}

func TestGoogleNewWithUserInfoURL(t *testing.T) {
	p := New("id", "secret", "redirect", WithUserInfoURL("https://example.com/userinfo"))
	if p.userInfoURL != "https://example.com/userinfo" {
		t.Fatalf("userInfoURL = %q", p.userInfoURL)
	}
}

func TestGoogleNewWithHTTPClient(t *testing.T) {
	client := &http.Client{}
	p := New("id", "secret", "redirect", WithHTTPClient(client))
	if p.httpClient != client {
		t.Fatal("HTTPClient was not stored")
	}
}

func TestGoogleNewWithAuthCodeOptions(t *testing.T) {
	p := New("id", "secret", "redirect", WithAuthCodeOptions(oauth2.SetAuthURLParam("prompt", "consent")))
	if len(p.authCodeOptions) != 1 {
		t.Fatalf("authCodeOptions len = %d, want 1", len(p.authCodeOptions))
	}
}

func TestGoogleName(t *testing.T) {
	if got := New("id", "secret", "redirect").Name(); got != "google" {
		t.Fatalf("Name() = %q, want google", got)
	}
}

func TestGoogleBeginAuthIncludesState(t *testing.T) {
	p := New("id", "secret", "http://example.com/callback", WithEndpoint(oauth2.Endpoint{AuthURL: "https://example.com/auth", TokenURL: "https://example.com/token"}))
	authURL, err := p.BeginAuth("state")
	if err != nil {
		t.Fatalf("BeginAuth() error = %v", err)
	}
	values, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if values.Query().Get("state") != "state" {
		t.Fatalf("state = %q", values.Query().Get("state"))
	}
}

func TestGoogleBeginAuthRequestsOfflineAccess(t *testing.T) {
	p := New("id", "secret", "http://example.com/callback", WithEndpoint(oauth2.Endpoint{AuthURL: "https://example.com/auth", TokenURL: "https://example.com/token"}))
	authURL, err := p.BeginAuth("state")
	if err != nil {
		t.Fatalf("BeginAuth() error = %v", err)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got := parsed.Query().Get("access_type"); got != "offline" {
		t.Fatalf("access_type = %q, want offline", got)
	}
}

func TestGoogleBeginAuthIncludesCustomOptions(t *testing.T) {
	p := New("id", "secret", "http://example.com/callback",
		WithEndpoint(oauth2.Endpoint{AuthURL: "https://example.com/auth", TokenURL: "https://example.com/token"}),
		WithAuthCodeOptions(oauth2.SetAuthURLParam("prompt", "consent")),
	)
	authURL, err := p.BeginAuth("state")
	if err != nil {
		t.Fatalf("BeginAuth() error = %v", err)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got := parsed.Query().Get("prompt"); got != "consent" {
		t.Fatalf("prompt = %q, want consent", got)
	}
}

func TestGoogleCompleteAuthRequiresCode(t *testing.T) {
	p := New("id", "secret", "redirect")
	_, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback", nil))
	if !errors.Is(err, goauth.ErrMissingCode) {
		t.Fatalf("CompleteAuth() error = %v, want %v", err, goauth.ErrMissingCode)
	}
}

func TestGoogleCompleteAuthFetchesUserInfo(t *testing.T) {
	p, server := newGoogleTestProvider(t, `{"sub":"123"}`)
	defer server.Close()
	if _, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil)); err != nil {
		t.Fatalf("CompleteAuth() error = %v", err)
	}
}

func TestGoogleCompleteAuthMapsIdentity(t *testing.T) {
	p, server := newGoogleTestProvider(t, `{"sub":"123","email":"user@example.com","name":"User","picture":"https://example.com/avatar.png"}`)
	defer server.Close()
	got, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil))
	if err != nil {
		t.Fatalf("CompleteAuth() error = %v", err)
	}
	want := goauth.Identity{ID: "123", Email: "user@example.com", Name: "User", AvatarURL: "https://example.com/avatar.png", Provider: "google"}
	if got.Identity != want {
		t.Fatalf("Identity = %#v, want %#v", got.Identity, want)
	}
}

func TestGoogleCompleteAuthSetsProvider(t *testing.T) {
	p, server := newGoogleTestProvider(t, `{"sub":"123"}`)
	defer server.Close()
	got, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil))
	if err != nil {
		t.Fatalf("CompleteAuth() error = %v", err)
	}
	if got.Identity.Provider != "google" {
		t.Fatalf("Provider = %q, want google", got.Identity.Provider)
	}
}

func TestGoogleCompleteAuthReturnsCredentials(t *testing.T) {
	p, server := newGoogleTestProvider(t, `{"sub":"123"}`)
	defer server.Close()
	got, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil))
	if err != nil {
		t.Fatalf("CompleteAuth() error = %v", err)
	}
	if got.Credentials.AccessToken != "access-token" || got.Credentials.RefreshToken != "refresh-token" || got.Credentials.ExpiresAt.IsZero() {
		t.Fatalf("Credentials = %#v", got.Credentials)
	}
}

func TestGoogleCompleteAuthPreservesRawData(t *testing.T) {
	p, server := newGoogleTestProvider(t, `{"sub":"123","email":"user@example.com"}`)
	defer server.Close()
	got, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil))
	if err != nil {
		t.Fatalf("CompleteAuth() error = %v", err)
	}
	if got.RawData["email"] != "user@example.com" {
		t.Fatalf("RawData = %#v", got.RawData)
	}
}

func TestGoogleCompleteAuthRequiresUserID(t *testing.T) {
	p, server := newGoogleTestProvider(t, `{"email":"user@example.com"}`)
	defer server.Close()
	_, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil))
	if !errors.Is(err, goauth.ErrMissingUserID) {
		t.Fatalf("CompleteAuth() error = %v, want %v", err, goauth.ErrMissingUserID)
	}
}

func TestGoogleCompleteAuthReturnsOAuthErrors(t *testing.T) {
	p, server := newGoogleTestProvider(t, `{"sub":"123"}`)
	defer server.Close()
	_, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=bad", nil))
	if err == nil {
		t.Fatal("CompleteAuth() exchange error = nil, want error")
	}

	p, server = newGoogleTestProvider(t, `nope`)
	defer server.Close()
	_, err = p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil))
	if err == nil {
		t.Fatal("CompleteAuth() userinfo error = nil, want error")
	}
}

func TestGoogleRefreshToken(t *testing.T) {
	p, server := newGoogleTestProvider(t, `{"sub":"123"}`)
	defer server.Close()
	got, err := p.RefreshToken(context.Background(), "old-refresh")
	if err != nil {
		t.Fatalf("RefreshToken() error = %v", err)
	}
	if got.AccessToken != "access-token" || got.RefreshToken != "refresh-token" {
		t.Fatalf("Credentials = %#v", got)
	}
}

func TestGoogleRefreshTokenUsesCustomHTTPClient(t *testing.T) {
	p, server := newGoogleTestProvider(t, `{"sub":"123"}`)
	defer server.Close()
	if _, err := p.RefreshToken(context.Background(), "old-refresh"); err != nil {
		t.Fatalf("RefreshToken() error = %v", err)
	}
}
