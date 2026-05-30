package discord

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	goauth "github.com/hazefyro/go-auth"
	"golang.org/x/oauth2"
)

func newDiscordOAuthServer(t *testing.T, userInfoStatus int, userInfoBody string) (*httptest.Server, oauth2.Endpoint) {
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

func newDiscordTestProvider(t *testing.T, body string, opts ...Option) (*Provider, *httptest.Server) {
	t.Helper()
	server, endpoint := newDiscordOAuthServer(t, http.StatusOK, body)
	allOpts := append([]Option{WithEndpoint(endpoint), WithUserInfoURL(server.URL + "/userinfo"), WithHTTPClient(server.Client())}, opts...)
	return New("client-id", "client-secret", "http://example.com/callback", allOpts...), server
}

func TestDiscordNewDefaultScopes(t *testing.T) {
	p := New("id", "secret", "redirect")
	want := []string{"identify", "email"}
	if !reflect.DeepEqual(p.config.Scopes, want) {
		t.Fatalf("Scopes = %#v, want %#v", p.config.Scopes, want)
	}
}

func TestDiscordNewWithScopes(t *testing.T) {
	p := New("id", "secret", "redirect", WithScopes("custom"))
	if !reflect.DeepEqual(p.config.Scopes, []string{"custom"}) {
		t.Fatalf("Scopes = %#v", p.config.Scopes)
	}
}

func TestDiscordNewWithAdditionalScopes(t *testing.T) {
	p := New("id", "secret", "redirect", WithAdditionalScopes("guilds"))
	want := []string{"identify", "email", "guilds"}
	if !reflect.DeepEqual(p.config.Scopes, want) {
		t.Fatalf("Scopes = %#v, want %#v", p.config.Scopes, want)
	}
}

func TestDiscordNewWithEndpoint(t *testing.T) {
	endpoint := oauth2.Endpoint{AuthURL: "https://example.com/auth", TokenURL: "https://example.com/token"}
	p := New("id", "secret", "redirect", WithEndpoint(endpoint))
	if p.config.Endpoint != endpoint {
		t.Fatalf("Endpoint = %#v, want %#v", p.config.Endpoint, endpoint)
	}
}

func TestDiscordNewWithUserInfoURL(t *testing.T) {
	p := New("id", "secret", "redirect", WithUserInfoURL("https://example.com/userinfo"))
	if p.userInfoURL != "https://example.com/userinfo" {
		t.Fatalf("userInfoURL = %q", p.userInfoURL)
	}
}

func TestDiscordNewWithHTTPClient(t *testing.T) {
	client := &http.Client{}
	p := New("id", "secret", "redirect", WithHTTPClient(client))
	if p.httpClient != client {
		t.Fatal("HTTPClient was not stored")
	}
}

func TestDiscordNewWithAuthCodeOptions(t *testing.T) {
	p := New("id", "secret", "redirect", WithAuthCodeOptions(oauth2.SetAuthURLParam("prompt", "none")))
	if len(p.authCodeOptions) != 1 {
		t.Fatalf("authCodeOptions len = %d, want 1", len(p.authCodeOptions))
	}
}

func TestDiscordName(t *testing.T) {
	if got := New("id", "secret", "redirect").Name(); got != "discord" {
		t.Fatalf("Name() = %q, want discord", got)
	}
}

func TestDiscordBeginAuthIncludesState(t *testing.T) {
	p := New("id", "secret", "http://example.com/callback", WithEndpoint(oauth2.Endpoint{AuthURL: "https://example.com/auth", TokenURL: "https://example.com/token"}))
	authURL, err := p.BeginAuth("state")
	if err != nil {
		t.Fatalf("BeginAuth() error = %v", err)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got := parsed.Query().Get("state"); got != "state" {
		t.Fatalf("state = %q, want state", got)
	}
}

func TestDiscordBeginAuthIncludesCustomOptions(t *testing.T) {
	p := New("id", "secret", "http://example.com/callback",
		WithEndpoint(oauth2.Endpoint{AuthURL: "https://example.com/auth", TokenURL: "https://example.com/token"}),
		WithAuthCodeOptions(oauth2.SetAuthURLParam("prompt", "none")),
	)
	authURL, err := p.BeginAuth("state")
	if err != nil {
		t.Fatalf("BeginAuth() error = %v", err)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got := parsed.Query().Get("prompt"); got != "none" {
		t.Fatalf("prompt = %q, want none", got)
	}
}

func TestDiscordCompleteAuthRequiresCode(t *testing.T) {
	p := New("id", "secret", "redirect")
	_, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback", nil))
	if !errors.Is(err, goauth.ErrMissingCode) {
		t.Fatalf("CompleteAuth() error = %v, want %v", err, goauth.ErrMissingCode)
	}
}

func TestDiscordCompleteAuthFetchesUserInfo(t *testing.T) {
	p, server := newDiscordTestProvider(t, `{"id":"123"}`)
	defer server.Close()
	if _, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil)); err != nil {
		t.Fatalf("CompleteAuth() error = %v", err)
	}
}

func TestDiscordCompleteAuthMapsIdentity(t *testing.T) {
	p, server := newDiscordTestProvider(t, `{"id":"123","email":"user@example.com","username":"user","global_name":"User"}`)
	defer server.Close()
	got, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil))
	if err != nil {
		t.Fatalf("CompleteAuth() error = %v", err)
	}
	want := goauth.Identity{ID: "123", Email: "user@example.com", Username: "user", Name: "User", Provider: "discord"}
	if got.Identity != want {
		t.Fatalf("Identity = %#v, want %#v", got.Identity, want)
	}
}

func TestDiscordCompleteAuthBuildsAvatarURL(t *testing.T) {
	p, server := newDiscordTestProvider(t, `{"id":"123","avatar":"hash"}`)
	defer server.Close()
	got, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil))
	if err != nil {
		t.Fatalf("CompleteAuth() error = %v", err)
	}
	want := "https://cdn.discordapp.com/avatars/123/hash.png"
	if got.Identity.AvatarURL != want {
		t.Fatalf("AvatarURL = %q, want %q", got.Identity.AvatarURL, want)
	}
}

func TestDiscordCompleteAuthAllowsMissingAvatar(t *testing.T) {
	p, server := newDiscordTestProvider(t, `{"id":"123"}`)
	defer server.Close()
	got, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil))
	if err != nil {
		t.Fatalf("CompleteAuth() error = %v", err)
	}
	if got.Identity.AvatarURL != "" {
		t.Fatalf("AvatarURL = %q, want empty", got.Identity.AvatarURL)
	}
}

func TestDiscordCompleteAuthSetsProvider(t *testing.T) {
	p, server := newDiscordTestProvider(t, `{"id":"123"}`)
	defer server.Close()
	got, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil))
	if err != nil {
		t.Fatalf("CompleteAuth() error = %v", err)
	}
	if got.Identity.Provider != "discord" {
		t.Fatalf("Provider = %q, want discord", got.Identity.Provider)
	}
}

func TestDiscordCompleteAuthReturnsCredentials(t *testing.T) {
	p, server := newDiscordTestProvider(t, `{"id":"123"}`)
	defer server.Close()
	got, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil))
	if err != nil {
		t.Fatalf("CompleteAuth() error = %v", err)
	}
	if got.Credentials.AccessToken != "access-token" || got.Credentials.RefreshToken != "refresh-token" || got.Credentials.ExpiresAt.IsZero() {
		t.Fatalf("Credentials = %#v", got.Credentials)
	}
}

func TestDiscordCompleteAuthPreservesRawData(t *testing.T) {
	p, server := newDiscordTestProvider(t, `{"id":"123","email":"user@example.com"}`)
	defer server.Close()
	got, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil))
	if err != nil {
		t.Fatalf("CompleteAuth() error = %v", err)
	}
	if got.RawData["email"] != "user@example.com" {
		t.Fatalf("RawData = %#v", got.RawData)
	}
}

func TestDiscordCompleteAuthRequiresUserID(t *testing.T) {
	p, server := newDiscordTestProvider(t, `{"email":"user@example.com"}`)
	defer server.Close()
	_, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil))
	if !errors.Is(err, goauth.ErrMissingUserID) {
		t.Fatalf("CompleteAuth() error = %v, want %v", err, goauth.ErrMissingUserID)
	}
}

func TestDiscordCompleteAuthReturnsOAuthErrors(t *testing.T) {
	p, server := newDiscordTestProvider(t, `{"id":"123"}`)
	defer server.Close()
	_, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=bad", nil))
	if err == nil {
		t.Fatal("CompleteAuth() exchange error = nil, want error")
	}

	p, server = newDiscordTestProvider(t, `nope`)
	defer server.Close()
	_, err = p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil))
	if err == nil {
		t.Fatal("CompleteAuth() userinfo error = nil, want error")
	}
}

func TestDiscordRefreshToken(t *testing.T) {
	p, server := newDiscordTestProvider(t, `{"id":"123"}`)
	defer server.Close()
	got, err := p.RefreshToken(context.Background(), "old-refresh")
	if err != nil {
		t.Fatalf("RefreshToken() error = %v", err)
	}
	if got.AccessToken != "access-token" || got.RefreshToken != "refresh-token" {
		t.Fatalf("Credentials = %#v", got)
	}
}

func TestDiscordRefreshTokenUsesCustomHTTPClient(t *testing.T) {
	p, server := newDiscordTestProvider(t, `{"id":"123"}`)
	defer server.Close()
	if _, err := p.RefreshToken(context.Background(), "old-refresh"); err != nil {
		t.Fatalf("RefreshToken() error = %v", err)
	}
}
