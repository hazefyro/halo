package github

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	goauth "github.com/hazefyro/go-auth"
	"golang.org/x/oauth2"
)

type githubEmailTransport struct {
	base       http.RoundTripper
	status     int
	body       string
	emailCalls int
}

func (t *githubEmailTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host == "api.github.com" && r.URL.Path == "/user/emails" {
		t.emailCalls++
		return &http.Response{
			StatusCode: t.status,
			Status:     http.StatusText(t.status),
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewBufferString(t.body)),
			Request:    r,
		}, nil
	}
	if t.base != nil {
		return t.base.RoundTrip(r)
	}
	return http.DefaultTransport.RoundTrip(r)
}

func newGitHubOAuthServer(t *testing.T, userInfoStatus int, userInfoBody string) (*httptest.Server, oauth2.Endpoint) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth":
			w.WriteHeader(http.StatusNoContent)
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Fatalf("ParseForm() error = %v", err)
			}
			if r.Form.Get("code") == "bad" {
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

func newGitHubTestProvider(t *testing.T, userInfoBody, emailBody string, emailStatus int, opts ...Option) (*Provider, *httptest.Server, *githubEmailTransport) {
	t.Helper()
	server, endpoint := newGitHubOAuthServer(t, http.StatusOK, userInfoBody)
	emailTransport := &githubEmailTransport{base: server.Client().Transport, status: emailStatus, body: emailBody}
	client := server.Client()
	client.Transport = emailTransport
	allOpts := append([]Option{WithEndpoint(endpoint), WithUserInfoURL(server.URL + "/userinfo"), WithHTTPClient(client)}, opts...)
	return New("client-id", "client-secret", "http://example.com/callback", allOpts...), server, emailTransport
}

func TestGitHubNewDefaultScopes(t *testing.T) {
	p := New("id", "secret", "redirect")
	want := []string{"read:user", "user:email"}
	if !reflect.DeepEqual(p.config.Scopes, want) {
		t.Fatalf("Scopes = %#v, want %#v", p.config.Scopes, want)
	}
}

func TestGitHubNewWithScopes(t *testing.T) {
	p := New("id", "secret", "redirect", WithScopes("custom"))
	if !reflect.DeepEqual(p.config.Scopes, []string{"custom"}) {
		t.Fatalf("Scopes = %#v", p.config.Scopes)
	}
}

func TestGitHubNewWithAdditionalScopes(t *testing.T) {
	p := New("id", "secret", "redirect", WithAdditionalScopes("repo"))
	want := []string{"read:user", "user:email", "repo"}
	if !reflect.DeepEqual(p.config.Scopes, want) {
		t.Fatalf("Scopes = %#v, want %#v", p.config.Scopes, want)
	}
}

func TestGitHubNewWithEndpoint(t *testing.T) {
	endpoint := oauth2.Endpoint{AuthURL: "https://example.com/auth", TokenURL: "https://example.com/token"}
	p := New("id", "secret", "redirect", WithEndpoint(endpoint))
	if p.config.Endpoint != endpoint {
		t.Fatalf("Endpoint = %#v, want %#v", p.config.Endpoint, endpoint)
	}
}

func TestGitHubNewWithUserInfoURL(t *testing.T) {
	p := New("id", "secret", "redirect", WithUserInfoURL("https://example.com/userinfo"))
	if p.userInfoURL != "https://example.com/userinfo" {
		t.Fatalf("userInfoURL = %q", p.userInfoURL)
	}
}

func TestGitHubNewWithHTTPClient(t *testing.T) {
	client := &http.Client{}
	p := New("id", "secret", "redirect", WithHTTPClient(client))
	if p.httpClient != client {
		t.Fatal("HTTPClient was not stored")
	}
}

func TestGitHubNewWithAuthCodeOptions(t *testing.T) {
	p := New("id", "secret", "redirect", WithAuthCodeOptions(oauth2.SetAuthURLParam("allow_signup", "false")))
	if len(p.authCodeOptions) != 1 {
		t.Fatalf("authCodeOptions len = %d, want 1", len(p.authCodeOptions))
	}
}

func TestGitHubName(t *testing.T) {
	if got := New("id", "secret", "redirect").Name(); got != "github" {
		t.Fatalf("Name() = %q, want github", got)
	}
}

func TestGitHubBeginAuthIncludesState(t *testing.T) {
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

func TestGitHubBeginAuthIncludesCustomOptions(t *testing.T) {
	p := New("id", "secret", "http://example.com/callback",
		WithEndpoint(oauth2.Endpoint{AuthURL: "https://example.com/auth", TokenURL: "https://example.com/token"}),
		WithAuthCodeOptions(oauth2.SetAuthURLParam("allow_signup", "false")),
	)
	authURL, err := p.BeginAuth("state")
	if err != nil {
		t.Fatalf("BeginAuth() error = %v", err)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got := parsed.Query().Get("allow_signup"); got != "false" {
		t.Fatalf("allow_signup = %q, want false", got)
	}
}

func TestGitHubCompleteAuthRequiresCode(t *testing.T) {
	p := New("id", "secret", "redirect")
	_, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback", nil))
	if !errors.Is(err, goauth.ErrMissingCode) {
		t.Fatalf("CompleteAuth() error = %v, want %v", err, goauth.ErrMissingCode)
	}
}

func TestGitHubCompleteAuthFetchesUserInfo(t *testing.T) {
	p, server, _ := newGitHubTestProvider(t, `{"id":123,"email":"user@example.com"}`, `[]`, http.StatusOK)
	defer server.Close()
	if _, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil)); err != nil {
		t.Fatalf("CompleteAuth() error = %v", err)
	}
}

func TestGitHubCompleteAuthMapsIdentity(t *testing.T) {
	p, server, _ := newGitHubTestProvider(t, `{"id":123,"email":"user@example.com","login":"octo","name":"Octo","avatar_url":"https://example.com/avatar.png"}`, `[]`, http.StatusOK)
	defer server.Close()
	got, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil))
	if err != nil {
		t.Fatalf("CompleteAuth() error = %v", err)
	}
	want := goauth.Identity{ID: "123", Email: "user@example.com", Username: "octo", Name: "Octo", AvatarURL: "https://example.com/avatar.png", Provider: "github"}
	if got.Identity != want {
		t.Fatalf("Identity = %#v, want %#v", got.Identity, want)
	}
}

func TestGitHubCompleteAuthSetsProvider(t *testing.T) {
	p, server, _ := newGitHubTestProvider(t, `{"id":123,"email":"user@example.com"}`, `[]`, http.StatusOK)
	defer server.Close()
	got, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil))
	if err != nil {
		t.Fatalf("CompleteAuth() error = %v", err)
	}
	if got.Identity.Provider != "github" {
		t.Fatalf("Provider = %q, want github", got.Identity.Provider)
	}
}

func TestGitHubCompleteAuthReturnsCredentials(t *testing.T) {
	p, server, _ := newGitHubTestProvider(t, `{"id":123,"email":"user@example.com"}`, `[]`, http.StatusOK)
	defer server.Close()
	got, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil))
	if err != nil {
		t.Fatalf("CompleteAuth() error = %v", err)
	}
	if got.Credentials.AccessToken != "access-token" || got.Credentials.RefreshToken != "refresh-token" || got.Credentials.ExpiresAt.IsZero() {
		t.Fatalf("Credentials = %#v", got.Credentials)
	}
}

func TestGitHubCompleteAuthPreservesRawData(t *testing.T) {
	p, server, _ := newGitHubTestProvider(t, `{"id":123,"email":"user@example.com"}`, `[]`, http.StatusOK)
	defer server.Close()
	got, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil))
	if err != nil {
		t.Fatalf("CompleteAuth() error = %v", err)
	}
	if got.RawData["email"] != "user@example.com" {
		t.Fatalf("RawData = %#v", got.RawData)
	}
}

func TestGitHubCompleteAuthRequiresUserID(t *testing.T) {
	p, server, _ := newGitHubTestProvider(t, `{"email":"user@example.com"}`, `[]`, http.StatusOK)
	defer server.Close()
	_, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil))
	if !errors.Is(err, goauth.ErrMissingUserID) {
		t.Fatalf("CompleteAuth() error = %v, want %v", err, goauth.ErrMissingUserID)
	}
}

func TestGitHubCompleteAuthReturnsOAuthErrors(t *testing.T) {
	p, server, _ := newGitHubTestProvider(t, `{"id":123,"email":"user@example.com"}`, `[]`, http.StatusOK)
	defer server.Close()
	_, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=bad", nil))
	if err == nil {
		t.Fatal("CompleteAuth() exchange error = nil, want error")
	}

	p, server, _ = newGitHubTestProvider(t, `nope`, `[]`, http.StatusOK)
	defer server.Close()
	_, err = p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil))
	if err == nil {
		t.Fatal("CompleteAuth() userinfo error = nil, want error")
	}
}

func TestGitHubCompleteAuthSkipsEmailEndpointWhenEmailPresent(t *testing.T) {
	p, server, transport := newGitHubTestProvider(t, `{"id":123,"email":"user@example.com"}`, `[{"email":"other@example.com","primary":true,"verified":true}]`, http.StatusOK)
	defer server.Close()
	if _, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil)); err != nil {
		t.Fatalf("CompleteAuth() error = %v", err)
	}
	if transport.emailCalls != 0 {
		t.Fatalf("email endpoint calls = %d, want 0", transport.emailCalls)
	}
}

func TestGitHubCompleteAuthFetchesPrimaryEmail(t *testing.T) {
	p, server, transport := newGitHubTestProvider(t, `{"id":123,"email":""}`, `[{"email":"primary@example.com","primary":true,"verified":true}]`, http.StatusOK)
	defer server.Close()
	if _, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil)); err != nil {
		t.Fatalf("CompleteAuth() error = %v", err)
	}
	if transport.emailCalls != 1 {
		t.Fatalf("email endpoint calls = %d, want 1", transport.emailCalls)
	}
}

func TestGitHubCompleteAuthUsesPrimaryVerifiedEmail(t *testing.T) {
	p, server, _ := newGitHubTestProvider(t, `{"id":123,"email":""}`, `[
		{"email":"secondary@example.com","primary":false,"verified":true},
		{"email":"primary@example.com","primary":true,"verified":true}
	]`, http.StatusOK)
	defer server.Close()
	got, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil))
	if err != nil {
		t.Fatalf("CompleteAuth() error = %v", err)
	}
	if got.Identity.Email != "primary@example.com" {
		t.Fatalf("Email = %q, want primary@example.com", got.Identity.Email)
	}
}

func TestGitHubCompleteAuthAllowsNoPrimaryVerifiedEmail(t *testing.T) {
	p, server, _ := newGitHubTestProvider(t, `{"id":123,"email":""}`, `[{"email":"primary@example.com","primary":true,"verified":false}]`, http.StatusOK)
	defer server.Close()
	got, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil))
	if err != nil {
		t.Fatalf("CompleteAuth() error = %v", err)
	}
	if got.Identity.Email != "" {
		t.Fatalf("Email = %q, want empty", got.Identity.Email)
	}
}

func TestGitHubCompleteAuthReturnsEmailEndpointStatusError(t *testing.T) {
	p, server, _ := newGitHubTestProvider(t, `{"id":123,"email":""}`, `nope`, http.StatusInternalServerError)
	defer server.Close()
	_, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil))
	if err == nil {
		t.Fatal("CompleteAuth() error = nil, want email endpoint status error")
	}
}

func TestGitHubCompleteAuthReturnsEmailEndpointJSONError(t *testing.T) {
	p, server, _ := newGitHubTestProvider(t, `{"id":123,"email":""}`, `{`, http.StatusOK)
	defer server.Close()
	_, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil))
	if err == nil {
		t.Fatal("CompleteAuth() error = nil, want email endpoint JSON error")
	}
}
