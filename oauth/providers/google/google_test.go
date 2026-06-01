package google_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/hazefyro/halo"
	"github.com/hazefyro/halo/oauth"
	"github.com/hazefyro/halo/oauth/providers/google"
	"golang.org/x/oauth2"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

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

func newGoogleTestProvider(t *testing.T, body string, opts ...google.Option) (*google.Provider, *httptest.Server) {
	t.Helper()
	server, endpoint := newGoogleOAuthServer(t, http.StatusOK, body)
	allOpts := append([]google.Option{google.WithEndpoint(endpoint), google.WithUserInfoURL(server.URL + "/userinfo"), google.WithHTTPClient(server.Client())}, opts...)
	return google.New("client-id", "client-secret", "http://example.com/callback", allOpts...), server
}

func queryFromBeginAuth(t *testing.T, p *google.Provider) url.Values {
	t.Helper()
	authURL, err := p.BeginAuth("state", "")
	if err != nil {
		t.Fatalf("BeginAuth() error = %v", err)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	return parsed.Query()
}

func TestGoogleNewDefaultScopes(t *testing.T) {
	p := google.New("id", "secret", "redirect")
	want := []string{"openid", "email", "profile"}
	if got := strings.Fields(queryFromBeginAuth(t, p).Get("scope")); !reflect.DeepEqual(got, want) {
		t.Fatalf("Scopes = %#v, want %#v", got, want)
	}
}

func TestGoogleNewWithScopes(t *testing.T) {
	p := google.New("id", "secret", "redirect", google.WithScopes("custom"))
	if got := strings.Fields(queryFromBeginAuth(t, p).Get("scope")); !reflect.DeepEqual(got, []string{"custom"}) {
		t.Fatalf("Scopes = %#v", got)
	}
}

func TestGoogleNewWithAdditionalScopes(t *testing.T) {
	p := google.New("id", "secret", "redirect", google.WithAdditionalScopes("calendar"))
	want := []string{"openid", "email", "profile", "calendar"}
	if got := strings.Fields(queryFromBeginAuth(t, p).Get("scope")); !reflect.DeepEqual(got, want) {
		t.Fatalf("Scopes = %#v, want %#v", got, want)
	}
}

func TestGoogleNewWithEndpoint(t *testing.T) {
	endpoint := oauth2.Endpoint{AuthURL: "https://example.com/auth", TokenURL: "https://example.com/token"}
	p := google.New("id", "secret", "redirect", google.WithEndpoint(endpoint))
	authURL, err := p.BeginAuth("state", "")
	if err != nil {
		t.Fatalf("BeginAuth() error = %v", err)
	}
	if !strings.HasPrefix(authURL, endpoint.AuthURL+"?") {
		t.Fatalf("auth URL = %q, want endpoint %q", authURL, endpoint.AuthURL)
	}
}

func TestGoogleNewWithUserInfoURL(t *testing.T) {
	server, endpoint := newGoogleOAuthServer(t, http.StatusOK, `{"sub":"123"}`)
	defer server.Close()
	p := google.New("id", "secret", "redirect", google.WithEndpoint(endpoint), google.WithUserInfoURL(server.URL+"/userinfo"), google.WithHTTPClient(server.Client()))
	if _, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil), ""); err != nil {
		t.Fatalf("CompleteAuth() error = %v", err)
	}
}

func TestGoogleNewWithHTTPClient(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/token":
			return jsonResponse(http.StatusOK, `{"access_token":"access-token","token_type":"Bearer","expires_in":3600}`), nil
		case "/userinfo":
			return jsonResponse(http.StatusOK, `{"sub":"123"}`), nil
		default:
			return jsonResponse(http.StatusNotFound, `{}`), nil
		}
	})}
	p := google.New("id", "secret", "redirect",
		google.WithEndpoint(oauth2.Endpoint{AuthURL: "http://oauth.test/auth", TokenURL: "http://oauth.test/token"}),
		google.WithUserInfoURL("http://oauth.test/userinfo"),
		google.WithHTTPClient(client),
	)
	if _, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil), ""); err != nil {
		t.Fatalf("CompleteAuth() error = %v", err)
	}
}

func TestGoogleNewWithAuthCodeOptions(t *testing.T) {
	p := google.New("id", "secret", "redirect", google.WithAuthCodeOptions(oauth2.SetAuthURLParam("prompt", "consent")))
	if got := queryFromBeginAuth(t, p).Get("prompt"); got != "consent" {
		t.Fatalf("prompt = %q, want consent", got)
	}
}

func TestGoogleBeginAuthIncludesPKCEChallenge(t *testing.T) {
	p := google.New("id", "secret", "redirect", google.WithEndpoint(oauth2.Endpoint{AuthURL: "https://example.com/auth", TokenURL: "https://example.com/token"}))
	authURL, err := p.BeginAuth("state", "my-verifier")
	if err != nil {
		t.Fatalf("BeginAuth() error = %v", err)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if parsed.Query().Get("code_challenge") == "" {
		t.Fatal("code_challenge missing from auth URL")
	}
	if got := parsed.Query().Get("code_challenge_method"); got != "S256" {
		t.Fatalf("code_challenge_method = %q, want S256", got)
	}
}

func TestGoogleBeginAuthOmitsPKCEWithoutVerifier(t *testing.T) {
	p := google.New("id", "secret", "redirect", google.WithEndpoint(oauth2.Endpoint{AuthURL: "https://example.com/auth", TokenURL: "https://example.com/token"}))
	authURL, err := p.BeginAuth("state", "")
	if err != nil {
		t.Fatalf("BeginAuth() error = %v", err)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got := parsed.Query().Get("code_challenge"); got != "" {
		t.Fatalf("code_challenge = %q, want empty", got)
	}
}

func TestGoogleCompleteAuthSendsCodeVerifier(t *testing.T) {
	var gotVerifier string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/token":
			body, _ := io.ReadAll(r.Body)
			vals, _ := url.ParseQuery(string(body))
			gotVerifier = vals.Get("code_verifier")
			return jsonResponse(http.StatusOK, `{"access_token":"access-token","token_type":"Bearer","expires_in":3600}`), nil
		case "/userinfo":
			return jsonResponse(http.StatusOK, `{"sub":"123"}`), nil
		default:
			return jsonResponse(http.StatusNotFound, `{}`), nil
		}
	})}
	p := google.New("id", "secret", "redirect",
		google.WithEndpoint(oauth2.Endpoint{AuthURL: "http://oauth.test/auth", TokenURL: "http://oauth.test/token"}),
		google.WithUserInfoURL("http://oauth.test/userinfo"),
		google.WithHTTPClient(client),
	)
	if _, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil), "my-verifier"); err != nil {
		t.Fatalf("CompleteAuth() error = %v", err)
	}
	if gotVerifier != "my-verifier" {
		t.Fatalf("code_verifier = %q, want my-verifier", gotVerifier)
	}
}

func TestGoogleName(t *testing.T) {
	if got := google.New("id", "secret", "redirect").Name(); got != "google" {
		t.Fatalf("Name() = %q, want google", got)
	}
}

func TestGoogleBeginAuthIncludesState(t *testing.T) {
	p := google.New("id", "secret", "http://example.com/callback", google.WithEndpoint(oauth2.Endpoint{AuthURL: "https://example.com/auth", TokenURL: "https://example.com/token"}))
	authURL, err := p.BeginAuth("state", "")
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
	p := google.New("id", "secret", "http://example.com/callback", google.WithEndpoint(oauth2.Endpoint{AuthURL: "https://example.com/auth", TokenURL: "https://example.com/token"}))
	authURL, err := p.BeginAuth("state", "")
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
	p := google.New("id", "secret", "http://example.com/callback",
		google.WithEndpoint(oauth2.Endpoint{AuthURL: "https://example.com/auth", TokenURL: "https://example.com/token"}),
		google.WithAuthCodeOptions(oauth2.SetAuthURLParam("prompt", "consent")),
	)
	authURL, err := p.BeginAuth("state", "")
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
	p := google.New("id", "secret", "redirect")
	_, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback", nil), "")
	if !errors.Is(err, oauth.ErrMissingCode) {
		t.Fatalf("CompleteAuth() error = %v, want %v", err, oauth.ErrMissingCode)
	}
}

func TestGoogleCompleteAuthFetchesUserInfo(t *testing.T) {
	p, server := newGoogleTestProvider(t, `{"sub":"123"}`)
	defer server.Close()
	if _, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil), ""); err != nil {
		t.Fatalf("CompleteAuth() error = %v", err)
	}
}

func TestGoogleCompleteAuthMapsIdentity(t *testing.T) {
	p, server := newGoogleTestProvider(t, `{"sub":"123","email":"user@example.com","email_verified":true,"name":"User","picture":"https://example.com/avatar.png"}`)
	defer server.Close()
	got, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil), "")
	if err != nil {
		t.Fatalf("CompleteAuth() error = %v", err)
	}
	want := halo.Identity{ID: "123", Email: "user@example.com", EmailVerified: true, Name: "User", AvatarURL: "https://example.com/avatar.png", Provider: "google"}
	if got.Identity != want {
		t.Fatalf("Identity = %#v, want %#v", got.Identity, want)
	}
}

func TestGoogleCompleteAuthSetsProvider(t *testing.T) {
	p, server := newGoogleTestProvider(t, `{"sub":"123"}`)
	defer server.Close()
	got, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil), "")
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
	got, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil), "")
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
	got, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil), "")
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
	_, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil), "")
	if !errors.Is(err, oauth.ErrMissingUserID) {
		t.Fatalf("CompleteAuth() error = %v, want %v", err, oauth.ErrMissingUserID)
	}
}

func TestGoogleCompleteAuthReturnsOAuthErrors(t *testing.T) {
	p, server := newGoogleTestProvider(t, `{"sub":"123"}`)
	defer server.Close()
	_, err := p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=bad", nil), "")
	if err == nil {
		t.Fatal("CompleteAuth() exchange error = nil, want error")
	}

	p, server = newGoogleTestProvider(t, `nope`)
	defer server.Close()
	_, err = p.CompleteAuth(httptest.NewRequest(http.MethodGet, "/callback?code=ok", nil), "")
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
