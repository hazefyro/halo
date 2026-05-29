package oauthutil

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func newOAuthTestServer(t *testing.T, userInfoStatus int, userInfoBody string) (*httptest.Server, *oauth2.Config, *int, *int) {
	t.Helper()
	tokenCalls := 0
	userInfoCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenCalls++
			if err := r.ParseForm(); err != nil {
				t.Fatalf("ParseForm() error = %v", err)
			}
			if r.Form.Get("code") == "bad-exchange" {
				http.Error(w, "bad code", http.StatusBadRequest)
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
			userInfoCalls++
			if auth := r.Header.Get("Authorization"); auth != "Bearer access-token" {
				t.Fatalf("Authorization = %q, want Bearer access-token", auth)
			}
			w.WriteHeader(userInfoStatus)
			_, _ = w.Write([]byte(userInfoBody))
		default:
			http.NotFound(w, r)
		}
	}))
	cfg := &oauth2.Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "http://example.com/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  server.URL + "/auth",
			TokenURL: server.URL + "/token",
		},
	}
	return server, cfg, &tokenCalls, &userInfoCalls
}

func TestFetchUserInfoExchangesCode(t *testing.T) {
	server, cfg, tokenCalls, _ := newOAuthTestServer(t, http.StatusOK, `{"id":"123"}`)
	defer server.Close()
	if _, _, err := FetchUserInfo(context.Background(), cfg, "ok", server.URL+"/userinfo"); err != nil {
		t.Fatalf("FetchUserInfo() error = %v", err)
	}
	if *tokenCalls != 1 {
		t.Fatalf("token calls = %d, want 1", *tokenCalls)
	}
}

func TestFetchUserInfoFetchesUserInfoWithTokenClient(t *testing.T) {
	server, cfg, _, userInfoCalls := newOAuthTestServer(t, http.StatusOK, `{"id":"123"}`)
	defer server.Close()
	if _, _, err := FetchUserInfo(context.Background(), cfg, "ok", server.URL+"/userinfo"); err != nil {
		t.Fatalf("FetchUserInfo() error = %v", err)
	}
	if *userInfoCalls != 1 {
		t.Fatalf("userinfo calls = %d, want 1", *userInfoCalls)
	}
}

func TestFetchUserInfoReturnsExchangeError(t *testing.T) {
	server, cfg, _, _ := newOAuthTestServer(t, http.StatusOK, `{"id":"123"}`)
	defer server.Close()
	_, _, err := FetchUserInfo(context.Background(), cfg, "bad-exchange", server.URL+"/userinfo")
	if err == nil {
		t.Fatal("FetchUserInfo() error = nil, want error")
	}
}

func TestFetchUserInfoReturnsHTTPError(t *testing.T) {
	cfg := &oauth2.Config{Endpoint: oauth2.Endpoint{TokenURL: "http://127.0.0.1:1/token"}}
	_, _, err := FetchUserInfo(context.Background(), cfg, "ok", "http://127.0.0.1:1/userinfo")
	if err == nil {
		t.Fatal("FetchUserInfo() error = nil, want error")
	}
}

func TestFetchUserInfoReturnsNon2xxError(t *testing.T) {
	server, cfg, _, _ := newOAuthTestServer(t, http.StatusTeapot, `nope`)
	defer server.Close()
	_, _, err := FetchUserInfo(context.Background(), cfg, "ok", server.URL+"/userinfo")
	if err == nil || !strings.Contains(err.Error(), "status 418") {
		t.Fatalf("FetchUserInfo() error = %v, want status 418", err)
	}
}

func TestFetchUserInfoUsesJSONNumber(t *testing.T) {
	server, cfg, _, _ := newOAuthTestServer(t, http.StatusOK, `{"id":12345678901234567890}`)
	defer server.Close()
	raw, _, err := FetchUserInfo(context.Background(), cfg, "ok", server.URL+"/userinfo")
	if err != nil {
		t.Fatalf("FetchUserInfo() error = %v", err)
	}
	if _, ok := raw["id"].(json.Number); !ok {
		t.Fatalf("id type = %T, want json.Number", raw["id"])
	}
}

func TestFetchUserInfoReturnsInvalidJSONError(t *testing.T) {
	server, cfg, _, _ := newOAuthTestServer(t, http.StatusOK, `{`)
	defer server.Close()
	_, _, err := FetchUserInfo(context.Background(), cfg, "ok", server.URL+"/userinfo")
	if err == nil {
		t.Fatal("FetchUserInfo() error = nil, want error")
	}
}

func TestFetchUserInfoLimitsResponseBody(t *testing.T) {
	server, cfg, _, _ := newOAuthTestServer(t, http.StatusOK, `{"payload":"`+strings.Repeat("x", 1<<20)+`"}`)
	defer server.Close()
	_, _, err := FetchUserInfo(context.Background(), cfg, "ok", server.URL+"/userinfo")
	if err == nil {
		t.Fatal("FetchUserInfo() error = nil, want error")
	}
}

func TestRefreshTokenReturnsCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-access","refresh_token":"new-refresh","token_type":"Bearer","expires_in":3600}`))
	}))
	defer server.Close()
	cfg := &oauth2.Config{Endpoint: oauth2.Endpoint{TokenURL: server.URL}}
	got, err := RefreshToken(context.Background(), cfg, "old-refresh")
	if err != nil {
		t.Fatalf("RefreshToken() error = %v", err)
	}
	if got.AccessToken != "new-access" || got.RefreshToken != "new-refresh" || got.ExpiresAt.IsZero() {
		t.Fatalf("credentials = %#v", got)
	}
}

func TestRefreshTokenKeepsOldRefreshToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-access","token_type":"Bearer","expires_in":3600}`))
	}))
	defer server.Close()
	cfg := &oauth2.Config{Endpoint: oauth2.Endpoint{TokenURL: server.URL}}
	got, err := RefreshToken(context.Background(), cfg, "old-refresh")
	if err != nil {
		t.Fatalf("RefreshToken() error = %v", err)
	}
	if got.RefreshToken != "old-refresh" {
		t.Fatalf("RefreshToken = %q, want old-refresh", got.RefreshToken)
	}
}

func TestRefreshTokenReturnsTokenSourceError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad refresh", http.StatusBadRequest)
	}))
	defer server.Close()
	cfg := &oauth2.Config{Endpoint: oauth2.Endpoint{TokenURL: server.URL}}
	_, err := RefreshToken(context.Background(), cfg, "old-refresh")
	if err == nil {
		t.Fatal("RefreshToken() error = nil, want error")
	}
	if errors.Is(err, context.Canceled) {
		t.Fatalf("RefreshToken() error = %v, want token source error", err)
	}
}
