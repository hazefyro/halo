package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hazefyro/auth"
)

func TestIdentityFromContextMissing(t *testing.T) {
	_, err := auth.IdentityFromContext(context.Background())
	if err == nil {
		t.Fatal("IdentityFromContext() error = nil, want error")
	}
}

func TestIdentityFromContextReturnsIdentity(t *testing.T) {
	ctx := auth.StoreIdentityInContext(context.Background(), auth.Identity{ID: "user-1"})
	got, err := auth.IdentityFromContext(ctx)
	if err != nil {
		t.Fatalf("IdentityFromContext() error = %v", err)
	}
	if got.ID != "user-1" {
		t.Fatalf("identity ID = %q, want user-1", got.ID)
	}
}

func TestStoreIdentityInContext(t *testing.T) {
	ctx := auth.StoreIdentityInContext(context.Background(), auth.Identity{ID: "user-1", Provider: "google"})
	got, err := auth.IdentityFromContext(ctx)
	if err != nil {
		t.Fatalf("IdentityFromContext() error = %v", err)
	}
	if got.ID != "user-1" || got.Provider != "google" {
		t.Fatalf("identity = %#v", got)
	}
}

func TestProviderFromContextReturnsProvider(t *testing.T) {
	ctx := auth.StoreIdentityInContext(context.Background(), auth.Identity{Provider: "google"})
	if got := auth.ProviderFromContext(ctx); got != "google" {
		t.Fatalf("ProviderFromContext() = %q, want google", got)
	}
}

func TestProviderFromContextMissing(t *testing.T) {
	if got := auth.ProviderFromContext(context.Background()); got != "" {
		t.Fatalf("ProviderFromContext() = %q, want empty", got)
	}
}

func TestAuthRequiredUnauthorized(t *testing.T) {
	w := httptest.NewRecorder()
	auth.AuthRequired(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler called")
	})).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if !strings.Contains(w.Body.String(), "unauthorized") {
		t.Fatalf("body = %q, want unauthorized", w.Body.String())
	}
}

func TestAuthRequiredAllowsAuthenticatedRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(auth.StoreIdentityInContext(req.Context(), auth.Identity{ID: "user-1"}))
	nextCalled := false
	auth.AuthRequired(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		nextCalled = true
	})).ServeHTTP(httptest.NewRecorder(), req)
	if !nextCalled {
		t.Fatal("next handler was not called")
	}
}
