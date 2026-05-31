package auth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hazefyro/auth"
)

type fakeProvider struct {
	name           string
	beginState     string
	beginURL       string
	beginErr       error
	completeCalled bool
	completeErr    error
	result         auth.AuthResult
}

func (p *fakeProvider) Name() string { return p.name }

func (p *fakeProvider) BeginAuth(state string) (string, error) {
	p.beginState = state
	if p.beginErr != nil {
		return "", p.beginErr
	}
	if p.beginURL != "" {
		return p.beginURL, nil
	}
	return "/provider/auth?state=" + state, nil
}

func (p *fakeProvider) CompleteAuth(r *http.Request) (auth.AuthResult, error) {
	p.completeCalled = true
	if p.completeErr != nil {
		return auth.AuthResult{}, p.completeErr
	}
	if p.result.Identity.ID != "" {
		return p.result, nil
	}
	return auth.AuthResult{
		Identity:    auth.Identity{ID: "user-1", Provider: p.name},
		Credentials: auth.Credentials{AccessToken: "access-token"},
		RawData:     auth.RawData{"id": "user-1"},
	}, nil
}

type fakeStateStore struct {
	storeState     string
	storeProvider  string
	storeErr       error
	verifyState    string
	verifyProvider string
	verifyErr      error
	clearProvider  string
}

func (s *fakeStateStore) Store(w http.ResponseWriter, r *http.Request, state, provider string) error {
	s.storeState = state
	s.storeProvider = provider
	return s.storeErr
}

func (s *fakeStateStore) Verify(r *http.Request, state, provider string) error {
	s.verifyState = state
	s.verifyProvider = provider
	return s.verifyErr
}

func (s *fakeStateStore) Clear(w http.ResponseWriter, provider string) {
	s.clearProvider = provider
}

func newTestRegistry(t *testing.T, p *fakeProvider, s *fakeStateStore) *auth.Registry {
	t.Helper()
	r, err := auth.New(auth.WithStateStore(s))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := r.Register(p); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	return r
}

func TestNewRequiresStateStore(t *testing.T) {
	r, err := auth.New()
	if err == nil {
		t.Fatal("New() error = nil, want error")
	}
	if r != nil {
		t.Fatalf("New() registry = %#v, want nil", r)
	}
}

func TestNewWithStateStore(t *testing.T) {
	store := &fakeStateStore{}
	r, err := auth.New(auth.WithStateStore(store))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := r.Register(&fakeProvider{name: "google"}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if err := r.BeginAuth(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), "google"); err != nil {
		t.Fatalf("BeginAuth() error = %v", err)
	}
	if store.storeProvider != "google" {
		t.Fatal("New() did not use provided StateStore")
	}
}

func TestRegisterAcceptsValidProviderNames(t *testing.T) {
	r, err := auth.New(auth.WithStateStore(&fakeStateStore{}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for _, name := range []string{"google", "github_1", "discord-test", "A0_-"} {
		if err := r.Register(&fakeProvider{name: name}); err != nil {
			t.Fatalf("Register(%q) error = %v", name, err)
		}
	}
}

func TestRegisterRejectsInvalidProviderNames(t *testing.T) {
	for _, name := range []string{"", "bad name", "bad/name", "bad.name"} {
		r, err := auth.New(auth.WithStateStore(&fakeStateStore{}))
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if err := r.Register(&fakeProvider{name: name}); err == nil {
			t.Fatalf("Register(%q) error = nil, want error", name)
		}
	}
}

func TestRegisterRejectsDuplicateProviders(t *testing.T) {
	r, err := auth.New(auth.WithStateStore(&fakeStateStore{}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := r.Register(&fakeProvider{name: "google"}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if err := r.Register(&fakeProvider{name: "google"}); err == nil {
		t.Fatal("Register() duplicate error = nil, want error")
	}
}

func TestGetReturnsRegisteredProvider(t *testing.T) {
	p := &fakeProvider{name: "google"}
	r := newTestRegistry(t, p, &fakeStateStore{})
	got, err := r.Get("google")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got != p {
		t.Fatal("Get() returned wrong provider")
	}
}

func TestGetReturnsErrProviderNotFound(t *testing.T) {
	r, err := auth.New(auth.WithStateStore(&fakeStateStore{}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = r.Get("missing")
	if !errors.Is(err, auth.ErrProviderNotFound) {
		t.Fatalf("Get() error = %v, want %v", err, auth.ErrProviderNotFound)
	}
}

func TestBeginAuthReturnsErrProviderNotFound(t *testing.T) {
	r, err := auth.New(auth.WithStateStore(&fakeStateStore{}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = r.BeginAuth(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), "missing")
	if !errors.Is(err, auth.ErrProviderNotFound) {
		t.Fatalf("BeginAuth() error = %v, want %v", err, auth.ErrProviderNotFound)
	}
}

func TestBeginAuthCallsProviderWithGeneratedState(t *testing.T) {
	p := &fakeProvider{name: "google"}
	r := newTestRegistry(t, p, &fakeStateStore{})
	err := r.BeginAuth(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), "google")
	if err != nil {
		t.Fatalf("BeginAuth() error = %v", err)
	}
	if len(p.beginState) != 32 {
		t.Fatalf("state length = %d, want 32", len(p.beginState))
	}
}

func TestBeginAuthStoresGeneratedState(t *testing.T) {
	p := &fakeProvider{name: "google"}
	store := &fakeStateStore{}
	r := newTestRegistry(t, p, store)
	err := r.BeginAuth(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), "google")
	if err != nil {
		t.Fatalf("BeginAuth() error = %v", err)
	}
	if store.storeState == "" || store.storeState != p.beginState {
		t.Fatalf("stored state = %q, provider state = %q", store.storeState, p.beginState)
	}
	if store.storeProvider != "google" {
		t.Fatalf("stored provider = %q, want google", store.storeProvider)
	}
}

func TestBeginAuthRedirectsToProviderURL(t *testing.T) {
	p := &fakeProvider{name: "google", beginURL: "https://provider.example/auth"}
	r := newTestRegistry(t, p, &fakeStateStore{})
	w := httptest.NewRecorder()
	err := r.BeginAuth(w, httptest.NewRequest(http.MethodGet, "/", nil), "google")
	if err != nil {
		t.Fatalf("BeginAuth() error = %v", err)
	}
	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusTemporaryRedirect)
	}
	if got := w.Header().Get("Location"); got != p.beginURL {
		t.Fatalf("Location = %q, want %q", got, p.beginURL)
	}
}

func TestBeginAuthReturnsProviderError(t *testing.T) {
	want := errors.New("begin failed")
	p := &fakeProvider{name: "google", beginErr: want}
	store := &fakeStateStore{}
	r := newTestRegistry(t, p, store)
	err := r.BeginAuth(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), "google")
	if !errors.Is(err, want) {
		t.Fatalf("BeginAuth() error = %v, want %v", err, want)
	}
	if store.storeState != "" {
		t.Fatalf("stored state = %q, want empty", store.storeState)
	}
}

func TestBeginAuthReturnsStateStoreError(t *testing.T) {
	want := errors.New("store failed")
	p := &fakeProvider{name: "google"}
	store := &fakeStateStore{storeErr: want}
	r := newTestRegistry(t, p, store)
	w := httptest.NewRecorder()
	err := r.BeginAuth(w, httptest.NewRequest(http.MethodGet, "/", nil), "google")
	if !errors.Is(err, want) {
		t.Fatalf("BeginAuth() error = %v, want %v", err, want)
	}
	if w.Header().Get("Location") != "" {
		t.Fatal("BeginAuth() redirected after store error")
	}
}

func TestCallbackRequiresNextHandler(t *testing.T) {
	r := newTestRegistry(t, &fakeProvider{name: "google"}, &fakeStateStore{})
	err := r.Callback(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/callback", nil), "google", nil)
	if err == nil {
		t.Fatal("Callback() error = nil, want error")
	}
}

func TestCallbackReturnsErrProviderNotFound(t *testing.T) {
	r, err := auth.New(auth.WithStateStore(&fakeStateStore{}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = r.Callback(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/callback", nil), "missing", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if !errors.Is(err, auth.ErrProviderNotFound) {
		t.Fatalf("Callback() error = %v, want %v", err, auth.ErrProviderNotFound)
	}
}

func TestCallbackReturnsCallbackErrorFromQuery(t *testing.T) {
	r := newTestRegistry(t, &fakeProvider{name: "google"}, &fakeStateStore{})
	req := httptest.NewRequest(http.MethodGet, "/callback?error=access_denied&error_description=nope", nil)
	err := r.Callback(httptest.NewRecorder(), req, "google", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	var callbackErr *auth.CallbackError
	if !errors.As(err, &callbackErr) {
		t.Fatalf("Callback() error = %T, want *CallbackError", err)
	}
	if callbackErr.Code != "access_denied" || callbackErr.Description != "nope" {
		t.Fatalf("CallbackError = %#v", callbackErr)
	}
}

func TestCallbackVerifiesStateBeforeCompleteAuth(t *testing.T) {
	p := &fakeProvider{name: "google"}
	store := &fakeStateStore{}
	r := newTestRegistry(t, p, store)
	req := httptest.NewRequest(http.MethodGet, "/callback?state=abc&code=ok", nil)
	err := r.Callback(httptest.NewRecorder(), req, "google", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err != nil {
		t.Fatalf("Callback() error = %v", err)
	}
	if store.verifyState != "abc" || store.verifyProvider != "google" {
		t.Fatalf("Verify called with state=%q provider=%q", store.verifyState, store.verifyProvider)
	}
	if !p.completeCalled {
		t.Fatal("CompleteAuth was not called")
	}
}

func TestCallbackReturnsErrStateMismatch(t *testing.T) {
	p := &fakeProvider{name: "google"}
	store := &fakeStateStore{verifyErr: auth.ErrStateMismatch}
	r := newTestRegistry(t, p, store)
	req := httptest.NewRequest(http.MethodGet, "/callback?state=bad&code=ok", nil)
	err := r.Callback(httptest.NewRecorder(), req, "google", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if !errors.Is(err, auth.ErrStateMismatch) {
		t.Fatalf("Callback() error = %v, want %v", err, auth.ErrStateMismatch)
	}
	if p.completeCalled {
		t.Fatal("CompleteAuth called after state mismatch")
	}
}

func TestCallbackClearsStateAfterVerification(t *testing.T) {
	store := &fakeStateStore{}
	r := newTestRegistry(t, &fakeProvider{name: "google"}, store)
	req := httptest.NewRequest(http.MethodGet, "/callback?state=abc&code=ok", nil)
	err := r.Callback(httptest.NewRecorder(), req, "google", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err != nil {
		t.Fatalf("Callback() error = %v", err)
	}
	if store.clearProvider != "google" {
		t.Fatalf("clear provider = %q, want google", store.clearProvider)
	}
}

func TestCallbackCallsCompleteAuth(t *testing.T) {
	p := &fakeProvider{name: "google"}
	r := newTestRegistry(t, p, &fakeStateStore{})
	req := httptest.NewRequest(http.MethodGet, "/callback?state=abc&code=ok", nil)
	err := r.Callback(httptest.NewRecorder(), req, "google", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err != nil {
		t.Fatalf("Callback() error = %v", err)
	}
	if !p.completeCalled {
		t.Fatal("CompleteAuth was not called")
	}
}

func TestCallbackReturnsCompleteAuthError(t *testing.T) {
	want := errors.New("complete failed")
	p := &fakeProvider{name: "google", completeErr: want}
	r := newTestRegistry(t, p, &fakeStateStore{})
	nextCalled := false
	req := httptest.NewRequest(http.MethodGet, "/callback?state=abc&code=ok", nil)
	err := r.Callback(httptest.NewRecorder(), req, "google", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		nextCalled = true
	}))
	if !errors.Is(err, want) {
		t.Fatalf("Callback() error = %v, want %v", err, want)
	}
	if nextCalled {
		t.Fatal("next handler called after CompleteAuth error")
	}
}

func TestCallbackStoresAuthResultInContext(t *testing.T) {
	result := auth.AuthResult{
		Identity:    auth.Identity{ID: "user-1", Provider: "google"},
		Credentials: auth.Credentials{AccessToken: "access-token"},
		RawData:     auth.RawData{"id": "user-1"},
	}
	p := &fakeProvider{name: "google", result: result}
	r := newTestRegistry(t, p, &fakeStateStore{})
	req := httptest.NewRequest(http.MethodGet, "/callback?state=abc&code=ok", nil)
	nextCalled := false
	err := r.Callback(httptest.NewRecorder(), req, "google", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		identity, err := auth.IdentityFromContext(r.Context())
		if err != nil {
			t.Fatalf("IdentityFromContext() error = %v", err)
		}
		credentials, err := auth.CredentialsFromContext(r.Context())
		if err != nil {
			t.Fatalf("CredentialsFromContext() error = %v", err)
		}
		raw, err := auth.RawDataFromContext(r.Context())
		if err != nil {
			t.Fatalf("RawDataFromContext() error = %v", err)
		}
		if identity.ID != result.Identity.ID || credentials.AccessToken != result.Credentials.AccessToken || raw["id"] != result.RawData["id"] {
			t.Fatalf("auth result accessors returned identity=%#v credentials=%#v raw=%#v", identity, credentials, raw)
		}
	}))
	if err != nil {
		t.Fatalf("Callback() error = %v", err)
	}
	if !nextCalled {
		t.Fatal("next handler was not called")
	}
}

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
	if _, err := auth.CredentialsFromContext(ctx); err == nil {
		t.Fatal("CredentialsFromContext() error = nil, want error")
	}
}

func TestCredentialsFromContextMissing(t *testing.T) {
	_, err := auth.CredentialsFromContext(context.Background())
	if err == nil {
		t.Fatal("CredentialsFromContext() error = nil, want error")
	}
}

func TestCredentialsFromContextEmptyAccessToken(t *testing.T) {
	ctx := auth.StoreIdentityInContext(context.Background(), auth.Identity{ID: "user-1"})
	_, err := auth.CredentialsFromContext(ctx)
	if err == nil {
		t.Fatal("CredentialsFromContext() error = nil, want error")
	}
}

func TestCredentialsFromContextReturnsCredentials(t *testing.T) {
	result := auth.AuthResult{
		Identity:    auth.Identity{ID: "user-1"},
		Credentials: auth.Credentials{AccessToken: "access"},
	}
	p := &fakeProvider{name: "google", result: result}
	r := newTestRegistry(t, p, &fakeStateStore{})
	err := r.Callback(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/callback?state=abc&code=ok", nil), "google", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, err := auth.CredentialsFromContext(r.Context())
		if err != nil {
			t.Fatalf("CredentialsFromContext() error = %v", err)
		}
		if got.AccessToken != "access" {
			t.Fatalf("access token = %q, want access", got.AccessToken)
		}
	}))
	if err != nil {
		t.Fatalf("Callback() error = %v", err)
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

func TestRawDataFromContextMissing(t *testing.T) {
	_, err := auth.RawDataFromContext(context.Background())
	if err == nil {
		t.Fatal("RawDataFromContext() error = nil, want error")
	}
}

func TestRawDataFromContextReturnsRawData(t *testing.T) {
	result := auth.AuthResult{
		Identity: auth.Identity{ID: "user-1"},
		RawData:  auth.RawData{"id": "user-1"},
	}
	p := &fakeProvider{name: "google", result: result}
	r := newTestRegistry(t, p, &fakeStateStore{})
	err := r.Callback(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/callback?state=abc&code=ok", nil), "google", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, err := auth.RawDataFromContext(r.Context())
		if err != nil {
			t.Fatalf("RawDataFromContext() error = %v", err)
		}
		if got["id"] != "user-1" {
			t.Fatalf("raw id = %v, want user-1", got["id"])
		}
	}))
	if err != nil {
		t.Fatalf("Callback() error = %v", err)
	}
}

func TestAuthRequiredUnauthorized(t *testing.T) {
	r := &auth.Registry{}
	w := httptest.NewRecorder()
	r.AuthRequired(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
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
	r := &auth.Registry{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(auth.StoreIdentityInContext(req.Context(), auth.Identity{ID: "user-1"}))
	nextCalled := false
	r.AuthRequired(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		nextCalled = true
	})).ServeHTTP(httptest.NewRecorder(), req)
	if !nextCalled {
		t.Fatal("next handler was not called")
	}
}

func TestCallbackErrorErrorWithDescription(t *testing.T) {
	err := (&auth.CallbackError{Code: "access_denied", Description: "nope"}).Error()
	want := "oauth callback error: access_denied: nope"
	if err != want {
		t.Fatalf("Error() = %q, want %q", err, want)
	}
}

func TestCallbackErrorErrorWithoutDescription(t *testing.T) {
	err := (&auth.CallbackError{Code: "access_denied"}).Error()
	want := "oauth callback error: access_denied"
	if err != want {
		t.Fatalf("Error() = %q, want %q", err, want)
	}
}

func TestRegistryOAuthFlow(t *testing.T) {
	p := &fakeProvider{name: "google"}
	store := &fakeStateStore{}
	r := newTestRegistry(t, p, store)

	beginReq := httptest.NewRequest(http.MethodGet, "/begin", nil)
	beginRes := httptest.NewRecorder()
	if err := r.BeginAuth(beginRes, beginReq, "google"); err != nil {
		t.Fatalf("BeginAuth() error = %v", err)
	}

	callbackReq := httptest.NewRequest(http.MethodGet, "/callback?state="+store.storeState+"&code=ok", nil)
	nextCalled := false
	err := r.Callback(httptest.NewRecorder(), callbackReq, "google", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		if _, err := auth.IdentityFromContext(r.Context()); err != nil {
			t.Fatalf("IdentityFromContext() error = %v", err)
		}
	}))
	if err != nil {
		t.Fatalf("Callback() error = %v", err)
	}
	if !nextCalled {
		t.Fatal("next handler was not called")
	}
}
