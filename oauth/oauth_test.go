package oauth_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hazefyro/halo"
	"github.com/hazefyro/halo/oauth"
)

type fakeProvider struct {
	name             string
	beginState       string
	beginVerifier    string
	beginURL         string
	beginErr         error
	completeCalled   bool
	completeVerifier string
	completeErr      error
	result           oauth.AuthResult
}

func (p *fakeProvider) Name() string { return p.name }

func (p *fakeProvider) BeginAuth(state, verifier string) (string, error) {
	p.beginState = state
	p.beginVerifier = verifier
	if p.beginErr != nil {
		return "", p.beginErr
	}
	if p.beginURL != "" {
		return p.beginURL, nil
	}
	return "/provider/auth?state=" + state, nil
}

func (p *fakeProvider) CompleteAuth(r *http.Request, verifier string) (oauth.AuthResult, error) {
	p.completeCalled = true
	p.completeVerifier = verifier
	if p.completeErr != nil {
		return oauth.AuthResult{}, p.completeErr
	}
	if p.result.Identity.ID != "" {
		return p.result, nil
	}
	return oauth.AuthResult{
		Identity:    halo.Identity{ID: "user-1", Provider: p.name},
		Credentials: oauth.Credentials{AccessToken: "access-token"},
		RawData:     oauth.RawData{"id": "user-1"},
	}, nil
}

type fakeStateStore struct {
	storeState     string
	storeVerifier  string
	storeProvider  string
	storeErr       error
	verifyState    string
	verifyProvider string
	verifyVerifier string
	verifyErr      error
	clearProvider  string
}

func (s *fakeStateStore) Store(w http.ResponseWriter, r *http.Request, state, verifier, provider string) error {
	s.storeState = state
	s.storeVerifier = verifier
	s.storeProvider = provider
	return s.storeErr
}

func (s *fakeStateStore) Verify(r *http.Request, state, provider string) (string, error) {
	s.verifyState = state
	s.verifyProvider = provider
	return s.verifyVerifier, s.verifyErr
}

func (s *fakeStateStore) Clear(w http.ResponseWriter, provider string) {
	s.clearProvider = provider
}

func newTestRegistry(t *testing.T, p *fakeProvider, s *fakeStateStore) *oauth.Registry {
	t.Helper()
	r, err := oauth.New(oauth.WithStateStore(s))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := r.Register(p); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	return r
}

func TestNewRequiresStateStore(t *testing.T) {
	r, err := oauth.New()
	if err == nil {
		t.Fatal("New() error = nil, want error")
	}
	if r != nil {
		t.Fatalf("New() registry = %#v, want nil", r)
	}
}

func TestNewWithStateStore(t *testing.T) {
	store := &fakeStateStore{}
	r, err := oauth.New(oauth.WithStateStore(store))
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
	r, err := oauth.New(oauth.WithStateStore(&fakeStateStore{}))
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
		r, err := oauth.New(oauth.WithStateStore(&fakeStateStore{}))
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if err := r.Register(&fakeProvider{name: name}); err == nil {
			t.Fatalf("Register(%q) error = nil, want error", name)
		}
	}
}

func TestRegisterRejectsDuplicateProviders(t *testing.T) {
	r, err := oauth.New(oauth.WithStateStore(&fakeStateStore{}))
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
	r, err := oauth.New(oauth.WithStateStore(&fakeStateStore{}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = r.Get("missing")
	if !errors.Is(err, oauth.ErrProviderNotFound) {
		t.Fatalf("Get() error = %v, want %v", err, oauth.ErrProviderNotFound)
	}
}

func TestBeginAuthReturnsErrProviderNotFound(t *testing.T) {
	r, err := oauth.New(oauth.WithStateStore(&fakeStateStore{}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = r.BeginAuth(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), "missing")
	if !errors.Is(err, oauth.ErrProviderNotFound) {
		t.Fatalf("BeginAuth() error = %v, want %v", err, oauth.ErrProviderNotFound)
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

func TestCallbackReturnsErrProviderNotFound(t *testing.T) {
	r, err := oauth.New(oauth.WithStateStore(&fakeStateStore{}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = r.Callback(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/callback", nil), "missing")
	if !errors.Is(err, oauth.ErrProviderNotFound) {
		t.Fatalf("Callback() error = %v, want %v", err, oauth.ErrProviderNotFound)
	}
}

func TestCallbackReturnsCallbackErrorFromQuery(t *testing.T) {
	r := newTestRegistry(t, &fakeProvider{name: "google"}, &fakeStateStore{})
	req := httptest.NewRequest(http.MethodGet, "/callback?error=access_denied&error_description=nope", nil)
	_, err := r.Callback(httptest.NewRecorder(), req, "google")
	var callbackErr *oauth.CallbackError
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
	if _, err := r.Callback(httptest.NewRecorder(), req, "google"); err != nil {
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
	store := &fakeStateStore{verifyErr: oauth.ErrStateMismatch}
	r := newTestRegistry(t, p, store)
	req := httptest.NewRequest(http.MethodGet, "/callback?state=bad&code=ok", nil)
	_, err := r.Callback(httptest.NewRecorder(), req, "google")
	if !errors.Is(err, oauth.ErrStateMismatch) {
		t.Fatalf("Callback() error = %v, want %v", err, oauth.ErrStateMismatch)
	}
	if p.completeCalled {
		t.Fatal("CompleteAuth called after state mismatch")
	}
}

func TestCallbackClearsStateAfterVerification(t *testing.T) {
	store := &fakeStateStore{}
	r := newTestRegistry(t, &fakeProvider{name: "google"}, store)
	req := httptest.NewRequest(http.MethodGet, "/callback?state=abc&code=ok", nil)
	if _, err := r.Callback(httptest.NewRecorder(), req, "google"); err != nil {
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
	if _, err := r.Callback(httptest.NewRecorder(), req, "google"); err != nil {
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
	req := httptest.NewRequest(http.MethodGet, "/callback?state=abc&code=ok", nil)
	if _, err := r.Callback(httptest.NewRecorder(), req, "google"); !errors.Is(err, want) {
		t.Fatalf("Callback() error = %v, want %v", err, want)
	}
}

func TestCallbackReturnsAuthResult(t *testing.T) {
	result := oauth.AuthResult{
		Identity:    halo.Identity{ID: "user-1", Provider: "google"},
		Credentials: oauth.Credentials{AccessToken: "access-token"},
		RawData:     oauth.RawData{"id": "user-1"},
	}
	p := &fakeProvider{name: "google", result: result}
	r := newTestRegistry(t, p, &fakeStateStore{})
	req := httptest.NewRequest(http.MethodGet, "/callback?state=abc&code=ok", nil)
	got, err := r.Callback(httptest.NewRecorder(), req, "google")
	if err != nil {
		t.Fatalf("Callback() error = %v", err)
	}
	if got.Identity.ID != result.Identity.ID ||
		got.Credentials.AccessToken != result.Credentials.AccessToken ||
		got.RawData["id"] != result.RawData["id"] {
		t.Fatalf("Callback() result = %#v, want %#v", got, result)
	}
}

func TestBeginAuthGeneratesPKCEVerifier(t *testing.T) {
	p := &fakeProvider{name: "google"}
	store := &fakeStateStore{}
	r := newTestRegistry(t, p, store)
	if err := r.BeginAuth(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), "google"); err != nil {
		t.Fatalf("BeginAuth() error = %v", err)
	}
	if p.beginVerifier == "" {
		t.Fatal("BeginAuth did not pass a PKCE verifier to the provider")
	}
	if store.storeVerifier != p.beginVerifier {
		t.Fatalf("stored verifier = %q, provider got %q; want equal", store.storeVerifier, p.beginVerifier)
	}
}

func TestCallbackPassesVerifierToProvider(t *testing.T) {
	p := &fakeProvider{name: "google"}
	store := &fakeStateStore{verifyVerifier: "stored-verifier"}
	r := newTestRegistry(t, p, store)
	req := httptest.NewRequest(http.MethodGet, "/callback?state=abc&code=ok", nil)
	if _, err := r.Callback(httptest.NewRecorder(), req, "google"); err != nil {
		t.Fatalf("Callback() error = %v", err)
	}
	if p.completeVerifier != "stored-verifier" {
		t.Fatalf("CompleteAuth verifier = %q, want stored-verifier", p.completeVerifier)
	}
}

func TestCallbackErrorErrorWithDescription(t *testing.T) {
	err := (&oauth.CallbackError{Code: "access_denied", Description: "nope"}).Error()
	want := "oauth: callback error: access_denied: nope"
	if err != want {
		t.Fatalf("Error() = %q, want %q", err, want)
	}
}

func TestCallbackErrorErrorWithoutDescription(t *testing.T) {
	err := (&oauth.CallbackError{Code: "access_denied"}).Error()
	want := "oauth: callback error: access_denied"
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
	if _, err := r.Callback(httptest.NewRecorder(), callbackReq, "google"); err != nil {
		t.Fatalf("Callback() error = %v", err)
	}
}
