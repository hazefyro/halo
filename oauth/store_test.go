package oauth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hazefyro/halo"
	"github.com/hazefyro/halo/identity"
	"github.com/hazefyro/halo/oauth"
)

type fakeStore struct {
	getProvider string
	getID       string
	getResult   halo.Identity
	getErr      error
	created     []halo.Identity
	createErr   error
}

func (s *fakeStore) GetIdentityByProviderID(ctx context.Context, provider, id string) (halo.Identity, error) {
	s.getProvider = provider
	s.getID = id
	return s.getResult, s.getErr
}

func (s *fakeStore) CreateIdentity(ctx context.Context, id halo.Identity) error {
	s.created = append(s.created, id)
	return s.createErr
}

func newTestRegistryWithStore(t *testing.T, p *fakeProvider, ss *fakeStateStore, store oauth.Store) *oauth.Registry {
	t.Helper()
	r, err := oauth.New(oauth.WithStateStore(ss), oauth.WithStore(store))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := r.Register(p); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	return r
}

func callbackReq() *http.Request {
	return httptest.NewRequest(http.MethodGet, "/callback?state=abc&code=ok", nil)
}

func TestCallbackCreatesIdentityWhenNotFound(t *testing.T) {
	want := halo.Identity{ID: "user-1", Provider: "google", Email: "a@example.com"}
	p := &fakeProvider{name: "google", result: oauth.AuthResult{Identity: want}}
	store := &fakeStore{getErr: identity.ErrNotFound}
	r := newTestRegistryWithStore(t, p, &fakeStateStore{}, store)

	got, err := r.Callback(httptest.NewRecorder(), callbackReq(), "google")
	if err != nil {
		t.Fatalf("Callback() error = %v", err)
	}
	if store.getProvider != "google" || store.getID != "user-1" {
		t.Fatalf("lookup called with provider=%q id=%q, want google/user-1", store.getProvider, store.getID)
	}
	if len(store.created) != 1 || store.created[0] != want {
		t.Fatalf("created = %#v, want one %#v", store.created, want)
	}
	if got.Identity != want {
		t.Fatalf("Callback() identity = %#v, want %#v", got.Identity, want)
	}
}

func TestCallbackReturnsExistingIdentity(t *testing.T) {
	stored := halo.Identity{ID: "user-1", Provider: "google", Name: "Stored Name"}
	fresh := halo.Identity{ID: "user-1", Provider: "google", Name: "Fresh Name"}
	p := &fakeProvider{name: "google", result: oauth.AuthResult{Identity: fresh}}
	store := &fakeStore{getResult: stored}
	r := newTestRegistryWithStore(t, p, &fakeStateStore{}, store)

	got, err := r.Callback(httptest.NewRecorder(), callbackReq(), "google")
	if err != nil {
		t.Fatalf("Callback() error = %v", err)
	}
	if len(store.created) != 0 {
		t.Fatalf("created = %#v, want none", store.created)
	}
	if got.Identity != stored {
		t.Fatalf("Callback() identity = %#v, want stored %#v", got.Identity, stored)
	}
}

func TestCallbackReturnsLookupError(t *testing.T) {
	want := errors.New("db down")
	p := &fakeProvider{name: "google", result: oauth.AuthResult{Identity: halo.Identity{ID: "user-1"}}}
	store := &fakeStore{getErr: want}
	r := newTestRegistryWithStore(t, p, &fakeStateStore{}, store)

	_, err := r.Callback(httptest.NewRecorder(), callbackReq(), "google")
	if !errors.Is(err, want) {
		t.Fatalf("Callback() error = %v, want %v", err, want)
	}
	if len(store.created) != 0 {
		t.Fatalf("created = %#v, want none", store.created)
	}
}

func TestCallbackReturnsCreateError(t *testing.T) {
	want := errors.New("insert failed")
	p := &fakeProvider{name: "google", result: oauth.AuthResult{Identity: halo.Identity{ID: "user-1"}}}
	store := &fakeStore{getErr: identity.ErrNotFound, createErr: want}
	r := newTestRegistryWithStore(t, p, &fakeStateStore{}, store)

	_, err := r.Callback(httptest.NewRecorder(), callbackReq(), "google")
	if !errors.Is(err, want) {
		t.Fatalf("Callback() error = %v, want %v", err, want)
	}
}

func TestCallbackWithoutStoreDoesNotPersist(t *testing.T) {
	want := halo.Identity{ID: "user-1", Provider: "google"}
	p := &fakeProvider{name: "google", result: oauth.AuthResult{Identity: want}}
	r := newTestRegistry(t, p, &fakeStateStore{})

	got, err := r.Callback(httptest.NewRecorder(), callbackReq(), "google")
	if err != nil {
		t.Fatalf("Callback() error = %v", err)
	}
	if got.Identity != want {
		t.Fatalf("Callback() identity = %#v, want %#v", got.Identity, want)
	}
}
