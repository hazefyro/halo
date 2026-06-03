package oauth

import (
	"context"
	"errors"
	"net/http"
	"regexp"

	"github.com/hazefyro/halo"
	"github.com/hazefyro/halo/identity"
	"github.com/hazefyro/halo/oauth/internal/randstate"
	"golang.org/x/oauth2"
)

var validProviderName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// Registry stores providers and coordinates OAuth begin and callback flows.
type Registry struct {
	providers  map[string]Provider
	stateStore StateStore
	store      Store
}

// Option configures a Registry.
type Option func(*Registry)

// WithStateStore configures the state store used for OAuth state validation.
func WithStateStore(s StateStore) Option {
	return func(r *Registry) { r.stateStore = s }
}

// WithStore configures the identity store used to persist authenticated users.
// When set, [Registry.Callback] looks up the identity by (provider, ID) and
// creates it if absent. When unset, Callback does not persist anything and
// returns the identity for the application to store itself.
func WithStore(s Store) Option {
	return func(r *Registry) { r.store = s }
}

// New creates a Registry.
func New(opts ...Option) (*Registry, error) {
	r := &Registry{providers: make(map[string]Provider)}
	for _, opt := range opts {
		opt(r)
	}
	if r.stateStore == nil {
		return nil, errors.New("oauth: no StateStore provided — use WithStateStore()")
	}
	return r, nil
}

// Register adds a provider to the registry.
func (r *Registry) Register(p Provider) error {
	if !validProviderName.MatchString(p.Name()) {
		return errors.New("oauth: provider name " + p.Name() + " contains invalid characters — use only a-z, A-Z, 0-9, - and _")
	}
	if _, exists := r.providers[p.Name()]; exists {
		return errors.New("oauth: provider " + p.Name() + " is already registered")
	}
	r.providers[p.Name()] = p
	return nil
}

// Get returns a registered provider by name.
func (r *Registry) Get(name string) (Provider, error) {
	p, ok := r.providers[name]

	if !ok {
		return nil, ErrProviderNotFound
	}

	return p, nil
}

// BeginAuth starts the OAuth flow and redirects to the provider.
func (r *Registry) BeginAuth(w http.ResponseWriter, req *http.Request, providerName string) error {
	p, err := r.Get(providerName)
	if err != nil {
		return err
	}

	state, err := randstate.RandomState()
	if err != nil {
		return err
	}

	verifier := oauth2.GenerateVerifier()

	redirectURL, err := p.BeginAuth(state, verifier)
	if err != nil {
		return err
	}

	if err := r.stateStore.Store(w, req, state, verifier, p.Name()); err != nil {
		return err
	}

	http.Redirect(w, req, redirectURL, http.StatusTemporaryRedirect)
	return nil
}

// Callback verifies OAuth state and completes the provider exchange, returning
// the [AuthResult]: the authenticated identity together with the OAuth tokens
// and raw userinfo.
//
// When the Registry has a [Store] (see [WithStore]), Callback persists the
// identity: it looks the identity up by (provider, ID) and creates it if
// absent, and the returned AuthResult carries the stored identity. Without a
// Store, the identity is returned unpersisted for the caller to map to a user
// in its own store.
//
// Callback never establishes a session, so an application can combine OAuth
// with other login methods (password, ...) on equal terms.
func (r *Registry) Callback(w http.ResponseWriter, req *http.Request, providerName string) (AuthResult, error) {
	p, err := r.Get(providerName)
	if err != nil {
		return AuthResult{}, err
	}

	if code := req.URL.Query().Get("error"); code != "" {
		return AuthResult{}, &CallbackError{
			Code:        code,
			Description: req.URL.Query().Get("error_description"),
		}
	}

	verifier, err := r.stateStore.Verify(req, req.URL.Query().Get("state"), p.Name())
	if err != nil {
		return AuthResult{}, err
	}
	r.stateStore.Clear(w, p.Name())

	result, err := p.CompleteAuth(req, verifier)
	if err != nil {
		return AuthResult{}, err
	}

	if r.store != nil {
		stored, err := r.getOrCreate(req.Context(), p.Name(), result.Identity)
		if err != nil {
			return AuthResult{}, err
		}
		result.Identity = stored
	}

	return result, nil
}

// getOrCreate returns the stored identity for (provider, id.ID), creating it
// from id when none exists yet.
func (r *Registry) getOrCreate(ctx context.Context, provider string, id halo.Identity) (halo.Identity, error) {
	stored, err := r.store.GetIdentityByProviderID(ctx, provider, id.ID)
	if err == nil {
		return stored, nil
	}
	if !errors.Is(err, identity.ErrNotFound) {
		return halo.Identity{}, err
	}
	if err := r.store.CreateIdentity(ctx, id); err != nil {
		return halo.Identity{}, err
	}
	return id, nil
}
