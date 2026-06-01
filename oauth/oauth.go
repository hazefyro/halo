package oauth

import (
	"errors"
	"net/http"
	"regexp"

	"github.com/hazefyro/halo/oauth/internal/randstate"
	"golang.org/x/oauth2"
)

var validProviderName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// Registry stores providers and coordinates OAuth begin and callback flows.
type Registry struct {
	providers  map[string]Provider
	stateStore StateStore
}

// Option configures a Registry.
type Option func(*Registry)

// WithStateStore configures the state store used for OAuth state validation.
func WithStateStore(s StateStore) Option {
	return func(r *Registry) { r.stateStore = s }
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
// the [AuthResult] — the authenticated identity together with the OAuth tokens
// and raw userinfo.
//
// The result's Identity is a data-transfer object: the caller maps it to a user
// in its own store and establishes a session. This package deliberately does
// not touch sessions or the request context, so an application can combine
// OAuth with other login methods (password, ...) on equal terms.
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

	return p.CompleteAuth(req, verifier)
}
