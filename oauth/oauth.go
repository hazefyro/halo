package oauth

import (
	"errors"
	"net/http"
	"regexp"

	"github.com/hazefyro/auth"
	"github.com/hazefyro/auth/oauth/internal/randstate"
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

	redirectURL, err := p.BeginAuth(state)
	if err != nil {
		return err
	}

	if err := r.stateStore.Store(w, req, state, p.Name()); err != nil {
		return err
	}

	http.Redirect(w, req, redirectURL, http.StatusTemporaryRedirect)
	return nil
}

// Callback verifies OAuth state, completes provider auth, and calls next.
//
// On success it stores the authenticated identity in the request context via
// [auth.StoreIdentityInContext] and the OAuth tokens and raw userinfo under the
// accessors [CredentialsFromContext] and [RawDataFromContext].
func (r *Registry) Callback(w http.ResponseWriter, req *http.Request, providerName string, next http.Handler) error {
	if next == nil {
		return errors.New("oauth: next handler must not be nil")
	}

	p, err := r.Get(providerName)
	if err != nil {
		return err
	}

	if code := req.URL.Query().Get("error"); code != "" {
		return &CallbackError{
			Code:        code,
			Description: req.URL.Query().Get("error_description"),
		}
	}

	if err := r.stateStore.Verify(req, req.URL.Query().Get("state"), p.Name()); err != nil {
		return err
	}
	r.stateStore.Clear(w, p.Name())

	result, err := p.CompleteAuth(req)
	if err != nil {
		return err
	}

	ctx := auth.StoreIdentityInContext(req.Context(), result.Identity)
	ctx = storeTokensInContext(ctx, oauthData{Credentials: result.Credentials, RawData: result.RawData})
	next.ServeHTTP(w, req.WithContext(ctx))
	return nil
}
