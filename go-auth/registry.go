package goauth

import (
	"context"
	"errors"
	"net/http"
	"regexp"

	"github.com/haze/go-auth/internal/randstate"
)

var validProviderName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

type authResultKey struct{}

type Registry struct {
	providers  map[string]Provider
	stateStore StateStore
}

type Option func(*Registry)

func WithStateStore(s StateStore) Option {
	return func(r *Registry) { r.stateStore = s }
}

func New(opts ...Option) (*Registry, error) {
	r := &Registry{providers: make(map[string]Provider)}
	for _, opt := range opts {
		opt(r)
	}
	if r.stateStore == nil {
		return nil, errors.New("goauth: no StateStore provided — use WithStateStore()")
	}
	return r, nil
}

func (r *Registry) Register(p Provider) error {
	if !validProviderName.MatchString(p.Name()) {
		return errors.New("goauth: provider name " + p.Name() + " contains invalid characters — use only a-z, A-Z, 0-9, - and _")
	}
	if _, exists := r.providers[p.Name()]; exists {
		return errors.New("goauth: provider " + p.Name() + " is already registered")
	}
	r.providers[p.Name()] = p
	return nil
}

func (r *Registry) Get(name string) (Provider, error) {
	p, ok := r.providers[name]

	if !ok {
		return nil, ErrProviderNotFound
	}

	return p, nil
}

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

func (r *Registry) Callback(w http.ResponseWriter, req *http.Request, providerName string, next http.Handler) error {
	if next == nil {
		return errors.New("goauth: next handler must not be nil")
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

	ctx := context.WithValue(req.Context(), authResultKey{}, result)
	next.ServeHTTP(w, req.WithContext(ctx))
	return nil
}

func authResultFromContext(ctx context.Context) (AuthResult, bool) {
	r, ok := ctx.Value(authResultKey{}).(AuthResult)
	return r, ok
}

func StoreIdentityInContext(ctx context.Context, identity Identity) context.Context {
	return context.WithValue(ctx, authResultKey{}, AuthResult{Identity: identity})
}

func IdentityFromContext(ctx context.Context) (Identity, error) {
	r, ok := authResultFromContext(ctx)
	if !ok {
		return Identity{}, errors.New("goauth: no identity in context")
	}
	return r.Identity, nil
}

func CredentialsFromContext(ctx context.Context) (Credentials, error) {
	r, ok := authResultFromContext(ctx)
	if !ok || r.Credentials.AccessToken == "" {
		return Credentials{}, errors.New("goauth: no credentials in context")
	}
	return r.Credentials, nil
}

func ProviderFromContext(ctx context.Context) string {
	r, _ := authResultFromContext(ctx)
	return r.Identity.Provider
}

func RawDataFromContext(ctx context.Context) (RawData, error) {
	r, ok := authResultFromContext(ctx)
	if !ok || r.RawData == nil {
		return nil, errors.New("goauth: no raw data in context")
	}
	return r.RawData, nil
}

func (r *Registry) AuthRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, err := IdentityFromContext(req.Context()); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, req)
	})
}
