package goauth

import (
	"context"
	"errors"
	"net/http"
)

type contextKey struct{}
type providerContextKey struct{}

type Registry struct {
	providers  map[string]Provider
	stateStore StateStore
}

type Option func(*Registry)

func WithStateStore(s StateStore) Option {
	return func(r *Registry) { r.stateStore = s }
}

func New(opts ...Option) *Registry {
	r := &Registry{providers: make(map[string]Provider)}
	for _, opt := range opts {
		opt(r)
	}
	if r.stateStore == nil {
		panic("goauth: no StateStore provided - use WithStateStore()")
	}

	return r
}

func (r *Registry) Register(p Provider) {
	r.providers[p.Name()] = p
}

func (r *Registry) Get(name string) (Provider, error) {
	p, ok := r.providers[name]

	if !ok {
		return nil, ErrProviderNotFound
	}

	return p, nil
}

func (r *Registry) BeginAuthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		p, err := r.Get(req.PathValue("provider"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		state, err := r.stateStore.Generate(w, req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		redirectURL, err := p.BeginAuth(state)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, req, redirectURL, http.StatusTemporaryRedirect)
	}
}

func (r *Registry) CallbackHandler(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		p, err := r.Get(req.PathValue("provider"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		if err := r.stateStore.Verify(req, req.URL.Query().Get("state")); err != nil {
			http.Error(w, ErrStateMismatch.Error(), http.StatusUnauthorized)
			return
		}
		r.stateStore.Clear(w)

		user, err := p.CompleteAuth(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		ctx := context.WithValue(req.Context(), contextKey{}, user)
		ctx = context.WithValue(ctx, providerContextKey{}, p.Name())
		next.ServeHTTP(w, req.WithContext(ctx))
	}
}

func StoreUserInContext(ctx context.Context, user User) context.Context {
	return context.WithValue(ctx, contextKey{}, user)
}

func UserFromContext(ctx context.Context) (User, error) {
	u, ok := ctx.Value(contextKey{}).(User)
	if !ok {
		return User{}, errors.New("goauth: no user in context")
	}
	return u, nil
}

func ProviderFromContext(ctx context.Context) string {
	name, _ := ctx.Value(providerContextKey{}).(string)
	return name
}

func (r *Registry) AuthRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, err := UserFromContext(req.Context()); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, req)
	})
}
