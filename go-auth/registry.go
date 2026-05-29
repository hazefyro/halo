package goauth

import (
	"context"
	"errors"
	"net/http"
	"regexp"
)

var validProviderName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

type contextKey struct{}
type providerContextKey struct{}

type Registry struct {
	providers    map[string]Provider
	stateStore   StateStore
	sessionStore SessionStore
}

type Option func(*Registry)

func WithStateStore(s StateStore) Option {
	return func(r *Registry) { r.stateStore = s }
}

func WithSessionStore(s SessionStore) Option {
	return func(r *Registry) { r.sessionStore = s }
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
	if !validProviderName.MatchString(p.Name()) {
		panic("goauth: provider name " + p.Name() + " contains invalid characters — use only a-z, A-Z, 0-9, - and _")
	}
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

		state, err := r.stateStore.Generate(w, req, p.Name())
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

		if err := r.stateStore.Verify(req, req.URL.Query().Get("state"), p.Name()); err != nil {
			http.Error(w, ErrStateMismatch.Error(), http.StatusUnauthorized)
			return
		}
		r.stateStore.Clear(w, p.Name())

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

func (r *Registry) SaveSession(w http.ResponseWriter, req *http.Request) error {
	if r.sessionStore == nil {
		return errors.New("goauth: no SessionStore configured — use WithSessionStore()")
	}
	user, err := UserFromContext(req.Context())
	if err != nil {
		return err
	}
	return r.sessionStore.Save(w, user)
}

func (r *Registry) DeleteSession(w http.ResponseWriter, req *http.Request) error {
	if r.sessionStore == nil {
		return errors.New("goauth: no SessionStore configured — use WithSessionStore()")
	}
	return r.sessionStore.Delete(w, req)
}

func (r *Registry) LoadSessionMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if r.sessionStore == nil {
				next.ServeHTTP(w, req)
				return
			}

			user, ok := r.sessionStore.Get(req)
			if !ok {
				next.ServeHTTP(w, req)
				return
			}

			ctx := StoreUserInContext(req.Context(), user)
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	}
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
