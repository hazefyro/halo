package goauth

import (
	"context"
	"errors"
	"net/http"
	"regexp"
)

var validProviderName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

type contextKey struct{}
type credentialsContextKey struct{}
type providerContextKey struct{}
type rawDataContextKey struct{}

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

func (r *Registry) BeginAuth(w http.ResponseWriter, req *http.Request, providerName string) error {
	p, err := r.Get(providerName)
	if err != nil {
		return err
	}

	state, err := r.stateStore.Generate(w, req, p.Name())
	if err != nil {
		return err
	}

	redirectURL, err := p.BeginAuth(state)
	if err != nil {
		return err
	}

	http.Redirect(w, req, redirectURL, http.StatusTemporaryRedirect)
	return nil
}

func (r *Registry) Callback(w http.ResponseWriter, req *http.Request, providerName string, next http.Handler) error {
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

	ctx := context.WithValue(req.Context(), contextKey{}, result.User)
	ctx = context.WithValue(ctx, credentialsContextKey{}, result.Credentials)
	ctx = context.WithValue(ctx, providerContextKey{}, p.Name())
	ctx = context.WithValue(ctx, rawDataContextKey{}, result.RawData)
	next.ServeHTTP(w, req.WithContext(ctx))
	return nil
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

func CredentialsFromContext(ctx context.Context) (Credentials, error) {
	c, ok := ctx.Value(credentialsContextKey{}).(Credentials)
	if !ok {
		return Credentials{}, errors.New("goauth: no credentials in context")
	}
	return c, nil
}

func ProviderFromContext(ctx context.Context) string {
	name, _ := ctx.Value(providerContextKey{}).(string)
	return name
}

func RawDataFromContext(ctx context.Context) RawData {
	raw, _ := ctx.Value(rawDataContextKey{}).(RawData)
	return raw
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
