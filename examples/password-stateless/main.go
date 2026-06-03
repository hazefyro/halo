// Command password-stateless is a minimal example wiring this module together
// with local email+password login backed by a stateless (JWT) session.
//
// It shows how an application implements the persistence contract: the
// in-memory store here satisfies password.Store, which embeds the shared
// identity.Store (CreateIdentity) and adds the lookups the password flow needs.
// A real app would back the same methods with its own database.
//
// Run:
//
//	go run ./examples/password-stateless
//
// Then open http://localhost:8080. Register an account, then log in with it.
// Accounts live only in memory, so they vanish when the process exits.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/hazefyro/halo"
	"github.com/hazefyro/halo/identity"
	"github.com/hazefyro/halo/password"
	"github.com/hazefyro/halo/session"
	"github.com/hazefyro/halo/session/store/stateless"
)

const addr = "localhost:8080"

// memStore is a throwaway in-memory implementation of password.Store. The
// password Manager calls CreateIdentity (from the embedded identity.Store) on
// register and GetIdentityByEmail on login; UpdatePassword backs a password
// change, which this example doesn't expose. A real app swaps this for its DB.
type memStore struct {
	mu      sync.Mutex
	byEmail map[string]halo.Identity
}

func newMemStore() *memStore {
	return &memStore{byEmail: make(map[string]halo.Identity)}
}

// CreateIdentity persists a new identity (identity.Store). It rejects a
// duplicate email with password.ErrEmailTaken so the handler can report it.
func (s *memStore) CreateIdentity(_ context.Context, id halo.Identity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.byEmail[id.Email]; taken {
		return password.ErrEmailTaken
	}
	s.byEmail[id.Email] = id
	return nil
}

// GetIdentityByEmail looks an identity up by email, returning
// identity.ErrNotFound when none matches so Login can reject it.
func (s *memStore) GetIdentityByEmail(_ context.Context, email, _ string) (halo.Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byEmail[email]
	if !ok {
		return halo.Identity{}, identity.ErrNotFound
	}
	return id, nil
}

// UpdatePassword replaces the stored hash for an email.
func (s *memStore) UpdatePassword(_ context.Context, email, passwordHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byEmail[email]
	if !ok {
		return identity.ErrNotFound
	}
	id.PasswordHash = passwordHash
	s.byEmail[email] = id
	return nil
}

func main() {
	// Password: the Manager hashes (bcrypt by default; override with
	// password.WithHasher) and persists via the store. Register returns an
	// Identity for the app to map to a user; Login verifies it and returns it.
	passwords := password.New(newMemStore())

	// Sessions: stateless store signs the whole session into a JWT cookie,
	// so there's no server-side storage to run.
	store, err := stateless.New(stateless.WithSigningKey([]byte("dev-session-signing-key-change-me")))
	if err != nil {
		log.Fatal(err)
	}
	// Sessions are Secure-by-default; opt out for plain-http localhost.
	// Drop WithSecure(false) once you're behind HTTPS.
	sessions, err := session.New(store, session.WithSecure(false))
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<a href="/register">Register</a> | <a href="/login">Log in</a>`)
	})

	mux.HandleFunc("GET /register", func(w http.ResponseWriter, r *http.Request) {
		writeForm(w, "Register", "/register")
	})

	// Register hashes the password and stores a new identity. The Identity is
	// just a DTO: we map it to a user (here, keyed by email) and create a
	// session, which is what actually keeps us logged in.
	mux.HandleFunc("POST /register", func(w http.ResponseWriter, r *http.Request) {
		id, err := passwords.Register(r.Context(), password.User{
			Email:    r.FormValue("email"),
			Password: r.FormValue("password"),
		})
		if errors.Is(err, password.ErrEmailTaken) {
			http.Error(w, "email already registered", http.StatusConflict)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		login(w, r, sessions, id)
	})

	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		writeForm(w, "Log in", "/login")
	})

	// Login verifies the password. ErrInvalidCredentials covers both unknown
	// email and wrong password, so we never reveal which it was.
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		id, err := passwords.Login(r.Context(), r.FormValue("email"), r.FormValue("password"))
		if err != nil {
			http.Error(w, "invalid email or password", http.StatusUnauthorized)
			return
		}
		login(w, r, sessions, id)
	})

	// Protected: RequireAuth loads the session and rejects requests without one.
	// Unauthenticated visitors are redirected to the login page; the handler
	// reads the active session from the request context.
	mux.Handle("GET /me", sessions.RequireAuth(session.WithLoginRedirect("/login"))(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s, _ := session.FromContext(r.Context())
			fmt.Fprintf(w, "logged in as %s\n<a href=\"/logout\">log out</a>", s.UserID)
		}),
	))

	mux.HandleFunc("GET /logout", func(w http.ResponseWriter, r *http.Request) {
		if err := sessions.Delete(w, r); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	log.Printf("listening on http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// login keys the session by the identity's email. A password identity has no
// provider ID, so email is its stable identifier; a real app would map it to
// its own user ID first.
func login(w http.ResponseWriter, r *http.Request, sessions *session.Manager, id halo.Identity) {
	if _, err := sessions.Create(r.Context(), w, id.Email); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/me", http.StatusSeeOther)
}

func writeForm(w http.ResponseWriter, title, action string) {
	fmt.Fprintf(w, `<h1>%s</h1>
<form method="post" action="%s">
  <input name="email" type="email" placeholder="email" required>
  <input name="password" type="password" placeholder="password" required>
  <button type="submit">%s</button>
</form>`, title, action, title)
}
