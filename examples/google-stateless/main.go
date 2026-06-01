// Command google-stateless is a minimal example wiring this module together:
// Google OAuth for login, and a stateless (JWT) session to stay logged in.
//
// Run:
//
//	export GOOGLE_CLIENT_ID=...        # from Google Cloud console
//	export GOOGLE_CLIENT_SECRET=...
//	go run ./examples/google-stateless
//
// Authorized redirect URI in the Google console must be:
//
//	http://localhost:8080/auth/google/callback
//
// Then open http://localhost:8080.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/hazefyro/auth"
	"github.com/hazefyro/auth/oauth"
	"github.com/hazefyro/auth/oauth/providers/google"
	"github.com/hazefyro/auth/session"
	"github.com/hazefyro/auth/session/store/stateless"
)

const addr = "localhost:8080"

func main() {
	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		log.Fatal("set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET")
	}

	// OAuth: a registry with the Google provider and a cookie-backed state store.
	// Insecure store = non-Secure cookies, fine for http://localhost.
	// Use the secure variant behind HTTPS.
	// The secret must be >= 32 bytes.
	stateStore, err := oauth.NewCookieStateStore("dev-oauth-state-secret-change-me!", oauth.WithSecure(false))
	if err != nil {
		log.Fatal(err)
	}
	registry, err := oauth.New(oauth.WithStateStore(stateStore))
	if err != nil {
		log.Fatal(err)
	}
	if err := registry.Register(google.New(
		clientID, clientSecret,
		"http://localhost:8080/auth/google/callback",
	)); err != nil {
		log.Fatal(err)
	}

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
		fmt.Fprintln(w, `<a href="/login/google">Log in with Google</a>`)
	})

	// Kick off the OAuth flow: generates state, sets the state cookie, redirects.
	mux.HandleFunc("GET /login/google", func(w http.ResponseWriter, r *http.Request) {
		if err := registry.BeginAuth(w, r, "google"); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	// OAuth callback: Callback verifies state, exchanges the code, puts the
	// identity in the request context, and calls our handler. We turn that
	// identity into a session and redirect.
	mux.HandleFunc("GET /auth/google/callback", func(w http.ResponseWriter, r *http.Request) {
		err := registry.Callback(w, r, "google", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := auth.IdentityFromContext(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			// In a real app you'd look up / upsert the user in your DB here and
			// use your own user ID. We just key the session by the Google ID.
			if _, err := sessions.Create(r.Context(), w, id.ID); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/me", http.StatusSeeOther)
		}))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})

	// Protected: read the session back from its cookie.
	mux.HandleFunc("GET /me", func(w http.ResponseWriter, r *http.Request) {
		s, err := sessions.Load(r)
		if err != nil {
			http.Redirect(w, r, "/login/google", http.StatusSeeOther)
			return
		}
		fmt.Fprintf(w, "logged in as user %s\n<a href=\"/logout\">log out</a>", s.UserID)
	})

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
