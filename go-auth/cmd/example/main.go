package main

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	goauth "github.com/haze/go-auth"
	"github.com/haze/go-auth/providers/discord"
	"github.com/haze/go-auth/providers/github"
	"github.com/haze/go-auth/providers/google"
	"github.com/joho/godotenv"
)

func main() {
	godotenv.Load()

	auth := goauth.New(
		goauth.WithStateStore(goauth.NewInsecureCookieStateStore("dev-state-secret")),
		goauth.WithSessionStore(goauth.NewInsecureCookieSessionStore("dev-session-secret")),
	)
	auth.Register(google.New(
		os.Getenv("GOOGLE_CLIENT_ID"),
		os.Getenv("GOOGLE_CLIENT_SECRET"),
		"http://localhost:8080/auth/google/callback",
	))
	auth.Register(github.New(
		os.Getenv("GITHUB_CLIENT_ID"),
		os.Getenv("GITHUB_CLIENT_SECRET"),
		"http://localhost:8080/auth/github/callback",
	))
	auth.Register(discord.New(
		os.Getenv("DISCORD_CLIENT_ID"),
		os.Getenv("DISCORD_CLIENT_SECRET"),
		"http://localhost:8080/auth/discord/callback",
	))

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(auth.LoadSessionMiddleware())

	r.Get("/", handleHome)
	r.Get("/auth/{provider}", auth.BeginAuthHandler())
	r.Get("/auth/{provider}/callback", auth.CallbackHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provider := goauth.ProviderFromContext(r.Context())
		user, _ := goauth.UserFromContext(r.Context())
		fmt.Printf("authenticated via %s: %s (%s)\n", provider, user.Name, user.Email)
		if err := auth.SaveSession(w, r); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/me", http.StatusTemporaryRedirect)
	})))

	r.Group(func(r chi.Router) {
		r.Use(auth.AuthRequired)
		r.Get("/me", handleMe)
		r.Post("/logout", func(w http.ResponseWriter, r *http.Request) {
			auth.DeleteSession(w, r)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		})
	})

	fmt.Println("listening on http://localhost:8080")
	http.ListenAndServe(":8080", r)
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	user, err := goauth.UserFromContext(r.Context())
	if err == nil {
		fmt.Fprintf(w, `logged in as %s — <a href='/me'>profile</a> | <form action='/logout' method='POST' style='display:inline'><button type='submit'>logout</button></form>`, html.EscapeString(user.Name))
		return
	}
	fmt.Fprint(w, `
		<a href="/auth/google">login with google</a><br>
		<a href="/auth/github">login with github</a><br>
		<a href="/auth/discord">login with discord</a>
	`)
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	user, _ := goauth.UserFromContext(r.Context())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"id":       user.ID,
		"name":     user.Name,
		"email":    user.Email,
		"username": user.Username,
		"avatar":   user.AvatarURL,
		"provider": user.Provider,
	})
}
