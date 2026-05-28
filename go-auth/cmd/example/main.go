package main

import (
	"fmt"
	"net/http"
	"os"

	goauth "github.com/haze/go-auth"
	"github.com/haze/go-auth/providers/google"
	"github.com/joho/godotenv"
)

func main() {
	godotenv.Load()

	auth := goauth.New(goauth.WithStateStore(goauth.NewCookieStateStore("dev-secret")))
	auth.Register(google.New(
		os.Getenv("GOOGLE_CLIENT_ID"),
		os.Getenv("GOOGLE_CLIENT_SECRET"),
		"http://localhost:8080/auth/google/callback",
	))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/{provider}", auth.BeginAuthHandler())
	mux.HandleFunc("GET /auth/{provider}/callback", auth.CallbackHandler(http.HandlerFunc(handleLogin)))

	fmt.Println("listening on http://localhost:8080")
	http.ListenAndServe(":8080", mux)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	user, err := goauth.UserFromContext(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "logged in as: %s (%s)", user.Name, user.Email)
}
