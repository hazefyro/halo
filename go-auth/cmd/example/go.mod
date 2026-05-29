module github.com/haze/go-auth/example

go 1.26.3

require (
	github.com/go-chi/chi/v5 v5.3.0
	github.com/haze/go-auth v0.0.0
	github.com/joho/godotenv v1.5.1
)

require (
	cloud.google.com/go/compute/metadata v0.3.0 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
)

replace github.com/haze/go-auth => ../..
