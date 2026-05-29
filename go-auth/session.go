package goauth

import "net/http"

type SessionStore interface {
	Save(w http.ResponseWriter, user User) error
	Get(r *http.Request) (User, bool)
	Delete(w http.ResponseWriter, r *http.Request) error
}
