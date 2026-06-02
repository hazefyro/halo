package hasher

import (
	"github.com/hazefyro/halo/password/hasher/bcrypt"
)

type Hasher interface {
	Hash(password string) (string, error)
	Verify(password, hash string) error
}

func Default() Hasher {
	h, err := bcrypt.New()
	if err != nil {
		panic(err) // default cost is always valid
	}
	return h
}
