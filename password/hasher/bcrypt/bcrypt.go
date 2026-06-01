package bcrypt

import (
	"fmt"

	golang_bcrypt "golang.org/x/crypto/bcrypt"
)

type Hasher struct {
	cost int
}

type Option func(*Hasher)

func WithCost(cost int) Option {
	return func(h *Hasher) { h.cost = cost }
}

func New(opts ...Option) (*Hasher, error) {
	h := &Hasher{
		cost: golang_bcrypt.DefaultCost,
	}
	for _, opt := range opts {
		opt(h)
	}
	if err := h.validate(); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *Hasher) validate() error {
	if h.cost < golang_bcrypt.MinCost || h.cost > golang_bcrypt.MaxCost {
		return fmt.Errorf("bcrypt: invalid cost %d, must be between %d and %d", h.cost, golang_bcrypt.MinCost, golang_bcrypt.MaxCost)
	}
	return nil
}

func (h *Hasher) Hash(password string) (string, error) {
	bytes, err := golang_bcrypt.GenerateFromPassword([]byte(password), h.cost)
	return string(bytes), err
}

func (h *Hasher) Verify(password, hash string) error {
	return golang_bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
