package password

import (
	"context"
	"fmt"

	"github.com/hazefyro/halo"
	"github.com/hazefyro/halo/password/hasher"
)

type User struct {
	Email     string
	Password  string
	Username  string
	Name      string
	AvatarURL string
}

type Manager struct {
	hasher hasher.Hasher
	store  Store
	cfg    Config
}

func New(store Store, hash hasher.Hasher, opts ...Option) *Manager {
	c := applyOptions(opts)

	if hash == nil {
		hash = hasher.Default()
	}

	return &Manager{
		hasher: hash,
		store:  store,
		cfg:    c,
	}
}

func (m *Manager) Register(ctx context.Context, user User) (halo.Identity, error) {
	if user.Email == "" {
		return halo.Identity{}, ErrEmailRequired
	}
	if user.Password == "" {
		return halo.Identity{}, ErrPasswordRequired
	}
	if m.cfg.CollectName && user.Name == "" {
		return halo.Identity{}, ErrNameRequired
	}
	if m.cfg.CollectUsername && user.Username == "" {
		return halo.Identity{}, ErrUsernameRequired
	}
	if m.cfg.CollectAvatar && user.AvatarURL == "" {
		return halo.Identity{}, ErrAvatarRequired
	}

	hashed, err := m.hasher.Hash(user.Password)
	if err != nil {
		return halo.Identity{}, fmt.Errorf("password: failed to hash password: %w", err)
	}

	identity := halo.Identity{
		Email:        user.Email,
		Name:         user.Name,
		Username:     user.Username,
		AvatarURL:    user.AvatarURL,
		Provider:     "password",
		PasswordHash: hashed,
	}

	if err := m.store.CreateIdentity(ctx, identity); err != nil {
		return halo.Identity{}, err
	}

	return identity, nil
}

func (m *Manager) Login(ctx context.Context, email, password string) (halo.Identity, error) {
	identity, err := m.store.GetIdentityByEmail(ctx, email, "password")
	if err != nil {
		return halo.Identity{}, ErrInvalidCredentials
	}

	if err := m.hasher.Verify(password, identity.PasswordHash); err != nil {
		return halo.Identity{}, ErrInvalidCredentials
	}

	return identity, nil
}
