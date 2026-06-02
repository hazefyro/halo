package password

import (
	"context"

	"github.com/hazefyro/halo"
)

type Store interface {
	CreateIdentity(ctx context.Context, identity halo.Identity) error
	GetIdentityByEmail(ctx context.Context, email, provider string) (halo.Identity, error)
	UpdatePassword(ctx context.Context, email, passwordHash string) error
}
