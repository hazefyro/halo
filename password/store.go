package password

import (
	"context"

	"github.com/hazefyro/halo"
	"github.com/hazefyro/halo/identity"
)

// Store persists password identities. It extends the shared
// [identity.Store] with the lookups the password flow needs.
type Store interface {
	identity.Store
	// GetIdentityByEmail returns the identity for the given email and provider.
	// It returns [identity.ErrNotFound] when no identity matches.
	GetIdentityByEmail(ctx context.Context, email, provider string) (halo.Identity, error)
	// UpdatePassword replaces the stored password hash for the given email.
	UpdatePassword(ctx context.Context, email, passwordHash string) error
}
