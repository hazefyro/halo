package identity

import (
	"context"

	"github.com/hazefyro/halo"
)

// Store is the minimal persistence contract shared by every login method.
// Login methods embed it and add their own lookups.
type Store interface {
	// CreateIdentity persists a new identity.
	CreateIdentity(ctx context.Context, identity halo.Identity) error
}
