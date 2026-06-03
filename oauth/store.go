package oauth

import (
	"context"

	"github.com/hazefyro/halo"
	"github.com/hazefyro/halo/identity"
)

// Store persists OAuth identities. It extends the shared [identity.Store]
// with the lookup the OAuth flow needs.
//
// Provide it with [WithStore] to have [Registry.Callback] persist identities
// automatically. Without a Store, Callback returns the identity for the
// application to persist itself.
type Store interface {
	identity.Store
	// GetIdentityByProviderID returns the identity for the given provider and
	// provider account ID. It returns [identity.ErrNotFound] when none matches.
	GetIdentityByProviderID(ctx context.Context, provider, id string) (halo.Identity, error)
}
