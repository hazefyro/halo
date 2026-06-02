package halo

// Identity is the normalized user identity produced by a login method.
//
// Every login method (OAuth, password, ...) returns an Identity. A method
// fills the fields it can supply and leaves the rest zero — a password login,
// for example, returns Email and Name but leaves ID and AvatarURL empty for
// the application's data store to populate.
type Identity struct {
	// ID is the provider's identifier for the account (e.g. the OAuth
	// account's ID), not your application's user ID. It is only unique within
	// a single provider, so the same ID may recur across different users.
	// Map it to your own user ID in your data store; do not treat it as a
	// primary key on its own.
	ID    string
	Email string
	// EmailVerified reports whether the provider considers Email verified.
	// Treat Email as untrusted for account linking unless this is true: an
	// attacker can set an unverified address matching a victim's on a second
	// provider. A login method leaves it false when it cannot vouch for Email.
	EmailVerified bool
	// Name is the human-readable display name (e.g. "Jane Doe"). It is for
	// presentation only: it is not unique, can change at any time, and may be
	// empty. Never use it to identify or look up an account.
	Name string
	// Username is the provider's login handle (e.g. a Discord tag or GitHub
	// login). It is unique within a single provider, so it identifies the
	// account there, but it is not unique across providers and a user may
	// rename it over time. Scope it by Provider before using it as a key, and
	// prefer mapping (Provider, ID) to your own user ID for a stable identifier.
	Username string
	// PasswordHash is only populated by the password provider.
	// Store it alongside the identity row; never expose it to the client.
	PasswordHash string
	AvatarURL    string
	Provider     string // "google", "discord", "password", etc.
}
