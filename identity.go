package halo

// Identity is the normalized user identity produced by a login method.
//
// Every login method (OAuth, password, ...) returns an Identity. A method
// fills the fields it can supply and leaves the rest zero — a password login,
// for example, returns Email and Name but leaves ID and AvatarURL empty for
// the application's data store to populate.
type Identity struct {
	ID    string
	Email string
	// EmailVerified reports whether the provider considers Email verified.
	// Treat Email as untrusted for account linking unless this is true: an
	// attacker can set an unverified address matching a victim's on a second
	// provider. A login method leaves it false when it cannot vouch for Email.
	EmailVerified bool
	Name          string
	Username      string // login name: Discord tag, GitHub login
	AvatarURL     string
	Provider      string // "google", "discord", "password", etc.
}
