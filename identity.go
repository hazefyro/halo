package halo

// Identity is the normalized user identity produced by a login method.
//
// Every login method (OAuth, password, ...) returns an Identity. A method
// fills the fields it can supply and leaves the rest zero — a password login,
// for example, returns Email and Name but leaves ID and AvatarURL empty for
// the application's data store to populate.
type Identity struct {
	ID        string
	Email     string
	Name      string
	Username  string // login name: Discord tag, GitHub login
	AvatarURL string
	Provider  string // "google", "discord", "password", etc.
}
