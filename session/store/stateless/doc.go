// Package stateless implements a session [github.com/hazefyro/halo/session.Store]
// that signs the whole session into a JWT carried in the cookie, so there is no
// server-side storage to run.
//
// The trade-off is that sessions cannot be revoked. The signed token is valid
// until it expires; [Store.Delete] only clears the browser's cookie, so a
// leaked token stays usable until expiry and there is no "log out everywhere".
// Rotating the signing key is the only way to invalidate stateless tokens, and
// it invalidates every session at once.
//
// Choose this store when zero infrastructure and easy scaling matter more than
// revocation, and keep the TTL short to bound how long a leaked token lives. If
// you need revocation, ban-on-demand, or sign-out-everywhere, use a server-side
// store such as github.com/hazefyro/halo/session/store/redis instead.
package stateless
