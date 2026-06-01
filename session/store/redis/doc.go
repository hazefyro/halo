// Package redis implements a session [github.com/hazefyro/halo/session.Store]
// backed by Redis. The cookie holds only an opaque session ID; the session
// lives in Redis and is looked up on each request.
//
// Because the server owns the session, it is revocable: [Store.Delete] takes
// effect immediately, even for a copied cookie. Revoking every session for a
// user is not built in — the store keys by session ID.
//
// Choose this store when you need revocation and can run Redis; the cost is a
// round-trip per request. For zero infrastructure, use
// github.com/hazefyro/halo/session/store/stateless instead.
package redis
