// Package halo holds the vocabulary shared by every authentication method in
// this module.
//
// It defines [Identity] — the normalized user that any login method produces.
// Identity is a data-transfer object: a login method (OAuth, password, ...)
// returns one, the application maps it to a user in its own data store, and the
// application then establishes a session keyed by that user. Identity is never
// used to authorize requests — that is the session's job.
//
// The login methods and session lifecycle live in sibling packages:
//
//   - halo/oauth     — OAuth login with pluggable providers
//   - halo/password  — local email + password login
//   - halo/session   — server-side session lifecycle; [session.Manager.RequireAuth]
//     gates protected routes and [session.FromContext] exposes the active session
package halo
