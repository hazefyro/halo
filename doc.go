// Package halo holds the vocabulary shared by every authentication method in
// this module.
//
// It defines [Identity] — the normalized user that any login method produces —
// and the request-context plumbing for carrying an authenticated identity
// through an HTTP handler chain ([StoreIdentityInContext], [IdentityFromContext],
// [AuthRequired]).
//
// The login methods live in sibling packages and all feed into this vocabulary:
//
//   - halo/oauth     — OAuth login with pluggable providers
//   - halo/password  — local email + password login
//   - halo/session   — server-side session lifecycle keyed by Identity.ID
package halo
