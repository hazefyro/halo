// Package auth holds the vocabulary shared by every authentication method in
// this module.
//
// It defines [Identity] — the normalized user that any login method produces —
// and the request-context plumbing for carrying an authenticated identity
// through an HTTP handler chain ([StoreIdentityInContext], [IdentityFromContext],
// [AuthRequired]).
//
// The login methods live in sibling packages and all feed into this vocabulary:
//
//   - auth/oauth     — OAuth login with pluggable providers
//   - auth/password  — local email + password login
//   - auth/session   — server-side session lifecycle keyed by Identity.ID
package auth
