// Package oauth provides a small OAuth registry with pluggable providers.
//
// A [Registry] handles state generation and verification, provider dispatch,
// and callback completion. [Registry.Callback] returns an [AuthResult] — the
// normalized [halo.Identity] plus the OAuth tokens and raw userinfo — and
// leaves it to the caller to map that identity to a user and establish a
// session. Session storage is intentionally out of scope.
//
// Provider implementations live under halo/oauth/providers.
package oauth
