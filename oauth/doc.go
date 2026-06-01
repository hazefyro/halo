// Package oauth provides a small OAuth registry with pluggable providers.
//
// A [Registry] handles state generation and verification, provider dispatch,
// and callback completion. On a successful callback it stores the authenticated
// [auth.Identity] in the request context (via [auth.StoreIdentityInContext]) and
// makes the OAuth tokens and raw userinfo available through
// [CredentialsFromContext] and [RawDataFromContext]. Session storage is
// intentionally left to the caller.
//
// Provider implementations live under auth/oauth/providers.
package oauth
