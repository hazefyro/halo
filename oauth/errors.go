package oauth

import "errors"

var (
	// ErrProviderNotFound is returned when a provider name is not registered.
	ErrProviderNotFound = errors.New("oauth: provider not registered")
	// ErrStateMismatch is returned when callback state verification fails.
	ErrStateMismatch = errors.New("oauth: state mismatch")
	// ErrMissingCode is returned when an OAuth callback has no code.
	ErrMissingCode = errors.New("oauth: no code in callback request")
	// ErrMissingUserID is returned when provider userinfo has no usable ID.
	ErrMissingUserID = errors.New("oauth: provider returned user with empty ID")
)

// CallbackError is returned when the provider redirects back with ?error=.
// Code is the OAuth error code (e.g. "access_denied"); Description is the
// optional human-readable message from the provider.
type CallbackError struct {
	Code        string
	Description string
}

func (e *CallbackError) Error() string {
	if e.Description != "" {
		return "oauth: callback error: " + e.Code + ": " + e.Description
	}
	return "oauth: callback error: " + e.Code
}
