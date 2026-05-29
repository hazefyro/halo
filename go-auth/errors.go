package goauth

import "errors"

var (
	ErrProviderNotFound = errors.New("provider not registered")
	ErrStateMismatch    = errors.New("oauth state mismatch")
	ErrMissingCode      = errors.New("no code in callback request")
	ErrMissingUserID    = errors.New("provider returned user with empty ID")
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
		return "oauth callback error: " + e.Code + ": " + e.Description
	}
	return "oauth callback error: " + e.Code
}
