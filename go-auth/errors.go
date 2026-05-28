package goauth

import "errors"

var (
	ErrProviderNotFound = errors.New("provider not registered")
	ErrStateMismatch    = errors.New("oauth state mismatch")
	ErrMissingCode      = errors.New("no code in callback request")
)
