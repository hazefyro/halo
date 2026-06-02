package password

import "errors"

var (
	ErrEmailRequired      = errors.New("password: email is required")
	ErrPasswordRequired   = errors.New("password: password is required")
	ErrNameRequired       = errors.New("password: name is required")
	ErrUsernameRequired   = errors.New("password: username is required")
	ErrAvatarRequired     = errors.New("password: avatar is required")
	ErrEmailTaken         = errors.New("password: email already taken")
	ErrInvalidCredentials = errors.New("password: invalid credentials")
)
