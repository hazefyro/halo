package identity

import "errors"

// ErrNotFound is returned by a Store's lookup methods when no identity matches.
// Login methods rely on it to tell "no such identity" apart from a real error,
// so a Store implementation must return it (or wrap it) for a missing row.
var ErrNotFound = errors.New("identity: not found")
