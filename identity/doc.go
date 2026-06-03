// Package identity defines the persistence contract shared by every login
// method in this module.
//
// A login method (OAuth, password, ...) produces a [halo.Identity]; an
// application persists it through a [Store] of its own implementation. The
// interface here holds only the operation every method needs; each login
// method extends it in its own package with the lookups it requires.
package identity
