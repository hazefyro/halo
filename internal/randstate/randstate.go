package randstate

import (
	"crypto/rand"
	"encoding/hex"
)

// RandomState returns a random 16-byte state encoded as hex.
func RandomState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
