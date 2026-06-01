package hmacutil

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Sign returns the hex HMAC-SHA256 signature for value.
func Sign(secret []byte, value string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify reports whether sig matches the HMAC-SHA256 signature for value.
func Verify(secret []byte, value, sig string) bool {
	expected := Sign(secret, value)
	return hmac.Equal([]byte(expected), []byte(sig))
}
