package hmacutil

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

func Sign(secret []byte, value string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

func Verify(secret []byte, value, sig string) bool {
	expected := Sign(secret, value)
	return hmac.Equal([]byte(expected), []byte(sig))
}
