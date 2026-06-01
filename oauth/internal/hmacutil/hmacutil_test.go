package hmacutil_test

import (
	"testing"

	"github.com/hazefyro/auth/oauth/internal/hmacutil"
)

func TestSignReturnsDeterministicHMAC(t *testing.T) {
	secret := []byte("secret")
	got := hmacutil.Sign(secret, "value")
	want := "50e03ebe65be98bb8bf11ba2c892d54c079aca2b0d3b0162769c6d757a25434f"
	if got != want {
		t.Fatalf("Sign() = %q, want %q", got, want)
	}
	if hmacutil.Sign(secret, "value") != got {
		t.Fatal("Sign() was not deterministic")
	}
}

func TestVerifyAcceptsMatchingSignature(t *testing.T) {
	secret := []byte("secret")
	if !hmacutil.Verify(secret, "value", hmacutil.Sign(secret, "value")) {
		t.Fatal("Verify() = false, want true")
	}
}

func TestVerifyRejectsMismatchedValue(t *testing.T) {
	secret := []byte("secret")
	if hmacutil.Verify(secret, "other", hmacutil.Sign(secret, "value")) {
		t.Fatal("Verify() = true, want false")
	}
}

func TestVerifyRejectsMismatchedSignature(t *testing.T) {
	if hmacutil.Verify([]byte("secret"), "value", "bad") {
		t.Fatal("Verify() = true, want false")
	}
}
