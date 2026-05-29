package hmacutil

import "testing"

func TestSignReturnsDeterministicHMAC(t *testing.T) {
	secret := []byte("secret")
	got := Sign(secret, "value")
	want := "50e03ebe65be98bb8bf11ba2c892d54c079aca2b0d3b0162769c6d757a25434f"
	if got != want {
		t.Fatalf("Sign() = %q, want %q", got, want)
	}
	if Sign(secret, "value") != got {
		t.Fatal("Sign() was not deterministic")
	}
}

func TestVerifyAcceptsMatchingSignature(t *testing.T) {
	secret := []byte("secret")
	if !Verify(secret, "value", Sign(secret, "value")) {
		t.Fatal("Verify() = false, want true")
	}
}

func TestVerifyRejectsMismatchedValue(t *testing.T) {
	secret := []byte("secret")
	if Verify(secret, "other", Sign(secret, "value")) {
		t.Fatal("Verify() = true, want false")
	}
}

func TestVerifyRejectsMismatchedSignature(t *testing.T) {
	if Verify([]byte("secret"), "value", "bad") {
		t.Fatal("Verify() = true, want false")
	}
}
