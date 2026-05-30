package randstate

import (
	"encoding/hex"
	"testing"
)

func TestRandomStateFormat(t *testing.T) {
	got, err := RandomState()
	if err != nil {
		t.Fatalf("RandomState() error = %v", err)
	}
	if len(got) != 32 {
		t.Fatalf("len(RandomState()) = %d, want 32", len(got))
	}
	if _, err := hex.DecodeString(got); err != nil {
		t.Fatalf("RandomState() = %q, want hex: %v", got, err)
	}
}

func TestRandomStateUniqueness(t *testing.T) {
	first, err := RandomState()
	if err != nil {
		t.Fatalf("RandomState() error = %v", err)
	}
	second, err := RandomState()
	if err != nil {
		t.Fatalf("RandomState() error = %v", err)
	}
	if first == second {
		t.Fatalf("RandomState() returned duplicate %q", first)
	}
}
