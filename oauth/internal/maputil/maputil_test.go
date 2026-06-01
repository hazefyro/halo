package maputil_test

import (
	"encoding/json"
	"testing"

	"github.com/hazefyro/auth/oauth/internal/maputil"
)

func TestGetStringReturnsStringValue(t *testing.T) {
	got := maputil.GetString(map[string]any{"email": "user@example.com"}, "email")
	if got != "user@example.com" {
		t.Fatalf("GetString() = %q, want user@example.com", got)
	}
}

func TestGetStringReturnsEmptyForMissingOrNonString(t *testing.T) {
	for _, m := range []map[string]any{
		{},
		{"email": 123},
		{"email": nil},
	} {
		if got := maputil.GetString(m, "email"); got != "" {
			t.Fatalf("GetString(%v) = %q, want empty", m, got)
		}
	}
}

func TestGetIDReturnsStringID(t *testing.T) {
	if got := maputil.GetID(map[string]any{"id": "123"}, "id"); got != "123" {
		t.Fatalf("GetID() = %q, want 123", got)
	}
}

func TestGetIDConvertsFloat64ID(t *testing.T) {
	if got := maputil.GetID(map[string]any{"id": float64(123)}, "id"); got != "123" {
		t.Fatalf("GetID() = %q, want 123", got)
	}
}

func TestGetIDConvertsJSONNumberID(t *testing.T) {
	if got := maputil.GetID(map[string]any{"id": json.Number("12345678901234567890")}, "id"); got != "12345678901234567890" {
		t.Fatalf("GetID() = %q, want precise json.Number", got)
	}
}

func TestGetIDReturnsEmptyForUnsupportedValues(t *testing.T) {
	for _, m := range []map[string]any{
		{},
		{"id": true},
		{"id": nil},
	} {
		if got := maputil.GetID(m, "id"); got != "" {
			t.Fatalf("GetID(%v) = %q, want empty", m, got)
		}
	}
}
