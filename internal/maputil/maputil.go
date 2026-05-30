package maputil

import (
	"encoding/json"
	"fmt"
)

// GetString returns the string value for key, or an empty string.
func GetString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// GetID returns a provider ID as a string.
func GetID(m map[string]any, key string) string {
	switch v := m[key].(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%.0f", v)
	case json.Number:
		return v.String()
	}
	return ""
}
