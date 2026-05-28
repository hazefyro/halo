package maputil

import "fmt"

func GetString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}

	return ""
}

func GetID(m map[string]any, key string) string {
	switch v := m[key].(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%.0f", v)
	}
	return ""
}
