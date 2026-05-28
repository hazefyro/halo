package maputil

func GetString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}

	return ""
}
