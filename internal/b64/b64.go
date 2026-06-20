package b64

import (
	"encoding/base64"
	"strings"
)

// DecodeURLSafe decodes standard or URL-safe base64.
func DecodeURLSafe(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if pad := len(s) % 4; pad != 0 {
		s += strings.Repeat("=", 4-pad)
	}
	if strings.ContainsAny(s, "-_") {
		return base64.URLEncoding.DecodeString(s)
	}
	return base64.StdEncoding.DecodeString(s)
}

// EncodeURLSafe encodes bytes with URL-safe base64 without padding.
func EncodeURLSafe(b []byte) string {
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
}

// DecodeURLSafeString decodes base64 to string.
func DecodeURLSafeString(s string) (string, error) {
	b, err := DecodeURLSafe(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
