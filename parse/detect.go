package parse

import (
	"strings"

	"node-config/internal/b64"
)

func tryBase64Decode(text string) (string, error) {
	line := strings.TrimSpace(text)
	if line == "" || strings.Contains(line, "://") {
		return text, errSkip
	}
	decoded, err := b64.DecodeURLSafeString(line)
	if err != nil {
		return text, err
	}
	if !strings.Contains(decoded, "://") && !strings.Contains(decoded, "proxies:") {
		return text, errSkip
	}
	return decoded, nil
}

var errSkip = errSentinel("skip")

type errSentinel string

func (e errSentinel) Error() string { return string(e) }
