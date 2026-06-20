package parse

import "strings"

func trimSpace(s string) string {
	return strings.TrimSpace(s)
}

func splitByNewline(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.Split(s, "\n")
}

func splitBySpace(s string) []string {
	return strings.Fields(s)
}
