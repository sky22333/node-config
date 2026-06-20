package parse

import (
	"node-config/profile"
)

// Result is returned by ParseText.
type Result struct {
	Profiles        []profile.Profile `json:"profiles"`
	SubscriptionURL string            `json:"subscription_url,omitempty"`
	Warnings        []string          `json:"warnings,omitempty"`
}

// Options configures parsing behavior.
type Options struct {
	FileName string
}

// ParseLinks parses multiple share links.
func ParseLinks(links []string) ([]profile.Profile, error) {
	out := make([]profile.Profile, 0, len(links))
	for _, link := range links {
		link = trimLink(link)
		if link == "" {
			continue
		}
		if sub := detectSubscriptionURL(link); sub != "" {
			return nil, profile.NewParseError(link, profile.ErrInvalidFormat)
		}
		p, err := parseLink(link)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, profile.ErrEmptyInput
	}
	return out, nil
}

// ParseText is the main entry: clipboard, file body, or subscription content.
func ParseText(text string, opts Options) (*Result, error) {
	text = trimText(text)
	if text == "" {
		return nil, profile.ErrEmptyInput
	}

	if sub := detectSubscriptionURL(text); sub != "" {
		return &Result{SubscriptionURL: sub}, nil
	}

	if profiles, ok := tryClashYAML(text); ok {
		return &Result{Profiles: profiles}, nil
	}

	if profiles, ok := tryWireGuardINI(text); ok {
		return &Result{Profiles: profiles}, nil
	}

	if profiles, ok := tryJSON(text); ok {
		return &Result{Profiles: profiles}, nil
	}

	if decoded, err := tryBase64Decode(text); err == nil && decoded != text {
		if r, err := ParseText(decoded, opts); err == nil && len(r.Profiles) > 0 {
			return r, nil
		}
	}

	links := splitLinks(text)
	profiles, err := ParseLinks(links)
	if err != nil {
		return nil, err
	}
	return &Result{Profiles: profiles}, nil
}

func parseLink(link string) (profile.Profile, error) {
	switch {
	case hasPrefix(link, "ss://"):
		return parseSS(link)
	case hasPrefix(link, "vmess://"), hasPrefix(link, "vless://"):
		return parseV2Ray(link)
	case hasPrefix(link, "hysteria://"):
		return parseHysteria1(link)
	case hasPrefix(link, "hysteria2://"), hasPrefix(link, "hy2://"):
		return parseHysteria2(link)
	case hasPrefix(link, "tuic://"):
		return parseTUIC(link)
	case hasPrefix(link, "trojan://"):
		return parseTrojan(link)
	case hasPrefix(link, "ssr://"):
		return parseSSR(link)
	case hasPrefix(link, "naive+"):
		return parseNaive(link)
	case hasPrefix(link, "anytls://"):
		return parseAnyTLS(link)
	case hasPrefix(link, "snell://"):
		return parseSnell(link)
	case hasPrefix(link, "http://"), hasPrefix(link, "https://"):
		return parseHTTP(link)
	case hasPrefix(link, "socks://"), hasPrefix(link, "socks4://"), hasPrefix(link, "socks4a://"), hasPrefix(link, "socks5://"):
		return parseSOCKS(link)
	default:
		return profile.Profile{}, profile.NewParseError(link, profile.ErrUnsupportedScheme)
	}
}

func detectSubscriptionURL(s string) string {
	s = trimLink(s)
	if hasPrefix(s, "clash://install-config?") || hasPrefix(s, "sn://subscription?") {
		return s
	}
	return ""
}

func splitLinks(text string) []string {
	var links []string
	for _, line := range splitLines(text) {
		for _, part := range splitFields(line) {
			if part != "" {
				links = append(links, part)
			}
		}
	}
	return links
}

func trimLink(s string) string {
	return trimSpace(s)
}

func trimText(s string) string {
	return trimSpace(s)
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func splitLines(text string) []string {
	return splitByNewline(text)
}

func splitFields(line string) []string {
	return splitBySpace(line)
}
