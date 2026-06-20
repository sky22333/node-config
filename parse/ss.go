package parse

import (
	"net/url"
	"strings"

	"node-config/internal/b64"
	"node-config/internal/urlutil"
	"node-config/profile"
)

func parseSS(raw string) (profile.Profile, error) {
	body := strings.TrimPrefix(raw, "ss://")
	hashIdx := strings.Index(body, "#")
	main := body
	fragment := ""
	if hashIdx >= 0 {
		main = body[:hashIdx]
		fragment, _ = url.QueryUnescape(body[hashIdx+1:])
	}

	if strings.Contains(main, "@") {
		return parseSSSIP003(main, fragment)
	}
	return parseSSV2rayN(main, fragment)
}

func parseSSSIP003(main, fragment string) (profile.Profile, error) {
	u, err := urlutil.ParseHTTPStyle("ss://"+main, "ss")
	if err != nil {
		return profile.Profile{}, profile.NewParseError("ss://"+main, profile.ErrInvalidFormat)
	}

	if u.User != nil && u.User.Username() != "" {
		user := u.User.Username()
		if pass, ok := u.User.Password(); ok && pass != "" {
			return ssFromUser(u, user, pass, fragment)
		}
		if decoded, err := b64.DecodeURLSafeString(user); err == nil && strings.Contains(decoded, ":") {
			parts := strings.SplitN(decoded, ":", 2)
			return ssFromUser(u, parts[0], parts[1], fragment)
		}
		if strings.Contains(user, ":") {
			parts := strings.SplitN(user, ":", 2)
			return ssFromUser(u, parts[0], parts[1], fragment)
		}
	}

	// justmysocks: username empty, whole main part is base64
	decoded, err := b64.DecodeURLSafeString(main)
	if err != nil {
		return profile.Profile{}, profile.NewParseError("ss://"+main, err)
	}
	u2, err := url.Parse("https://" + decoded)
	if err != nil {
		return profile.Profile{}, profile.NewParseError("ss://"+main, profile.ErrInvalidFormat)
	}
	if fragment != "" {
		u2.Fragment = fragment
	}
	user := u2.User.Username()
	pass, _ := u2.User.Password()
	if pass == "" && strings.Contains(user, ":") {
		parts := strings.SplitN(user, ":", 2)
		return ssFromUser(u2, parts[0], parts[1], fragment)
	}
	return ssFromUser(u2, user, pass, fragment)
}

func ssFromUser(u *url.URL, method, password, fragment string) (profile.Profile, error) {
	if strings.Contains(method, ":") {
		parts := strings.SplitN(method, ":", 2)
		method = parts[0]
		password = parts[1]
	}
	p := profile.Profile{
		Type:     profile.TypeSS,
		Server:   u.Hostname(),
		Port:     portFromURL(u),
		Method:   method,
		Password: password,
		Plugin:   fixSSPlugin(u.Query().Get("plugin")),
		Name:     nameOrFragment(fragment, u),
	}
	return p, nil
}

func parseSSV2rayN(main, fragment string) (profile.Profile, error) {
	decoded, err := b64.DecodeURLSafeString(main)
	if err != nil {
		return profile.Profile{}, profile.NewParseError("ss://"+main, err)
	}
	u, err := url.Parse("https://" + decoded)
	if err != nil {
		return profile.Profile{}, profile.NewParseError("ss://"+main, profile.ErrInvalidFormat)
	}
	user := u.User.Username()
	pass, _ := u.User.Password()
	if strings.Contains(user, ":") {
		parts := strings.SplitN(user, ":", 2)
		user = parts[0]
		pass = parts[1]
	}
	name := fragment
	if name == "" {
		name = urlutil.FragmentName(u)
	}
	return profile.Profile{
		Type:     profile.TypeSS,
		Server:   u.Hostname(),
		Port:     portFromURL(u),
		Method:   user,
		Password: pass,
		Name:     name,
	}, nil
}

func fixSSPlugin(plugin string) string {
	if strings.HasPrefix(plugin, "simple-obfs") {
		return strings.Replace(plugin, "simple-obfs", "obfs-local", 1)
	}
	return plugin
}

func portFromURL(u *url.URL) uint16 {
	p := u.Port()
	if p == "" {
		if u.Scheme == "https" {
			return 443
		}
		return 80
	}
	var port uint16
	for _, c := range p {
		if c < '0' || c > '9' {
			return 0
		}
		port = port*10 + uint16(c-'0')
	}
	return port
}

func nameOrFragment(fragment string, u *url.URL) string {
	if fragment != "" {
		return fragment
	}
	return urlutil.FragmentName(u)
}
