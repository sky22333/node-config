package parse

import (
	"strings"

	"node-config/internal/b64"
	"node-config/internal/urlutil"
	"node-config/profile"
)

func parseSOCKS(raw string) (profile.Profile, error) {
	after := raw[strings.Index(raw, "://")+3:]
	u, err := urlutil.ParseHTTPStyle("http://"+after, "http")
	if err != nil {
		return profile.Profile{}, profile.NewParseError(raw, profile.ErrInvalidFormat)
	}

	version := "5"
	switch {
	case strings.HasPrefix(raw, "socks4a://"):
		version = "4a"
	case strings.HasPrefix(raw, "socks4://"):
		version = "4"
	case strings.HasPrefix(raw, "socks5://"), strings.HasPrefix(raw, "socks://"):
		version = "5"
	}

	user := ""
	pass := ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}

	if pass == "" && user != "" {
		if decoded, err := b64.DecodeURLSafeString(user); err == nil && strings.Contains(decoded, ":") {
			parts := strings.SplitN(decoded, ":", 2)
			user = parts[0]
			pass = parts[1]
		}
	}

	return profile.Profile{
		Type:         profile.TypeSOCKS,
		Server:       u.Hostname(),
		Port:         portFromURL(u),
		Username:     user,
		Password:     pass,
		SocksVersion: version,
		Name:         urlutil.FragmentName(u),
	}, nil
}
