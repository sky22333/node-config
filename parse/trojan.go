package parse

import (
	"net/url"
	"strings"

	"node-config/internal/urlutil"
	"node-config/profile"
)

func parseTrojan(raw string) (profile.Profile, error) {
	u, err := urlutil.ParseHTTPStyle(raw, "trojan")
	if err != nil {
		return profile.Profile{}, profile.NewParseError(raw, profile.ErrInvalidFormat)
	}

	password := u.User.Username()
	if pass, ok := u.User.Password(); ok && pass != "" {
		password = pass
	}

	p := profile.Profile{
		Type:     profile.TypeTrojan,
		Server:   u.Hostname(),
		Port:     portFromURL(u),
		Password: password,
		Name:     urlutil.FragmentName(u),
		TLS:      &profile.TLS{Enabled: true, Security: "tls"},
		Transport: &profile.Transport{Type: "tcp"},
	}

	q := u.Query()
	applyTrojanQuery(&p, q)

	if path := strings.Trim(strings.TrimPrefix(u.Path, "/"), "/"); path != "" {
		if p.Transport == nil {
			p.Transport = &profile.Transport{}
		}
		p.Transport.Path = path
	}

	return p, nil
}

func applyTrojanQuery(p *profile.Profile, q url.Values) {
	if p.TLS == nil {
		p.TLS = &profile.TLS{}
	}
	if v := q.Get("allowInsecure"); v == "1" || v == "true" {
		p.TLS.AllowInsecure = true
	}
	if v := q.Get("peer"); v != "" {
		p.TLS.SNI = v
	}
	if v := q.Get("sni"); v != "" {
		p.TLS.SNI = v
	}
	if v := q.Get("alpn"); v != "" && v != "none" {
		p.TLS.ALPN = v
	}

	transportType := q.Get("type")
	if transportType == "" {
		transportType = "tcp"
	}
	if transportType == "h2" || q.Get("headerType") == "http" {
		transportType = "http"
	}
	if p.Transport == nil {
		p.Transport = &profile.Transport{}
	}
	p.Transport.Type = transportType

	sec := q.Get("security")
	if sec == "" {
		sec = "tls"
	}
	if sec == "tls" || sec == "reality" {
		p.TLS.Security = "tls"
		p.TLS.Enabled = true
		if sec == "reality" {
			p.TLS.Security = "reality"
		}
		if v := q.Get("allowInsecure"); v == "1" || v == "true" {
			p.TLS.AllowInsecure = true
		}
		if v := q.Get("sni"); v != "" {
			p.TLS.SNI = v
		}
		if v := q.Get("host"); v != "" && p.TLS.SNI == "" {
			p.TLS.SNI = v
		}
		if v := q.Get("pbk"); v != "" {
			p.TLS.RealityPubKey = v
		}
		if v := q.Get("sid"); v != "" {
			p.TLS.RealityShortID = v
		}
	}

	switch transportType {
	case "ws", "http", "grpc":
		if v := q.Get("host"); v != "" {
			p.Transport.Host = v
		}
		if v := q.Get("path"); v != "" {
			p.Transport.Path = v
		}
		if v := q.Get("serviceName"); v != "" {
			p.Transport.ServiceName = v
		}
	}
}
