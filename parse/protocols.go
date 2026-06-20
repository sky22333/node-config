package parse

import (
	"net/url"
	"strings"

	"node-config/internal/b64"
	"node-config/internal/urlutil"
	"node-config/profile"
)

func parseSSR(raw string) (profile.Profile, error) {
	body := strings.TrimPrefix(raw, "ssr://")
	decoded, err := b64.DecodeURLSafe(body)
	if err != nil {
		return profile.Profile{}, profile.NewParseError(raw, profile.ErrInvalidFormat)
	}
	parts := strings.Split(string(decoded), ":")
	if len(parts) < 6 {
		return profile.Profile{}, profile.NewParseError(raw, profile.ErrInvalidFormat)
	}
	port := intFromAny(parts[1])
	p := profile.Profile{
		Type:     profile.TypeSSR,
		Server:   parts[0],
		Port:     uint16(port),
		Protocol: parts[2],
		Method:   parts[3],
		Obfs:     parts[4],
	}
	passPart := parts[5]
	passMain := passPart
	query := ""
	if i := strings.Index(passPart, "/?"); i >= 0 {
		passMain = passPart[:i]
		query = passPart[i+2:]
	} else if i := strings.Index(passPart, "?"); i >= 0 {
		passMain = passPart[:i]
		query = passPart[i+1:]
	}
	if pw, err := b64.DecodeURLSafe(passMain); err == nil {
		p.Password = string(pw)
	}
	if query != "" {
		q, _ := url.ParseQuery(query)
		if v := q.Get("obfsparam"); v != "" {
			if b, err := b64.DecodeURLSafe(v); err == nil {
				p.ObfsParam = string(b)
			}
		}
		if v := q.Get("protoparam"); v != "" {
			if b, err := b64.DecodeURLSafe(v); err == nil {
				p.ProtocolParam = string(b)
			}
		}
		if v := q.Get("remarks"); v != "" {
			if b, err := b64.DecodeURLSafe(v); err == nil {
				p.Name = string(b)
			}
		}
	}
	return p, nil
}

func parseNaive(raw string) (profile.Profile, error) {
	plus := strings.Index(raw, "+")
	if plus < 0 {
		return profile.Profile{}, profile.NewParseError(raw, profile.ErrInvalidFormat)
	}
	afterPlus := raw[plus+1:]
	colon := strings.Index(afterPlus, "://")
	if colon < 0 {
		return profile.Profile{}, profile.NewParseError(raw, profile.ErrInvalidFormat)
	}
	proto := afterPlus[:colon]
	after := afterPlus[colon+3:]
	u, err := urlutil.ParseHTTPStyle("https://"+after, "https")
	if err != nil {
		return profile.Profile{}, profile.NewParseError(raw, profile.ErrInvalidFormat)
	}
	p := profile.Profile{
		Type:       profile.TypeNaive,
		NaiveProto: proto,
		Server:     u.Hostname(),
		Port:       portFromURL(u),
		Username:   u.User.Username(),
		Name:       u.Fragment,
		TLS:        &profile.TLS{Enabled: true, Security: "tls"},
	}
	if pass, ok := u.User.Password(); ok {
		p.Password = pass
	}
	q := u.Query()
	if v := q.Get("sni"); v != "" {
		p.TLS.SNI = v
	}
	if v := q.Get("extra-headers"); v != "" {
		p.ExtraHeaders = strings.ReplaceAll(v, "\r\n", "\n")
	}
	if v := q.Get("insecure-concurrency"); v != "" {
		p.InsecureConcurrency = intFromAny(v)
	}
	return p, nil
}

func parseAnyTLS(raw string) (profile.Profile, error) {
	u, err := urlutil.ParseHTTPStyle(strings.Replace(raw, "anytls://", "https://", 1), "https")
	if err != nil {
		return profile.Profile{}, profile.NewParseError(raw, profile.ErrInvalidFormat)
	}
	p := profile.Profile{
		Type:     profile.TypeAnyTLS,
		Server:   u.Hostname(),
		Port:     portFromURL(u),
		Password: u.User.Username(),
		Name:     u.Fragment,
		TLS:      &profile.TLS{Enabled: true, Security: "tls"},
	}
	q := u.Query()
	if v := q.Get("sni"); v != "" {
		p.TLS.SNI = v
	}
	if q.Get("insecure") == "1" || q.Get("insecure") == "true" {
		p.TLS.AllowInsecure = true
	}
	if v := q.Get("fp"); v != "" {
		p.TLS.UTLSFingerprint = v
	}
	if v := q.Get("pbk"); v != "" {
		p.TLS.Security = "reality"
		p.TLS.RealityPubKey = v
	}
	if v := q.Get("sid"); v != "" {
		p.TLS.RealityShortID = v
	}
	return p, nil
}

func parseSnell(raw string) (profile.Profile, error) {
	u, err := urlutil.ParseHTTPStyle(strings.Replace(raw, "snell://", "https://", 1), "https")
	if err != nil {
		return profile.Profile{}, profile.NewParseError(raw, profile.ErrInvalidFormat)
	}
	psk, _ := url.PathUnescape(u.User.Username())
	p := profile.Profile{
		Type:           profile.TypeSnell,
		Server:         u.Hostname(),
		Port:           portFromURL(u),
		Password:       psk,
		Name:           u.Fragment,
		SnellVersion:   4,
		ExternalPlugin: "snell",
	}
	q := u.Query()
	if v := q.Get("version"); v != "" {
		p.SnellVersion = intFromAny(v)
	}
	p.SnellObfsMode = q.Get("obfs-mode")
	p.SnellObfsHost = q.Get("obfs-host")
	p.SnellReuse = q.Get("reuse") == "true"
	if v := q.Get("network"); v != "" {
		_ = v
	}
	return p, nil
}

func parseHTTP(raw string) (profile.Profile, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Path != "" && u.Path != "/" {
		return profile.Profile{}, profile.NewParseError(raw, profile.ErrInvalidFormat)
	}
	p := profile.Profile{
		Type:   profile.TypeHTTP,
		Server: u.Hostname(),
		Port:     portFromURL(u),
		Name:   u.Fragment,
	}
	if u.User != nil {
		p.Username = u.User.Username()
		p.Password, _ = u.User.Password()
	}
	if u.Scheme == "https" {
		p.TLS = &profile.TLS{Enabled: true, Security: "tls"}
	}
	if v := u.Query().Get("sni"); v != "" {
		if p.TLS == nil {
			p.TLS = &profile.TLS{Enabled: true, Security: "tls"}
		}
		p.TLS.SNI = v
	}
	if p.Port == 0 {
		if u.Scheme == "https" {
			p.Port = 443
		} else {
			p.Port = 80
		}
	}
	return p, nil
}
