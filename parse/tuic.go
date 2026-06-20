package parse

import (
	"strings"

	"node-config/internal/urlutil"
	"node-config/profile"
)

func parseTUIC(raw string) (profile.Profile, error) {
	u, err := urlutil.ParseHTTPStyle(raw, "tuic")
	if err != nil {
		return profile.Profile{}, profile.NewParseError(raw, profile.ErrInvalidFormat)
	}

	p := profile.Profile{
		Type:              profile.TypeTUIC,
		Server:            u.Hostname(),
		Port:              portFromURL(u),
		Name:              urlutil.FragmentName(u),
		CongestionControl: "cubic",
		UDPRelayMode:      "native",
		TLS:               &profile.TLS{Enabled: true, Security: "tls"},
	}

	user := u.User.Username()
	pass, _ := u.User.Password()
	if strings.Contains(user, ":") {
		parts := strings.SplitN(user, ":", 2)
		p.UUID = parts[0]
		p.Token = parts[1]
	} else {
		p.UUID = user
		p.Token = pass
	}

	q := u.Query()
	if v := q.Get("sni"); v != "" {
		p.TLS.SNI = v
	}
	if v := q.Get("congestion_control"); v != "" {
		p.CongestionControl = v
	}
	if v := q.Get("udp_relay_mode"); v != "" {
		p.UDPRelayMode = v
	}
	if v := q.Get("alpn"); v != "" && v != "none" {
		p.TLS.ALPN = v
	}
	if q.Get("allow_insecure") == "1" {
		p.TLS.AllowInsecure = true
	}
	if q.Get("disable_sni") == "1" {
		p.DisableSNI = true
	}
	return p, nil
}
