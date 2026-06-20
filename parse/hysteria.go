package parse

import (
	"strconv"
	"strings"

	"node-config/internal/urlutil"
	"node-config/profile"
)

func parseHysteria2(raw string) (profile.Profile, error) {
	scheme := "hysteria2"
	if strings.HasPrefix(raw, "hy2://") {
		scheme = "hy2"
	}
	u, err := urlutil.ParseHTTPStyle(raw, scheme)
	if err != nil {
		return profile.Profile{}, profile.NewParseError(raw, profile.ErrInvalidFormat)
	}

	auth := u.User.Username()
	if pass, ok := u.User.Password(); ok && pass != "" {
		auth = u.User.Username() + ":" + pass
	}

	p := profile.Profile{
		Type:            profile.TypeHysteria2,
		HysteriaVersion: 2,
		Server:          u.Hostname(),
		Port:            portFromURL(u),
		Password:        auth,
		Name:            urlutil.FragmentName(u),
		TLS:             &profile.TLS{Enabled: true, Security: "tls"},
	}

	q := u.Query()
	if v := q.Get("mport"); v != "" {
		p.ServerPorts = v
	}
	if v := q.Get("sni"); v != "" {
		p.TLS.SNI = v
	}
	if q.Get("insecure") == "1" || q.Get("insecure") == "true" {
		p.TLS.AllowInsecure = true
	}
	if v := q.Get("obfs-password"); v != "" {
		p.Obfuscation = v
	}
	if v := q.Get("upmbps"); v != "" {
		p.UploadMbps, _ = strconv.Atoi(v)
	}
	if v := q.Get("downmbps"); v != "" {
		p.DownloadMbps, _ = strconv.Atoi(v)
	}
	return p, nil
}

func parseHysteria1(raw string) (profile.Profile, error) {
	u, err := urlutil.ParseHTTPStyle(raw, "hysteria")
	if err != nil {
		return profile.Profile{}, profile.NewParseError(raw, profile.ErrInvalidFormat)
	}

	p := profile.Profile{
		Type:            profile.TypeHysteria,
		HysteriaVersion: 1,
		ExternalPlugin:  "hysteria",
		Server:          u.Hostname(),
		Port:            portFromURL(u),
		Name:            urlutil.FragmentName(u),
		TLS:             &profile.TLS{Enabled: true, Security: "tls"},
	}

	q := u.Query()
	if v := q.Get("mport"); v != "" {
		p.ServerPorts = v
	} else {
		p.ServerPorts = strconv.Itoa(int(p.Port))
	}
	if v := q.Get("peer"); v != "" {
		p.TLS.SNI = v
	}
	if v := q.Get("auth"); v != "" {
		p.Password = v
	}
	if q.Get("insecure") == "1" || q.Get("insecure") == "true" {
		p.TLS.AllowInsecure = true
	}
	if v := q.Get("upmbps"); v != "" {
		p.UploadMbps, _ = strconv.Atoi(v)
	}
	if v := q.Get("downmbps"); v != "" {
		p.DownloadMbps, _ = strconv.Atoi(v)
	}
	if v := q.Get("alpn"); v != "" && v != "none" {
		p.TLS.ALPN = v
	}
	if v := q.Get("obfsParam"); v != "" {
		p.Obfuscation = v
	}
	return p, nil
}
