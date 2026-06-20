package export

import (
	"fmt"
	"net/url"
	"strings"

	"node-config/internal/b64"
	"node-config/profile"
)

// ToShareLink exports a profile as standard share link.
func ToShareLink(p profile.Profile) (string, error) {
	switch p.Type {
	case profile.TypeSS:
		return ssLink(p)
	case profile.TypeTrojan:
		return trojanLink(p)
	case profile.TypeSOCKS:
		return socksLink(p)
	case profile.TypeVMess, profile.TypeVLESS:
		return v2rayLink(p)
	case profile.TypeHysteria2:
		return hysteria2Link(p)
	case profile.TypeTUIC:
		return tuicLink(p)
	case profile.TypeHysteria:
		return hysteria1Link(p)
	case profile.TypeHTTP:
		return httpLink(p)
	case profile.TypeSSR:
		return ssrLink(p)
	case profile.TypeAnyTLS:
		return anytlsLink(p)
	case profile.TypeNaive:
		return naiveLink(p)
	case profile.TypeSnell:
		return snellLink(p)
	default:
		return "", profile.ErrUnsupportedType
	}
}

func ssLink(p profile.Profile) (string, error) {
	user := b64.EncodeURLSafe([]byte(p.Method + ":" + p.Password))
	u := &url.URL{
		Scheme:   "https",
		User:     url.User(user),
		Host:     fmt.Sprintf("%s:%d", p.Server, p.Port),
		RawQuery: "",
	}
	if p.Plugin != "" {
		q := u.Query()
		q.Set("plugin", p.Plugin)
		u.RawQuery = q.Encode()
	}
	link := "ss://" + strings.TrimPrefix(u.String(), "https://")
	if p.Name != "" {
		link += "#" + url.QueryEscape(p.Name)
	}
	return link, nil
}

func trojanLink(p profile.Profile) (string, error) {
	u := &url.URL{
		Scheme: "https",
		User:   url.User(url.QueryEscape(p.Password)),
		Host:   fmt.Sprintf("%s:%d", p.Server, p.Port),
	}
	q := u.Query()
	if p.TLS != nil {
		if p.TLS.AllowInsecure {
			q.Set("allowInsecure", "1")
		}
		if p.TLS.SNI != "" {
			q.Set("sni", p.TLS.SNI)
		}
		if p.TLS.ALPN != "" {
			q.Set("alpn", p.TLS.ALPN)
		}
		if p.Transport != nil && p.Transport.Type != "" && p.Transport.Type != "tcp" {
			q.Set("type", p.Transport.Type)
		}
	}
	u.RawQuery = q.Encode()
	link := "trojan://" + strings.TrimPrefix(u.String(), "https://")
	if p.Name != "" {
		link += "#" + url.QueryEscape(p.Name)
	}
	return link, nil
}

func socksLink(p profile.Profile) (string, error) {
	scheme := "socks"
	switch p.SocksVersion {
	case "4":
		scheme = "socks4"
	case "4a":
		scheme = "socks4a"
	case "5":
		scheme = "socks5"
	}
	u := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("%s:%d", p.Server, p.Port),
	}
	if p.Username != "" {
		u.User = url.UserPassword(p.Username, p.Password)
	}
	link := scheme + "://" + strings.TrimPrefix(u.String(), "http://")
	if p.Name != "" {
		link += "#" + url.QueryEscape(p.Name)
	}
	return link, nil
}

func v2rayLink(p profile.Profile) (string, error) {
	scheme := "vmess"
	if p.Type == profile.TypeVLESS {
		scheme = "vless"
	}
	u := &url.URL{
		Scheme: "https",
		User:   url.User(url.QueryEscape(p.UUID)),
		Host:   fmt.Sprintf("%s:%d", p.Server, p.Port),
	}
	q := u.Query()
	if p.Transport != nil && p.Transport.Type != "" && p.Transport.Type != "tcp" {
		q.Set("type", p.Transport.Type)
		if p.Transport.Host != "" {
			q.Set("host", p.Transport.Host)
		}
		if p.Transport.Path != "" {
			q.Set("path", p.Transport.Path)
		}
		if p.Transport.ServiceName != "" {
			q.Set("serviceName", p.Transport.ServiceName)
		}
	}
	if p.TLS != nil && p.TLS.Enabled {
		sec := p.TLS.Security
		if sec == "" {
			sec = "tls"
		}
		q.Set("security", sec)
		if p.TLS.SNI != "" {
			q.Set("sni", p.TLS.SNI)
		}
		if p.TLS.AllowInsecure {
			q.Set("allowInsecure", "1")
		}
		if p.TLS.RealityPubKey != "" {
			q.Set("pbk", p.TLS.RealityPubKey)
		}
		if p.TLS.RealityShortID != "" {
			q.Set("sid", p.TLS.RealityShortID)
		}
	}
	if p.Flow != "" {
		q.Set("flow", p.Flow)
	}
	if p.TLS != nil && p.TLS.UTLSFingerprint != "" {
		q.Set("fp", p.TLS.UTLSFingerprint)
	}
	if p.Type == profile.TypeVMess && p.Encryption != "" && p.Encryption != "auto" {
		q.Set("encryption", p.Encryption)
	}
	u.RawQuery = q.Encode()
	link := scheme + "://" + strings.TrimPrefix(u.String(), "https://")
	if p.Name != "" {
		link += "#" + url.QueryEscape(p.Name)
	}
	return link, nil
}

func hysteria2Link(p profile.Profile) (string, error) {
	u := &url.URL{Scheme: "https", Host: fmt.Sprintf("%s:%d", p.Server, p.Port)}
	if p.Password != "" {
		if strings.Contains(p.Password, ":") {
			parts := strings.SplitN(p.Password, ":", 2)
			u.User = url.UserPassword(url.QueryEscape(parts[0]), url.QueryEscape(parts[1]))
		} else {
			u.User = url.User(url.QueryEscape(p.Password))
		}
	}
	q := u.Query()
	if p.ServerPorts != "" {
		q.Set("mport", p.ServerPorts)
	}
	if p.TLS != nil && p.TLS.SNI != "" {
		q.Set("sni", p.TLS.SNI)
	}
	if p.TLS != nil && p.TLS.AllowInsecure {
		q.Set("insecure", "1")
	}
	if p.Obfuscation != "" {
		q.Set("obfs-password", p.Obfuscation)
	}
	u.RawQuery = q.Encode()
	link := "hy2://" + strings.TrimPrefix(u.String(), "https://")
	if p.Name != "" {
		link += "#" + url.QueryEscape(p.Name)
	}
	return link, nil
}

func tuicLink(p profile.Profile) (string, error) {
	u := &url.URL{
		Scheme: "https",
		User:   url.UserPassword(url.QueryEscape(p.UUID), url.QueryEscape(p.Token)),
		Host:   fmt.Sprintf("%s:%d", p.Server, p.Port),
	}
	q := u.Query()
	if p.CongestionControl != "" {
		q.Set("congestion_control", p.CongestionControl)
	}
	if p.UDPRelayMode != "" {
		q.Set("udp_relay_mode", p.UDPRelayMode)
	}
	if p.TLS != nil && p.TLS.SNI != "" {
		q.Set("sni", p.TLS.SNI)
	}
	if p.TLS != nil && p.TLS.AllowInsecure {
		q.Set("allow_insecure", "1")
	}
	if p.DisableSNI {
		q.Set("disable_sni", "1")
	}
	u.RawQuery = q.Encode()
	link := "tuic://" + strings.TrimPrefix(u.String(), "https://")
	if p.Name != "" {
		link += "#" + url.QueryEscape(p.Name)
	}
	return link, nil
}
