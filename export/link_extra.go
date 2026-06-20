package export

import (
	"fmt"
	"net/url"
	"strings"

	"node-config/internal/b64"
	"node-config/profile"
)

func httpLink(p profile.Profile) (string, error) {
	scheme := "http"
	if p.TLS != nil && p.TLS.Enabled {
		scheme = "https"
	}
	u := &url.URL{Scheme: scheme, Host: fmt.Sprintf("%s:%d", p.Server, p.Port), Path: "/"}
	if p.Username != "" {
		u.User = url.UserPassword(p.Username, p.Password)
	}
	if p.TLS != nil && p.TLS.SNI != "" {
		q := u.Query()
		q.Set("sni", p.TLS.SNI)
		u.RawQuery = q.Encode()
	}
	link := u.String()
	if p.Name != "" {
		link += "#" + url.QueryEscape(p.Name)
	}
	return link, nil
}

func ssrLink(p profile.Profile) (string, error) {
	inner := fmt.Sprintf("%s:%d:%s:%s:%s:%s/?obfsparam=%s&protoparam=%s&remarks=%s",
		p.Server, p.Port, p.Protocol, p.Method, p.Obfs,
		b64.EncodeURLSafe([]byte(p.Password)),
		b64.EncodeURLSafe([]byte(p.ObfsParam)),
		b64.EncodeURLSafe([]byte(p.ProtocolParam)),
		b64.EncodeURLSafe([]byte(p.Name)),
	)
	return "ssr://" + b64.EncodeURLSafe([]byte(inner)), nil
}

func anytlsLink(p profile.Profile) (string, error) {
	u := &url.URL{
		Scheme: "https",
		User:   url.User(url.QueryEscape(p.Password)),
		Host:   fmt.Sprintf("%s:%d", p.Server, p.Port),
	}
	q := u.Query()
	if p.TLS != nil {
		if p.TLS.SNI != "" {
			q.Set("sni", p.TLS.SNI)
		}
		if p.TLS.AllowInsecure {
			q.Set("insecure", "1")
		}
		if p.TLS.UTLSFingerprint != "" {
			q.Set("fp", p.TLS.UTLSFingerprint)
		}
		if p.TLS.RealityPubKey != "" {
			q.Set("pbk", p.TLS.RealityPubKey)
		}
		if p.TLS.RealityShortID != "" {
			q.Set("sid", p.TLS.RealityShortID)
		}
	}
	u.RawQuery = q.Encode()
	link := "anytls://" + strings.TrimPrefix(u.String(), "https://")
	if p.Name != "" {
		link += "#" + url.QueryEscape(p.Name)
	}
	return link, nil
}

func naiveLink(p profile.Profile) (string, error) {
	proto := p.NaiveProto
	if proto == "" {
		proto = "https"
	}
	u := &url.URL{
		Scheme: "https",
		Host:   fmt.Sprintf("%s:%d", p.Server, p.Port),
	}
	if p.Username != "" {
		u.User = url.UserPassword(url.QueryEscape(p.Username), url.QueryEscape(p.Password))
	}
	q := u.Query()
	if p.TLS != nil && p.TLS.SNI != "" {
		q.Set("sni", p.TLS.SNI)
	}
	if p.ExtraHeaders != "" {
		q.Set("extra-headers", p.ExtraHeaders)
	}
	if p.InsecureConcurrency > 0 {
		q.Set("insecure-concurrency", fmt.Sprintf("%d", p.InsecureConcurrency))
	}
	u.RawQuery = q.Encode()
	link := "naive+" + proto + "://" + strings.TrimPrefix(u.String(), "https://")
	if p.Name != "" {
		link += "#" + url.QueryEscape(p.Name)
	}
	return link, nil
}

func snellLink(p profile.Profile) (string, error) {
	ver := p.SnellVersion
	if ver == 0 {
		ver = 4
	}
	u := &url.URL{
		Scheme: "https",
		User:   url.User(url.QueryEscape(p.Password)),
		Host:   fmt.Sprintf("%s:%d", p.Server, p.Port),
	}
	q := u.Query()
	q.Set("version", fmt.Sprintf("%d", ver))
	if p.SnellObfsMode != "" {
		q.Set("obfs-mode", p.SnellObfsMode)
	}
	if p.SnellObfsHost != "" {
		q.Set("obfs-host", p.SnellObfsHost)
	}
	if p.SnellReuse {
		q.Set("reuse", "true")
	}
	u.RawQuery = q.Encode()
	link := "snell://" + strings.TrimPrefix(u.String(), "https://")
	if p.Name != "" {
		link += "#" + url.QueryEscape(p.Name)
	}
	return link, nil
}

func hysteria1Link(p profile.Profile) (string, error) {
	u := &url.URL{
		Scheme: "https",
		Host:   fmt.Sprintf("%s:%d", p.Server, p.Port),
	}
	if p.Password != "" {
		u.User = url.User(url.QueryEscape(p.Password))
	}
	link := "hysteria://" + strings.TrimPrefix(u.String(), "https://")
	if p.Name != "" {
		link += "#" + url.QueryEscape(p.Name)
	}
	return link, nil
}
