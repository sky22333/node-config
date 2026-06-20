package build

import (
	"net/netip"
	"net/url"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"node-config/profile"
)

func normalizeSettings(s profile.Settings) profile.Settings {
	d := profile.DefaultSettings()
	if s.MixedPort == 0 {
		s.MixedPort = d.MixedPort
	}
	if s.MixedListen == "" {
		s.MixedListen = d.MixedListen
	}
	if s.LogLevel == "" {
		s.LogLevel = d.LogLevel
	}
	if s.IPv6Mode == "" {
		s.IPv6Mode = d.IPv6Mode
	}
	if s.TunStack == "" {
		s.TunStack = d.TunStack
	}
	if s.MTU == 0 {
		s.MTU = d.MTU
	}
	if len(s.RemoteDNS) == 0 {
		s.RemoteDNS = d.RemoteDNS
	}
	if len(s.DirectDNS) == 0 {
		s.DirectDNS = d.DirectDNS
	}
	return s
}

func mixedListen(s profile.Settings) string {
	if s.AllowAccess {
		return "0.0.0.0"
	}
	return s.MixedListen
}

func domainStrategy(s profile.Settings, noAsIs bool) option.DomainStrategy {
	if !noAsIs {
		return option.DomainStrategy(C.DomainStrategyAsIS)
	}
	switch s.IPv6Mode {
	case profile.IPv6Disable:
		return option.DomainStrategy(C.DomainStrategyIPv4Only)
	case profile.IPv6Prefer:
		return option.DomainStrategy(C.DomainStrategyPreferIPv6)
	case profile.IPv6Only:
		return option.DomainStrategy(C.DomainStrategyIPv6Only)
	default:
		return option.DomainStrategy(C.DomainStrategyPreferIPv4)
	}
}

func dnsStrategy(s profile.Settings) option.DomainStrategy {
	switch s.IPv6Mode {
	case profile.IPv6Disable:
		return option.DomainStrategy(C.DomainStrategyIPv4Only)
	case profile.IPv6Enable:
		return option.DomainStrategy(C.DomainStrategyPreferIPv4)
	case profile.IPv6Prefer:
		return option.DomainStrategy(C.DomainStrategyPreferIPv6)
	case profile.IPv6Only:
		return option.DomainStrategy(C.DomainStrategyIPv6Only)
	default:
		return option.DomainStrategy(C.DomainStrategyAsIS)
	}
}

func prefixList(v4, v6 bool) badoption.Listable[netip.Prefix] {
	var out []netip.Prefix
	if v4 {
		out = append(out, netip.MustParsePrefix(vlan4Client))
	}
	if v6 {
		out = append(out, netip.MustParsePrefix(vlan6Client))
	}
	return badoption.Listable[netip.Prefix](out)
}

type dnsEndpoint struct {
	typ    string
	server string
	port   uint16
	path   string
}

func parseDNSEndpoint(raw string) dnsEndpoint {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") {
		return dnsEndpoint{}
	}
	if !strings.Contains(raw, "://") {
		host, port := splitHostPort(raw, 53)
		return dnsEndpoint{typ: "udp", server: host, port: port}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return dnsEndpoint{}
	}
	host, port := splitHostPort(u.Host, defaultDNSPort(u.Scheme))
	switch u.Scheme {
	case "https", "http":
		return dnsEndpoint{typ: "https", server: host, port: port, path: u.Path}
	case "tls":
		return dnsEndpoint{typ: "tls", server: host, port: port}
	case "quic":
		return dnsEndpoint{typ: "quic", server: host, port: port}
	case "h3":
		return dnsEndpoint{typ: "h3", server: host, port: port}
	case "udp":
		return dnsEndpoint{typ: "udp", server: host, port: port}
	default:
		return dnsEndpoint{typ: "udp", server: host, port: port}
	}
}

func splitHostPort(hostport string, defaultPort uint16) (string, uint16) {
	if hostport == "" {
		return "", defaultPort
	}
	if strings.HasPrefix(hostport, "[") {
		if ap, err := netip.ParseAddrPort(hostport); err == nil {
			return ap.Addr().String(), ap.Port()
		}
	}
	if i := strings.LastIndex(hostport, ":"); i > 0 {
		host := hostport[:i]
		var port uint16
		for _, c := range hostport[i+1:] {
			if c < '0' || c > '9' {
				return hostport, defaultPort
			}
			port = port*10 + uint16(c-'0')
		}
		return host, port
	}
	return hostport, defaultPort
}

func defaultDNSPort(scheme string) uint16 {
	switch scheme {
	case "https", "h3":
		return 443
	case "tls", "quic":
		return 853
	default:
		return 53
	}
}

func listableStrings(items []string) badoption.Listable[string] {
	if len(items) == 0 {
		return nil
	}
	return badoption.Listable[string](items)
}

func listablePorts(items []uint16) badoption.Listable[uint16] {
	if len(items) == 0 {
		return nil
	}
	return badoption.Listable[uint16](items)
}
