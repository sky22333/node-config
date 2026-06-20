package build

import (
	"net/netip"

	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"node-config/profile"
)

func wireguardEndpoint(p profile.Profile, tag string) (option.Endpoint, error) {
	if p.WGPrivateKey == "" || p.PeerPublicKey == "" {
		return option.Endpoint{}, profile.ErrInvalidFormat
	}
	addrs := p.LocalAddresses
	if len(addrs) == 0 {
		addrs = []string{"172.16.0.2/32"}
	}
	var prefixes []netip.Prefix
	for _, a := range addrs {
		prefixes = append(prefixes, netip.MustParsePrefix(a))
	}
	allowed := p.AllowedIPs
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0", "::/0"}
	}
	var allowedPrefixes []netip.Prefix
	for _, a := range allowed {
		allowedPrefixes = append(allowedPrefixes, netip.MustParsePrefix(a))
	}
	peer := option.WireGuardPeer{
		Address:    p.Server,
		Port:       p.Port,
		PublicKey:  p.PeerPublicKey,
		AllowedIPs: badoption.Listable[netip.Prefix](allowedPrefixes),
	}
	if p.PreSharedKey != "" {
		peer.PreSharedKey = p.PreSharedKey
	}
	if r := parseReservedBytes(p.Reserved); len(r) > 0 {
		peer.Reserved = r
	}
	opts := &option.WireGuardEndpointOptions{
		PrivateKey: p.WGPrivateKey,
		Address:    badoption.Listable[netip.Prefix](prefixes),
		MTU:        p.WGMTU,
		Peers:      []option.WireGuardPeer{peer},
	}
	return option.Endpoint{
		Type:    constant.TypeWireGuard,
		Tag:     tag,
		Options: opts,
	}, nil
}

func parseReservedBytes(s string) []uint8 {
	s = trimSpace(s)
	if s == "" {
		return nil
	}
	if s[0] == '[' {
		s = trimSpace(s[1:])
		if i := len(s) - 1; i >= 0 && s[i] == ']' {
			s = s[:i]
		}
		parts := splitComma(s)
		if len(parts) == 3 {
			out := make([]uint8, 3)
			for i, p := range parts {
				var n int
				for _, c := range p {
					if c >= '0' && c <= '9' {
						n = n*10 + int(c-'0')
					}
				}
				out[i] = uint8(n)
			}
			return out
		}
	}
	return nil
}

func splitComma(s string) []string {
	var out []string
	for _, p := range splitByComma(s) {
		if p = trimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitByComma(s string) []string {
	return stringsSplit(s, ',')
}

func stringsSplit(s string, sep byte) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 {
		c := s[len(s)-1]
		if c == ' ' || c == '\t' {
			s = s[:len(s)-1]
			continue
		}
		break
	}
	return s
}

func isWireGuard(p profile.Profile) bool { return p.Type == profile.TypeWireGuard }

func isNonBuildable(p profile.Profile) bool {
	switch p.Type {
	case profile.TypeSSR, profile.TypeSnell, profile.TypeTrojanGo:
		return true
	default:
		return false
	}
}
