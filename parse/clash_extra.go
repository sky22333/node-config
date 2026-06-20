package parse

import (
	"fmt"

	"node-config/profile"
)

func clashSSR(m map[string]any) (profile.Profile, error) {
	return profile.Profile{
		Type:          profile.TypeSSR,
		Name:          str(m["name"]),
		Server:        str(m["server"]),
		Port:          uint16(intFromAny(m["port"])),
		Method:        clashCipher(str(m["cipher"])),
		Password:      str(m["password"]),
		Protocol:      str(m["protocol"]),
		ProtocolParam: str(m["protocol-param"]),
		Obfs:          str(m["obfs"]),
		ObfsParam:     str(m["obfs-param"]),
	}, nil
}

func clashAnyTLS(m map[string]any) (profile.Profile, error) {
	p := profile.Profile{
		Type:     profile.TypeAnyTLS,
		Name:     str(m["name"]),
		Server:   str(m["server"]),
		Port:     uint16(intFromAny(m["port"])),
		Password: str(m["password"]),
		TLS:      &profile.TLS{Enabled: true, Security: "tls"},
	}
	if v := str(m["sni"]); v != "" {
		p.TLS.SNI = v
	}
	if m["skip-cert-verify"] == true || str(m["skip-cert-verify"]) == "true" {
		p.TLS.AllowInsecure = true
	}
	if v := str(m["client-fingerprint"]); v != "" {
		p.TLS.UTLSFingerprint = v
	}
	if v := str(m["reality-opts"]); v != "" {
		_ = v
	}
	if opts, ok := m["reality-opts"].(map[string]any); ok {
		p.TLS.Security = "reality"
		p.TLS.RealityPubKey = str(opts["public-key"])
		p.TLS.RealityShortID = str(opts["short-id"])
	}
	return p, nil
}

func clashWireGuard(m map[string]any) (profile.Profile, error) {
	src := m
	if peers, ok := m["peers"].([]any); ok && len(peers) > 0 {
		if pm, ok := peers[0].(map[string]any); ok {
			src = pm
		}
	}
	p := profile.Profile{
		Type:         profile.TypeWireGuard,
		Name:         str(m["name"]),
		Server:       str(src["server"]),
		Port:         uint16(intFromAny(src["port"])),
		WGPrivateKey: str(src["private-key"]),
		PeerPublicKey: str(src["public-key"]),
		PreSharedKey: str(src["pre-shared-key"]),
		WGMTU:        uint32(intFromAny(src["mtu"])),
	}
	if p.WGPrivateKey == "" {
		p.WGPrivateKey = str(m["private-key"])
	}
	if ip := str(src["ip"]); ip != "" {
		if !containsSlash(ip) {
			ip += "/32"
		}
		p.LocalAddresses = []string{ip}
	}
	if ip6 := str(src["ipv6"]); ip6 != "" {
		if !containsSlash(ip6) {
			ip6 += "/128"
		}
		p.LocalAddresses = append(p.LocalAddresses, ip6)
	}
	if v := src["reserved"]; v != nil {
		switch x := v.(type) {
		case []any:
			if len(x) == 3 {
				p.Reserved = fmt.Sprintf("[%v %v %v]", x[0], x[1], x[2])
			}
		default:
			p.Reserved = str(v)
		}
	}
	return p, nil
}

func clashSnell(m map[string]any) (profile.Profile, error) {
	return profile.Profile{
		Type:           profile.TypeSnell,
		Name:           str(m["name"]),
		Server:         str(m["server"]),
		Port:           uint16(intFromAny(m["port"])),
		Password:       str(m["psk"]),
		SnellVersion:   intFromAny(m["version"]),
		SnellObfsMode:  str(m["obfs-opts"]),
		ExternalPlugin: "snell",
	}, nil
}

func clashSSH(m map[string]any) (profile.Profile, error) {
	p := profile.Profile{
		Type:     profile.TypeSSH,
		Name:     str(m["name"]),
		Server:   str(m["server"]),
		Port:     uint16(intFromAny(m["port"])),
		SSHUser:  str(m["username"]),
		Password: str(m["password"]),
	}
	if v := str(m["private-key"]); v != "" {
		p.PrivateKey = v
	}
	return p, nil
}

func clashShadowTLS(m map[string]any) (profile.Profile, error) {
	p := profile.Profile{
		Type:             profile.TypeShadowTLS,
		Name:             str(m["name"]),
		Server:           str(m["server"]),
		Port:             uint16(intFromAny(m["port"])),
		Password:         str(m["password"]),
		ShadowTLSVersion: intFromAny(m["version"]),
		TLS:              &profile.TLS{Enabled: true, Security: "tls"},
	}
	if v := str(m["sni"]); v != "" {
		p.TLS.SNI = v
	}
	if p.ShadowTLSVersion == 0 {
		p.ShadowTLSVersion = 3
	}
	return p, nil
}

func clashNaive(m map[string]any) (profile.Profile, error) {
	p := profile.Profile{
		Type:       profile.TypeNaive,
		Name:       str(m["name"]),
		Server:     str(m["server"]),
		Port:       uint16(intFromAny(m["port"])),
		Username:   str(m["username"]),
		Password:   str(m["password"]),
		NaiveProto: str(m["protocol"]),
		TLS:        &profile.TLS{Enabled: true, Security: "tls"},
	}
	if p.NaiveProto == "" {
		p.NaiveProto = "https"
	}
	if v := str(m["sni"]); v != "" {
		p.TLS.SNI = v
	}
	return p, nil
}

func clashTor(m map[string]any) (profile.Profile, error) {
	return profile.Profile{
		Type: profile.TypeTor,
		Name: str(m["name"]),
	}, nil
}

func containsSlash(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return true
		}
	}
	return false
}
