package parse

import (
	"strings"

	"node-config/profile"
)

func clashV2Ray(m map[string]any, typ string) (profile.Profile, error) {
	isVLESS := typ == "vless"
	pType := profile.TypeVMess
	if isVLESS {
		pType = profile.TypeVLESS
	}
	p := profile.Profile{
		Type:       pType,
		Server:     str(m["server"]),
		Port:       uint16(intFromAny(m["port"])),
		Name:       str(m["name"]),
		UUID:       str(m["uuid"]),
		Encryption: "auto",
		Transport:  &profile.Transport{Type: "tcp"},
	}
	if !isVLESS {
		p.AlterID = intFromAny(m["alterId"])
		if v := str(m["cipher"]); v != "" {
			p.Encryption = v
		}
	}
	if isVLESS {
		if v := str(m["flow"]); strings.Contains(v, "xtls-rprx-vision") {
			p.Flow = "xtls-rprx-vision"
		}
		if v := str(m["encryption"]); v != "" {
			p.VlessEncryption = v
		}
		switch str(m["packet-encoding"]) {
		case "packetaddr":
			p.PacketEncoding = "packetaddr"
		case "xudp":
			p.PacketEncoding = "xudp"
		}
	}
	if m["tls"] == true || str(m["tls"]) == "true" {
		p.TLS = &profile.TLS{Enabled: true, Security: "tls"}
	}
	if v := str(m["servername"]); v != "" {
		if p.TLS == nil {
			p.TLS = &profile.TLS{}
		}
		p.TLS.SNI = v
	}
	if v := str(m["sni"]); v != "" {
		if p.TLS == nil {
			p.TLS = &profile.TLS{}
		}
		p.TLS.SNI = v
	}
	if m["skip-cert-verify"] == true || str(m["skip-cert-verify"]) == "true" {
		if p.TLS == nil {
			p.TLS = &profile.TLS{}
		}
		p.TLS.AllowInsecure = true
	}
	if v := str(m["client-fingerprint"]); v != "" {
		if p.TLS == nil {
			p.TLS = &profile.TLS{}
		}
		p.TLS.UTLSFingerprint = v
	}
	if opts, ok := m["reality-opts"].(map[string]any); ok {
		if p.TLS == nil {
			p.TLS = &profile.TLS{Security: "reality"}
		}
		p.TLS.Enabled = true
		p.TLS.RealityPubKey = str(opts["public-key"])
		p.TLS.RealityShortID = str(opts["short-id"])
	}
	if alpn, ok := m["alpn"].([]any); ok {
		if p.TLS == nil {
			p.TLS = &profile.TLS{}
		}
		parts := make([]string, 0, len(alpn))
		for _, a := range alpn {
			if s, ok := a.(string); ok {
				parts = append(parts, s)
			}
		}
		p.TLS.ALPN = strings.Join(parts, "\n")
	}
	switch str(m["network"]) {
	case "ws":
		p.Transport.Type = "ws"
		if ws, ok := m["ws-opts"].(map[string]any); ok {
			p.Transport.Path = str(ws["path"])
			if headers, ok := ws["headers"].(map[string]any); ok {
				for k, v := range headers {
					if strings.EqualFold(k, "host") {
						p.Transport.Host = str(v)
					}
				}
			}
		}
	case "grpc":
		p.Transport.Type = "grpc"
		if grpc, ok := m["grpc-opts"].(map[string]any); ok {
			p.Transport.ServiceName = str(grpc["grpc-service-name"])
		}
	case "h2", "http":
		p.Transport.Type = "http"
	}
	return p, nil
}

func clashHysteria2(m map[string]any) profile.Profile {
	p := profile.Profile{
		Type:            profile.TypeHysteria2,
		HysteriaVersion: 2,
		Name:            str(m["name"]),
		Server:          str(m["server"]),
		Port:            uint16(intFromAny(m["port"])),
		Password:        str(m["password"]),
		TLS:             &profile.TLS{Enabled: true, Security: "tls"},
	}
	if v := str(m["sni"]); v != "" {
		p.TLS.SNI = v
	}
	if m["skip-cert-verify"] == true || str(m["skip-cert-verify"]) == "true" {
		p.TLS.AllowInsecure = true
	}
	if v := str(m["obfs-password"]); v != "" {
		p.Obfuscation = v
	}
	if v := str(m["ports"]); v != "" {
		p.ServerPorts = v
	}
	if v := str(m["hop-interval"]); v != "" {
		p.HopInterval = v
	}
	if v := str(m["hop-interval-max"]); v != "" {
		p.HopIntervalMax = v
	}
	if v := str(m["obfs"]); v != "" {
		p.ObfsType = v
	}
	if v := intFromAny(m["obfs-min-size"]); v != 0 {
		p.ObfsMinSize = v
	}
	if v := intFromAny(m["obfs-max-size"]); v != 0 {
		p.ObfsMaxSize = v
	}
	if v := str(m["bbr-profile"]); v != "" {
		p.BBRProfile = v
	}
	return p
}

func clashTUIC(m map[string]any) profile.Profile {
	p := profile.Profile{
		Type:              profile.TypeTUIC,
		Name:              str(m["name"]),
		Server:            str(m["server"]),
		Port:              uint16(intFromAny(m["port"])),
		UUID:              str(m["uuid"]),
		Password:          str(m["password"]),
		Token:             str(m["password"]),
		CongestionControl: str(m["congestion-control"]),
		UDPRelayMode:      str(m["udp-relay-mode"]),
		TLS:               &profile.TLS{Enabled: true, Security: "tls"},
	}
	if v := str(m["sni"]); v != "" {
		p.TLS.SNI = v
	}
	if m["skip-cert-verify"] == true || str(m["skip-cert-verify"]) == "true" {
		p.TLS.AllowInsecure = true
	}
	if p.CongestionControl == "" {
		p.CongestionControl = "cubic"
	}
	return p
}
