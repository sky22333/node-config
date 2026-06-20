package build

import (
	"strings"

	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"node-config/profile"
)

// Outbound builds a sing-box outbound from profile.
func Outbound(p profile.Profile, tag string) (option.Outbound, error) {
	if tag == "" {
		tag = TagProxy
	}
	switch p.Type {
	case profile.TypeSS:
		return ssOutbound(p, tag), nil
	case profile.TypeTrojan:
		return trojanOutbound(p, tag), nil
	case profile.TypeSOCKS:
		return socksOutbound(p, tag), nil
	case profile.TypeHTTP:
		return httpOutbound(p, tag), nil
	case profile.TypeVMess:
		return vmessOutbound(p, tag), nil
	case profile.TypeVLESS:
		return vlessOutbound(p, tag), nil
	case profile.TypeHysteria2:
		return hysteria2Outbound(p, tag), nil
	case profile.TypeHysteria:
		return hysteria1Outbound(p, tag), nil
	case profile.TypeTUIC:
		return tuicOutbound(p, tag), nil
	case profile.TypeAnyTLS:
		return anytlsOutbound(p, tag), nil
	case profile.TypeNaive:
		return naiveOutbound(p, tag), nil
	case profile.TypeShadowTLS:
		return shadowtlsOutbound(p, tag), nil
	case profile.TypeSSH:
		return sshOutbound(p, tag), nil
	case profile.TypeTor:
		return torOutbound(p, tag), nil
	case profile.TypeSSR:
		return option.Outbound{}, profile.ErrRemovedInSingBox
	case profile.TypeSnell, profile.TypeTrojanGo:
		return option.Outbound{}, profile.ErrUnsupportedType
	case profile.TypeWireGuard:
		return option.Outbound{}, profile.ErrInvalidFormat // use endpoint builder
	case profile.TypeConfig:
		if len(p.RawOutbound) > 0 {
			return rawOutbound(p.RawOutbound, tag)
		}
		return option.Outbound{}, profile.ErrInvalidFormat
	default:
		return option.Outbound{}, profile.ErrUnsupportedType
	}
}

func ssOutbound(p profile.Profile, tag string) option.Outbound {
	opts := &option.ShadowsocksOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     p.Server,
			ServerPort: p.Port,
		},
		Method:   p.Method,
		Password: p.Password,
	}
	if p.Plugin != "" {
		parts := strings.SplitN(p.Plugin, ";", 2)
		opts.Plugin = parts[0]
		if len(parts) > 1 {
			opts.PluginOptions = parts[1]
		}
		if opts.Plugin == "none" {
			opts.Plugin = ""
			opts.PluginOptions = ""
		}
	}
	return option.Outbound{Type: constant.TypeShadowsocks, Tag: tag, Options: opts}
}

func trojanOutbound(p profile.Profile, tag string) option.Outbound {
	opts := &option.TrojanOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     p.Server,
			ServerPort: p.Port,
		},
		Password: p.Password,
	}
	if p.TLS != nil {
		opts.TLS = outboundTLS(p)
	} else {
		opts.TLS = &option.OutboundTLSOptions{Enabled: true}
	}
	opts.Transport = v2rayTransport(p)
	return option.Outbound{Type: constant.TypeTrojan, Tag: tag, Options: opts}
}

func socksOutbound(p profile.Profile, tag string) option.Outbound {
	ver := p.SocksVersion
	if ver == "" {
		ver = "5"
	}
	return option.Outbound{
		Type: constant.TypeSOCKS,
		Tag:  tag,
		Options: &option.SOCKSOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     p.Server,
				ServerPort: p.Port,
			},
			Version:  ver,
			Username: p.Username,
			Password: p.Password,
		},
	}
}

func httpOutbound(p profile.Profile, tag string) option.Outbound {
	opts := &option.HTTPOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     p.Server,
			ServerPort: p.Port,
		},
		Username: p.Username,
		Password: p.Password,
	}
	if p.TLS != nil && p.TLS.Enabled {
		opts.TLS = &option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: p.TLS.SNI,
			Insecure:   p.TLS.AllowInsecure,
		}
	}
	return option.Outbound{Type: constant.TypeHTTP, Tag: tag, Options: opts}
}

func anytlsOutbound(p profile.Profile, tag string) option.Outbound {
	opts := &option.AnyTLSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: p.Server, ServerPort: p.Port},
		Password:      p.Password,
	}
	opts.TLS = outboundTLS(p)
	if opts.TLS == nil {
		opts.TLS = &option.OutboundTLSOptions{Enabled: true}
	}
	return option.Outbound{Type: constant.TypeAnyTLS, Tag: tag, Options: opts}
}

func naiveOutbound(p profile.Profile, tag string) option.Outbound {
	opts := &option.NaiveOutboundOptions{
		ServerOptions:       option.ServerOptions{Server: p.Server, ServerPort: p.Port},
		Username:            p.Username,
		Password:            p.Password,
		QUIC:                p.NaiveQUIC || p.NaiveProto == "quic",
		InsecureConcurrency: p.InsecureConcurrency,
	}
	if p.ExtraHeaders != "" {
		opts.ExtraHeaders = parseHTTPHeaderLines(p.ExtraHeaders)
	}
	opts.TLS = outboundTLS(p)
	if opts.TLS == nil {
		opts.TLS = &option.OutboundTLSOptions{Enabled: true}
	}
	return option.Outbound{Type: constant.TypeNaive, Tag: tag, Options: opts}
}

func shadowtlsOutbound(p profile.Profile, tag string) option.Outbound {
	ver := p.ShadowTLSVersion
	if ver == 0 {
		ver = 3
	}
	opts := &option.ShadowTLSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: p.Server, ServerPort: p.Port},
		Version:       ver,
		Password:      p.Password,
	}
	opts.TLS = outboundTLS(p)
	if opts.TLS == nil {
		opts.TLS = &option.OutboundTLSOptions{Enabled: true}
	}
	return option.Outbound{Type: constant.TypeShadowTLS, Tag: tag, Options: opts}
}

func sshOutbound(p profile.Profile, tag string) option.Outbound {
	user := p.SSHUser
	if user == "" {
		user = p.Username
	}
	opts := &option.SSHOutboundOptions{
		ServerOptions:        option.ServerOptions{Server: p.Server, ServerPort: p.Port},
		User:                 user,
		Password:             p.Password,
		PrivateKey:           listableStrings([]string{p.PrivateKey}),
		PrivateKeyPath:       p.PrivateKeyPath,
		PrivateKeyPassphrase: p.PrivateKeyPassphrase,
		HostKey:              listableStrings(p.HostKey),
	}
	return option.Outbound{Type: constant.TypeSSH, Tag: tag, Options: opts}
}

func torOutbound(p profile.Profile, tag string) option.Outbound {
	opts := &option.TorOutboundOptions{
		ExecutablePath: p.TorExecutable,
		DataDirectory:  p.TorDataDir,
		Options:        p.Torrc,
	}
	return option.Outbound{Type: constant.TypeTor, Tag: tag, Options: opts}
}

func parseHTTPHeaderLines(raw string) badoption.HTTPHeader {
	h := badoption.HTTPHeader{}
	for _, line := range splitHeaderLines(raw) {
		k, v, ok := splitHeaderKV(line)
		if !ok {
			continue
		}
		h[k] = append(h[k], v)
	}
	return h
}

func splitHeaderLines(raw string) []string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

func splitHeaderKV(line string) (string, string, bool) {
	i := strings.Index(line, ":")
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
}

func vmessOutbound(p profile.Profile, tag string) option.Outbound {
	sec := p.Encryption
	if sec == "" {
		sec = "auto"
	}
	opts := &option.VMessOutboundOptions{
		ServerOptions: option.ServerOptions{Server: p.Server, ServerPort: p.Port},
		UUID:          p.UUID,
		Security:      sec,
		AlterId:       p.AlterID,
	}
	if p.PacketEncoding != "" {
		opts.PacketEncoding = p.PacketEncoding
	}
	opts.TLS = outboundTLS(p)
	opts.Transport = v2rayTransport(p)
	return option.Outbound{Type: constant.TypeVMess, Tag: tag, Options: opts}
}

func vlessOutbound(p profile.Profile, tag string) option.Outbound {
	opts := &option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: p.Server, ServerPort: p.Port},
		UUID:          p.UUID,
		Flow:          p.Flow,
	}
	if p.PacketEncoding != "" {
		opts.PacketEncoding = &p.PacketEncoding
	}
	opts.TLS = outboundTLS(p)
	opts.Transport = v2rayTransport(p)
	return option.Outbound{Type: constant.TypeVLESS, Tag: tag, Options: opts}
}

func hysteria2Outbound(p profile.Profile, tag string) option.Outbound {
	server := option.ServerOptions{Server: p.Server, ServerPort: p.Port}
	if p.ServerPorts != "" {
		server.ServerPort = 0
	}
	opts := &option.Hysteria2OutboundOptions{
		ServerOptions: server,
		Password:      p.Password,
		UpMbps:        p.UploadMbps,
		DownMbps:      p.DownloadMbps,
		BBRProfile:    p.BBRProfile,
	}
	if p.ServerPorts != "" {
		opts.ServerPorts = badoption.Listable[string]{p.ServerPorts}
	}
	if p.HopInterval != "" {
		opts.HopInterval = durationFromString(p.HopInterval)
	}
	if p.HopIntervalMax != "" {
		opts.HopIntervalMax = durationFromString(p.HopIntervalMax)
	}
	if p.Obfuscation != "" {
		obfsType := p.ObfsType
		if obfsType == "" {
			obfsType = constant.Hysteria2ObfsTypeSalamander
		}
		opts.Obfs = &option.Hysteria2Obfs{Type: obfsType, Password: p.Obfuscation}
		if obfsType == constant.Hysteria2ObfsTypeGecko {
			opts.Obfs.GeckoOptions.MinPacketSize = p.ObfsMinSize
			opts.Obfs.GeckoOptions.MaxPacketSize = p.ObfsMaxSize
		}
	}
	opts.TLS = outboundTLS(p)
	if opts.TLS == nil {
		opts.TLS = &option.OutboundTLSOptions{Enabled: true, ALPN: badoption.Listable[string]{"h3"}}
	} else if len(opts.TLS.ALPN) == 0 {
		opts.TLS.ALPN = badoption.Listable[string]{"h3"}
	}
	return option.Outbound{Type: constant.TypeHysteria2, Tag: tag, Options: opts}
}

func hysteria1Outbound(p profile.Profile, tag string) option.Outbound {
	server := option.ServerOptions{Server: p.Server, ServerPort: p.Port}
	if p.ServerPorts != "" {
		server.ServerPort = 0
	}
	opts := &option.HysteriaOutboundOptions{
		ServerOptions: server,
		UpMbps:        p.UploadMbps,
		DownMbps:      p.DownloadMbps,
		Obfs:          p.Obfuscation,
	}
	if p.ServerPorts != "" {
		opts.ServerPorts = badoption.Listable[string]{p.ServerPorts}
	}
	if p.HopInterval != "" {
		opts.HopInterval = durationFromString(p.HopInterval)
	}
	if p.Password != "" {
		opts.AuthString = p.Password
	}
	opts.TLS = outboundTLS(p)
	if opts.TLS == nil {
		opts.TLS = &option.OutboundTLSOptions{Enabled: true}
	}
	return option.Outbound{Type: constant.TypeHysteria, Tag: tag, Options: opts}
}

func tuicOutbound(p profile.Profile, tag string) option.Outbound {
	cc := p.CongestionControl
	if cc == "" {
		cc = "cubic"
	}
	opts := &option.TUICOutboundOptions{
		ServerOptions:     option.ServerOptions{Server: p.Server, ServerPort: p.Port},
		UUID:              p.UUID,
		Password:          p.Token,
		CongestionControl: cc,
		UDPRelayMode:      p.UDPRelayMode,
		ZeroRTTHandshake:  p.ZeroRTTHandshake,
	}
	opts.TLS = outboundTLS(p)
	if opts.TLS == nil {
		opts.TLS = &option.OutboundTLSOptions{Enabled: true}
	}
	return option.Outbound{Type: constant.TypeTUIC, Tag: tag, Options: opts}
}

func parseFirstPort(s string) (uint16, error) {
	part := s
	if i := indexByte(s, ','); i >= 0 {
		part = s[:i]
	}
	if i := indexByte(part, ':'); i >= 0 {
		part = part[:i]
	}
	var n uint16
	for _, c := range part {
		if c < '0' || c > '9' {
			return 0, profile.ErrInvalidFormat
		}
		n = n*10 + uint16(c-'0')
	}
	return n, nil
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
