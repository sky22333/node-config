package build

import (
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"node-config/profile"
)

func outboundTLS(p profile.Profile) *option.OutboundTLSOptions {
	if p.TLS == nil {
		return nil
	}
	tls := &option.OutboundTLSOptions{
		Enabled:    p.TLS.Enabled || p.TLS.Security == "tls" || p.TLS.Security == "reality",
		ServerName: p.TLS.SNI,
		Insecure:   p.TLS.AllowInsecure,
	}
	if p.TLS.ALPN != "" {
		tls.ALPN = badoption.Listable[string]{p.TLS.ALPN}
	}
	if p.TLS.UTLSFingerprint != "" {
		tls.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: p.TLS.UTLSFingerprint}
	}
	if p.TLS.RealityPubKey != "" {
		tls.Reality = &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: p.TLS.RealityPubKey,
			ShortID:   p.TLS.RealityShortID,
		}
	}
	if p.DisableSNI {
		tls.DisableSNI = true
	}
	return tls
}

func v2rayTransport(p profile.Profile) *option.V2RayTransportOptions {
	if p.Transport == nil || p.Transport.Type == "" || p.Transport.Type == "tcp" {
		return nil
	}
	t := &option.V2RayTransportOptions{}
	switch p.Transport.Type {
	case "http", "h2":
		t.Type = C.V2RayTransportTypeHTTP
	case "ws":
		t.Type = C.V2RayTransportTypeWebsocket
	case "grpc":
		t.Type = C.V2RayTransportTypeGRPC
	case "httpupgrade":
		t.Type = C.V2RayTransportTypeHTTPUpgrade
	default:
		t.Type = p.Transport.Type
	}
	switch t.Type {
	case C.V2RayTransportTypeHTTP:
		if p.Transport.Host != "" {
			t.HTTPOptions.Host = badoption.Listable[string]{p.Transport.Host}
		}
		t.HTTPOptions.Path = p.Transport.Path
	case C.V2RayTransportTypeWebsocket:
		t.WebsocketOptions.Path = p.Transport.Path
		if p.Transport.Host != "" {
			t.WebsocketOptions.Headers = badoption.HTTPHeader{"Host": badoption.Listable[string]{p.Transport.Host}}
		}
	case C.V2RayTransportTypeGRPC:
		name := p.Transport.ServiceName
		if name == "" {
			name = p.Transport.Path
		}
		t.GRPCOptions.ServiceName = name
	case C.V2RayTransportTypeHTTPUpgrade:
		t.HTTPUpgradeOptions.Host = p.Transport.Host
		t.HTTPUpgradeOptions.Path = p.Transport.Path
	}
	return t
}
