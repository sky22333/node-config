package export

import (
	"context"
	"encoding/json"

	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"

	"node-config/build"
	"node-config/profile"
)

// ToOutboundJSON exports a single outbound as JSON.
func ToOutboundJSON(p profile.Profile) ([]byte, error) {
	out, err := build.Outbound(p, "proxy")
	if err != nil {
		return nil, err
	}
	return sjson.MarshalContext(context.Background(), out)
}

// FromOutboundJSON parses sing-box outbound JSON into Profile.
func FromOutboundJSON(raw []byte) (profile.Profile, error) {
	var out option.Outbound
	if err := sjson.UnmarshalContext(context.Background(), raw, &out); err != nil {
		return profile.Profile{}, err
	}
	return outboundToProfile(out)
}

func outboundToProfile(out option.Outbound) (profile.Profile, error) {
	switch out.Type {
	case "shadowsocks":
		opts, ok := out.Options.(*option.ShadowsocksOutboundOptions)
		if !ok {
			return profile.Profile{}, profile.ErrInvalidFormat
		}
		p := profile.Profile{
			Type:     profile.TypeSS,
			Server:   opts.Server,
			Port:     opts.ServerPort,
			Method:   opts.Method,
			Password: opts.Password,
		}
		if opts.Plugin != "" {
			p.Plugin = opts.Plugin
			if opts.PluginOptions != "" {
				p.Plugin += ";" + opts.PluginOptions
			}
		}
		return p, nil
	case "trojan":
		opts, ok := out.Options.(*option.TrojanOutboundOptions)
		if !ok {
			return profile.Profile{}, profile.ErrInvalidFormat
		}
		p := profile.Profile{
			Type:     profile.TypeTrojan,
			Server:   opts.Server,
			Port:     opts.ServerPort,
			Password: opts.Password,
			TLS:      &profile.TLS{Enabled: true, Security: "tls"},
		}
		if opts.TLS != nil {
			p.TLS.SNI = opts.TLS.ServerName
			p.TLS.AllowInsecure = opts.TLS.Insecure
			if len(opts.TLS.ALPN) > 0 {
				p.TLS.ALPN = opts.TLS.ALPN[0]
			}
		}
		return p, nil
	case "socks":
		opts, ok := out.Options.(*option.SOCKSOutboundOptions)
		if !ok {
			return profile.Profile{}, profile.ErrInvalidFormat
		}
		return profile.Profile{
			Type:         profile.TypeSOCKS,
			Server:       opts.Server,
			Port:         opts.ServerPort,
			Username:     opts.Username,
			Password:     opts.Password,
			SocksVersion: opts.Version,
		}, nil
	default:
		return profile.Profile{}, profile.ErrUnsupportedType
	}
}

// MustMarshalProfile is a helper for tests.
func MustMarshalProfile(p profile.Profile) string {
	b, _ := json.Marshal(p)
	return string(b)
}
