package build

import (
	"net/netip"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/json/badoption"

	"node-config/profile"
)

func buildInbounds(s profile.Settings) []option.Inbound {
	if s.ForTest {
		return nil
	}
	var inbounds []option.Inbound
	if s.Mode == profile.ModeVPN {
		inbounds = append(inbounds, tunInbound(s))
	}
	inbounds = append(inbounds, mixedInbound(s))
	return inbounds
}

func tunInbound(s profile.Settings) option.Inbound {
	v4, v6 := tunAddresses(s)
	opts := &option.TunInboundOptions{
		InterfaceName: "tun0",
		MTU:           s.MTU,
		Address:       prefixList(v4, v6),
		AutoRoute:     true,
		StrictRoute:   s.StrictRoute,
		Stack:         s.TunStack,
		InboundOptions: option.InboundOptions{
			SniffEnabled:             s.Sniff,
			SniffOverrideDestination: s.SniffOverrideDest,
			DomainStrategy:           domainStrategy(s, s.ResolveDest),
		},
	}
	if len(s.IncludePackages) > 0 {
		opts.IncludePackage = listableStrings(s.IncludePackages)
	}
	if len(s.ExcludePackages) > 0 {
		opts.ExcludePackage = listableStrings(s.ExcludePackages)
	}
	return option.Inbound{
		Type:    C.TypeTun,
		Tag:     TagTun,
		Options: opts,
	}
}

func tunAddresses(s profile.Settings) (v4, v6 bool) {
	switch s.IPv6Mode {
	case profile.IPv6Disable:
		return true, false
	case profile.IPv6Only:
		return false, true
	default:
		return true, true
	}
}

func mixedInbound(s profile.Settings) option.Inbound {
	addr, _ := netip.ParseAddr(mixedListen(s))
	listen := badoption.Addr(addr)
	opts := &option.HTTPMixedInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     &listen,
			ListenPort: s.MixedPort,
			InboundOptions: option.InboundOptions{
				SniffEnabled:             s.Sniff,
				SniffOverrideDestination: s.SniffOverrideDest,
				DomainStrategy:           domainStrategy(s, s.ResolveDest),
			},
		},
	}
	if s.MixedUser != "" {
		opts.Users = []auth.User{{Username: s.MixedUser, Password: s.MixedPass}}
	}
	return option.Inbound{
		Type:    C.TypeMixed,
		Tag:     TagMixed,
		Options: opts,
	}
}
