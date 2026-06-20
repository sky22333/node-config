package build

import (
	"net/netip"

	mDNS "github.com/miekg/dns"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"node-config/profile"
)

func buildDNS(c *buildCtx) *option.DNSOptions {
	s := c.settings
	if s.ForTest {
		ep := parseDNSEndpoint(s.DirectDNS[0])
		return &option.DNSOptions{
			RawDNSOptions: option.RawDNSOptions{
				Servers: []option.DNSServerOptions{makeRemoteDNS(dnsDirect, ep, TagDirect, s, true)},
				Final:   dnsDirect,
				DNSClientOptions: option.DNSClientOptions{
					IndependentCache: true,
					Strategy:         dnsStrategy(s),
				},
			},
		}
	}

	servers := []option.DNSServerOptions{
		{
			Type: C.DNSTypeLocal,
			Tag:  dnsLocal,
			Options: &option.LocalDNSServerOptions{
				RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{
					DialerOptions: option.DialerOptions{Detour: TagDirect},
				},
			},
		},
	}

	if ep := parseDNSEndpoint(s.DirectDNS[0]); ep.server != "" {
		servers = append(servers, makeRemoteDNS(dnsDirect, ep, TagDirect, s, true))
	}
	if ep := parseDNSEndpoint(s.RemoteDNS[0]); ep.server != "" {
		servers = append(servers, makeRemoteDNS(dnsRemote, ep, "", s, false))
	}
	if s.EnableFakeDNS {
		inet4 := badoption.Prefix(netip.MustParsePrefix("198.18.0.0/15"))
		inet6 := badoption.Prefix(netip.MustParsePrefix("fc00::/18"))
		servers = append(servers, option.DNSServerOptions{
			Type: C.DNSTypeFakeIP,
			Tag:  dnsFake,
			Options: &option.FakeIPDNSServerOptions{
				Inet4Range: &inet4,
				Inet6Range: &inet6,
			},
		})
	}

	final := dnsRemote
	if s.ForTest {
		final = dnsDirect
	}

	dns := &option.DNSOptions{
		RawDNSOptions: option.RawDNSOptions{
			Servers: servers,
			Rules:   buildDNSRules(c),
			Final:   final,
			DNSClientOptions: option.DNSClientOptions{
				IndependentCache: true,
				Strategy:         dnsStrategy(s),
			},
		},
	}
	return dns
}

func makeRemoteDNS(tag string, ep dnsEndpoint, detour string, s profile.Settings, useLocalResolver bool) option.DNSServerOptions {
	dialer := option.DialerOptions{Detour: detour}
	if useLocalResolver {
		dialer.DomainResolver = &option.DomainResolveOptions{Server: dnsLocal}
	}
	addr := option.DNSServerAddressOptions{Server: ep.server, ServerPort: ep.port}

	switch ep.typ {
	case "tcp":
		return option.DNSServerOptions{
			Type: C.DNSTypeTCP,
			Tag:  tag,
			Options: &option.RemoteDNSServerOptions{
				RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{DialerOptions: dialer},
				DNSServerAddressOptions:  addr,
			},
		}
	case "https":
		path := ep.path
		if path == "" {
			path = "/dns-query"
		}
		return option.DNSServerOptions{
			Type: C.DNSTypeHTTPS,
			Tag:  tag,
			Options: &option.RemoteHTTPSDNSServerOptions{
				RemoteTLSDNSServerOptions: option.RemoteTLSDNSServerOptions{
					RemoteDNSServerOptions: option.RemoteDNSServerOptions{
						RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{DialerOptions: dialer},
						DNSServerAddressOptions:  addr,
					},
					OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
						TLS: &option.OutboundTLSOptions{Enabled: true, ServerName: ep.server},
					},
				},
				Path: path,
			},
		}
	case "h3":
		path := ep.path
		if path == "" {
			path = "/dns-query"
		}
		return option.DNSServerOptions{
			Type: C.DNSTypeHTTP3,
			Tag:  tag,
			Options: &option.RemoteHTTPSDNSServerOptions{
				RemoteTLSDNSServerOptions: option.RemoteTLSDNSServerOptions{
					RemoteDNSServerOptions: option.RemoteDNSServerOptions{
						RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{DialerOptions: dialer},
						DNSServerAddressOptions:  addr,
					},
					OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
						TLS: &option.OutboundTLSOptions{Enabled: true, ServerName: ep.server},
					},
				},
				Path: path,
			},
		}
	case "tls":
		return option.DNSServerOptions{
			Type: C.DNSTypeTLS,
			Tag:  tag,
			Options: &option.RemoteTLSDNSServerOptions{
				RemoteDNSServerOptions: option.RemoteDNSServerOptions{
					RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{DialerOptions: dialer},
					DNSServerAddressOptions:  addr,
				},
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
					TLS: &option.OutboundTLSOptions{Enabled: true, ServerName: ep.server},
				},
			},
		}
	case "quic":
		return option.DNSServerOptions{
			Type: C.DNSTypeQUIC,
			Tag:  tag,
			Options: &option.RemoteTLSDNSServerOptions{
				RemoteDNSServerOptions: option.RemoteDNSServerOptions{
					RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{DialerOptions: dialer},
					DNSServerAddressOptions:  addr,
				},
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
					TLS: &option.OutboundTLSOptions{Enabled: true, ServerName: ep.server},
				},
			},
		}
	default:
		return option.DNSServerOptions{
			Type: C.DNSTypeUDP,
			Tag:  tag,
			Options: &option.RemoteDNSServerOptions{
				RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{DialerOptions: dialer},
				DNSServerAddressOptions:  addr,
			},
		}
	}
}

func buildDNSRules(c *buildCtx) []option.DNSRule {
	s := c.settings
	if s.ForTest {
		return nil
	}
	var rules []option.DNSRule

	rules = append(rules, defaultDNSRule(
		option.RawDefaultDNSRule{
			Outbound: badoption.Listable[string]{"any"},
		},
		option.DNSRuleAction{
			Action: C.RuleActionTypeRoute,
			RouteOptions: option.DNSRouteActionOptions{
				Server: dnsDirect,
			},
		},
	))

	if s.EnableFakeDNS {
		rules = append(rules, defaultDNSRule(
			option.RawDefaultDNSRule{
				Inbound: badoption.Listable[string]{TagTun},
				QueryType: badoption.Listable[option.DNSQueryType]{
					option.DNSQueryType(mDNS.TypeA),
					option.DNSQueryType(mDNS.TypeAAAA),
				},
			},
			option.DNSRuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{
					Server:       dnsFake,
					DisableCache: true,
				},
			},
		))
	}

	if s.EnableDNSRouting {
		for _, r := range s.Rules {
			if len(r.Domains) == 0 && len(r.RuleSetRefs) == 0 && len(r.RemoteRuleSets) == 0 {
				continue
			}
			server := dnsRemote
			switch r.Outbound {
			case "direct", "bypass":
				server = dnsDirect
			}
			raw := option.RawDefaultDNSRule{}
			applyDNSDomainMatchers(&raw, r.Domains)
			mergeDNSRuleSetTags(&raw, c.collectRuleSets(r))

			action := option.DNSRuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{
					Server: server,
				},
			}
			if r.Outbound == "block" {
				action = option.DNSRuleAction{Action: C.RuleActionTypeReject}
			}
			rules = append(rules, defaultDNSRule(raw, action))
		}
	}
	return rules
}

func defaultDNSRule(raw option.RawDefaultDNSRule, action option.DNSRuleAction) option.DNSRule {
	return option.DNSRule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultDNSRule{
			RawDefaultDNSRule: raw,
			DNSRuleAction:     action,
		},
	}
}
