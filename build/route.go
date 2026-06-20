package build

import (
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"node-config/profile"
)

func buildRoute(c *buildCtx, mainTag string) *option.RouteOptions {
	route := &option.RouteOptions{
		AutoDetectInterface: true,
		OverrideAndroidVPN:  true,
		Final:               mainTag,
	}

	if c.settings.ForTest {
		return route
	}

	route.Rules = append(route.Rules,
		defaultRouteRule(
			option.RawDefaultRule{Protocol: listableStrings([]string{"dns"})},
			option.RuleAction{Action: C.RuleActionTypeHijackDNS},
		),
		defaultRouteRule(
			option.RawDefaultRule{Port: listablePorts([]uint16{53})},
			option.RuleAction{Action: C.RuleActionTypeHijackDNS},
		),
	)

	if c.settings.BypassPrivateIP {
		route.Rules = append(route.Rules, defaultRouteRule(
			option.RawDefaultRule{IPIsPrivate: true},
			option.RuleAction{
				Action:       C.RuleActionTypeRoute,
				RouteOptions: option.RouteActionOptions{Outbound: TagBypass},
			},
		))
	}

	route.Rules = append(route.Rules, defaultRouteRule(
		option.RawDefaultRule{
			IPCIDR:       listableStrings([]string{"224.0.0.0/3", "ff00::/8"}),
			SourceIPCIDR: listableStrings([]string{"224.0.0.0/3", "ff00::/8"}),
		},
		option.RuleAction{Action: C.RuleActionTypeReject},
	))

	if c.settings.GlobalMode {
		if c.settings.BypassLAN {
			route.Rules = append(route.Rules, defaultRouteRule(
				option.RawDefaultRule{
					IPCIDR: listableStrings([]string{
						"224.0.0.0/3", "172.16.0.0/12", "127.0.0.0/8", "10.0.0.0/8",
						"192.168.0.0/16", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
					}),
				},
				option.RuleAction{
					Action:       C.RuleActionTypeRoute,
					RouteOptions: option.RouteActionOptions{Outbound: TagDirect},
				},
			))
		}
		if c.settings.Mode == profile.ModeVPN {
			route.Rules = append(route.Rules, inboundRouteRule(TagTun, mainTag))
		}
		route.Rules = append(route.Rules, inboundRouteRule(TagMixed, mainTag))
		route.Final = mainTag
	} else {
		if c.settings.Mode == profile.ModeVPN {
			route.Rules = append(route.Rules, inboundRouteRule(TagTun, mainTag))
		}
		route.Rules = append(route.Rules, inboundRouteRule(TagMixed, mainTag))

		for _, r := range c.settings.Rules {
			if rule := userRouteRule(c, r, mainTag); rule.IsValid() {
				route.Rules = append(route.Rules, rule)
			}
		}
	}

	route.RuleSet = c.ruleSetList()
	return route
}

func defaultRouteRule(raw option.RawDefaultRule, action option.RuleAction) option.Rule {
	return option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: raw,
			RuleAction:     action,
		},
	}
}

func inboundRouteRule(inbound, outbound string) option.Rule {
	return defaultRouteRule(
		option.RawDefaultRule{
			Inbound: badoption.Listable[string]{inbound},
		},
		option.RuleAction{
			Action:       C.RuleActionTypeRoute,
			RouteOptions: option.RouteActionOptions{Outbound: outbound},
		},
	)
}

func userRouteRule(c *buildCtx, r profile.RouteRule, mainTag string) option.Rule {
	raw := option.RawDefaultRule{
		PackageName: listableStrings(r.Packages),
		Port:        listablePorts(r.Ports),
		PortRange:   listableStrings(r.PortRanges),
		SourceIPCIDR: listableStrings(r.SourceIPCIDR),
		SourcePort:  listablePorts(r.SourcePorts),
		SourcePortRange: listableStrings(r.SourcePortRanges),
	}
	applyDomainMatchers(&raw, r.Domains)
	applyIPCIDRMatchers(&raw, r.IPCIDR)
	mergeRuleSetTags(&raw, c.collectRuleSets(r))

	if r.Network != "" {
		raw.Network = listableStrings([]string{r.Network})
	}
	if len(r.Protocol) > 0 {
		raw.Protocol = listableStrings(r.Protocol)
	}

	outbound := c.resolveRuleOutbound(r, mainTag)
	if outbound == TagBlock || r.Outbound == "block" {
		return defaultRouteRule(raw, option.RuleAction{Action: C.RuleActionTypeReject})
	}
	if outbound == "" {
		return option.Rule{}
	}
	return defaultRouteRule(raw, option.RuleAction{
		Action:       C.RuleActionTypeRoute,
		RouteOptions: option.RouteActionOptions{Outbound: outbound},
	})
}

func resolveRuleOutbound(name, mainTag string) string {
	switch name {
	case "", "proxy":
		return mainTag
	case "direct":
		return TagDirect
	case "bypass":
		return TagBypass
	case "block":
		return TagBlock
	default:
		return name
	}
}
