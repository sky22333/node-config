package build

import (
	"strings"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func applyDomainMatchers(raw *option.RawDefaultRule, items []string) {
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		switch {
		case strings.HasPrefix(item, "geosite:"):
			raw.RuleSet = append(raw.RuleSet, item)
		case strings.HasPrefix(item, "full:"):
			raw.Domain = append(raw.Domain, strings.ToLower(strings.TrimPrefix(item, "full:")))
		case strings.HasPrefix(item, "domain:"):
			raw.DomainSuffix = append(raw.DomainSuffix, strings.ToLower(strings.TrimPrefix(item, "domain:")))
		case strings.HasPrefix(item, "regexp:"):
			raw.DomainRegex = append(raw.DomainRegex, strings.ToLower(strings.TrimPrefix(item, "regexp:")))
		case strings.HasPrefix(item, "keyword:"):
			raw.DomainKeyword = append(raw.DomainKeyword, strings.ToLower(strings.TrimPrefix(item, "keyword:")))
		default:
			raw.DomainSuffix = append(raw.DomainSuffix, strings.ToLower(item))
		}
	}
}

func applyIPCIDRMatchers(raw *option.RawDefaultRule, items []string) {
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.HasPrefix(item, "geoip:") {
			if item == "geoip:private" {
				raw.IPIsPrivate = true
			} else {
				raw.RuleSet = append(raw.RuleSet, item)
			}
			continue
		}
		raw.IPCIDR = append(raw.IPCIDR, item)
	}
}

func applyDNSDomainMatchers(raw *option.RawDefaultDNSRule, items []string) {
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		switch {
		case strings.HasPrefix(item, "geosite:"):
			raw.RuleSet = append(raw.RuleSet, item)
		case strings.HasPrefix(item, "full:"):
			raw.Domain = append(raw.Domain, strings.ToLower(strings.TrimPrefix(item, "full:")))
		case strings.HasPrefix(item, "domain:"):
			raw.DomainSuffix = append(raw.DomainSuffix, strings.ToLower(strings.TrimPrefix(item, "domain:")))
		case strings.HasPrefix(item, "regexp:"):
			raw.DomainRegex = append(raw.DomainRegex, strings.ToLower(strings.TrimPrefix(item, "regexp:")))
		case strings.HasPrefix(item, "keyword:"):
			raw.DomainKeyword = append(raw.DomainKeyword, strings.ToLower(strings.TrimPrefix(item, "keyword:")))
		default:
			raw.DomainSuffix = append(raw.DomainSuffix, strings.ToLower(item))
		}
	}
}

func mergeRuleSetTags(dst *option.RawDefaultRule, extra badoption.Listable[string]) {
	if len(extra) == 0 {
		return
	}
	dst.RuleSet = append(dst.RuleSet, extra...)
}

func mergeDNSRuleSetTags(dst *option.RawDefaultDNSRule, extra badoption.Listable[string]) {
	if len(extra) == 0 {
		return
	}
	dst.RuleSet = append(dst.RuleSet, extra...)
}
