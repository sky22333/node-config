package build

import (
	"hash/fnv"
	"strconv"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"node-config/profile"
)

func (c *buildCtx) collectRuleSets(rule profile.RouteRule) badoption.Listable[string] {
	var tags []string

	for _, ref := range rule.RuleSetRefs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}
		switch {
		case strings.HasPrefix(ref, "geoip:"), strings.HasPrefix(ref, "geosite:"):
			c.ruleSets[ref] = option.RuleSet{
			Type:         C.RuleSetTypeLocal,
			Tag:          ref,
			Format:       C.RuleSetFormatBinary,
			LocalOptions: option.LocalRuleSet{Path: ref},
		}
			tags = append(tags, ref)
		}
	}

	for _, remote := range rule.RemoteRuleSets {
		url := strings.TrimSpace(remote.URL)
		if url == "" {
			continue
		}
		tag := remoteRuleSetTag(url)
		if _, ok := c.ruleSets[tag]; !ok {
			rs := option.RuleSet{
				Type: C.RuleSetTypeRemote,
				Tag:  tag,
				RemoteOptions: option.RemoteRuleSet{
					URL: url,
				},
				Format: C.RuleSetFormatBinary,
			}
			if iv := c.settings.RuleSetUpdateInterval; iv != "" {
				if d, err := time.ParseDuration(iv); err == nil {
					rs.RemoteOptions.UpdateInterval = badoption.Duration(d)
				}
			}
			c.ruleSets[tag] = rs
		}
		tags = append(tags, tag)
	}

	if len(tags) == 0 {
		return nil
	}
	return badoption.Listable[string](tags)
}

func remoteRuleSetTag(url string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(url))
	return "ruleset-" + strconv.FormatUint(uint64(h.Sum32()), 10)
}

func (c *buildCtx) resolveRuleOutbound(r profile.RouteRule, mainTag string) string {
	if r.OutboundProfileID > 0 {
		if tag := c.ensureProfileChain(r.OutboundProfileID); tag != "" {
			return tag
		}
	}
	return resolveRuleOutbound(r.Outbound, mainTag)
}
