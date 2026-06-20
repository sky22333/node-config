package build

import (
	"fmt"
	"strings"

	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	"node-config/profile"
)

type buildCtx struct {
	settings       profile.Settings
	profiles       map[int64]profile.Profile
	globalTags     map[int64]string
	profileTags    map[int64]string
	extraOutbounds []option.Outbound
	extraEndpoints []option.Endpoint
	ruleSets       map[string]option.RuleSet
	usedTags       map[string]struct{}
}

func newBuildCtx(in Input) *buildCtx {
	profiles := in.Profiles
	if profiles == nil {
		profiles = map[int64]profile.Profile{}
	}
	if in.Profile.ID != 0 {
		profiles[in.Profile.ID] = in.Profile
	}
	return &buildCtx{
		settings:    normalizeSettings(in.Settings),
		profiles:    profiles,
		globalTags:  map[int64]string{},
		profileTags: map[int64]string{},
		ruleSets:    map[string]option.RuleSet{},
		usedTags:    map[string]struct{}{TagDirect: {}, TagBypass: {}, TagBlock: {}, TagProxy: {}, TagMixed: {}, TagTun: {}},
	}
}

func (c *buildCtx) ensureProfileChain(id int64) string {
	if tag, ok := c.profileTags[id]; ok {
		return tag
	}
	p, ok := c.profiles[id]
	if !ok {
		return ""
	}
	tag, outbounds, err := c.buildChain(id, p)
	if err != nil {
		return ""
	}
	c.profileTags[id] = tag
	c.extraOutbounds = append(c.extraOutbounds, outbounds...)
	return tag
}

func resolveChain(p profile.Profile, profiles map[int64]profile.Profile, frontID, landingID int64) ([]profile.Profile, error) {
	var list []profile.Profile

	if landingID > 0 {
		lp, ok := profiles[landingID]
		if !ok {
			return nil, fmt.Errorf("%w: landing %d", profile.ErrProfileNotFound, landingID)
		}
		list = append(list, lp)
	}

	chain, err := resolveChainInternal(p, profiles)
	if err != nil {
		return nil, err
	}
	list = append(list, chain...)

	if frontID > 0 {
		fp, ok := profiles[frontID]
		if !ok {
			return nil, fmt.Errorf("%w: front %d", profile.ErrProfileNotFound, frontID)
		}
		list = append(list, fp)
	}
	return list, nil
}

func resolveChainInternal(p profile.Profile, profiles map[int64]profile.Profile) ([]profile.Profile, error) {
	if p.Type != profile.TypeChain {
		return []profile.Profile{p}, nil
	}
	var out []profile.Profile
	for _, id := range p.Chain {
		cp, ok := profiles[id]
		if !ok {
			return nil, fmt.Errorf("%w: chain member %d", profile.ErrProfileNotFound, id)
		}
		sub, err := resolveChainInternal(cp, profiles)
		if err != nil {
			return nil, err
		}
		out = append(out, sub...)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

func (c *buildCtx) buildChain(chainID int64, entity profile.Profile) (string, []option.Outbound, error) {
	if chainID == 0 {
		chainID = entity.ID
	}
	if chainID == 0 {
		chainID = 1
	}

	profiles, err := resolveChain(entity, c.profiles, c.settings.FrontProxyID, c.settings.LandingProxyID)
	if err != nil {
		return "", nil, err
	}

	chainTag := fmt.Sprintf("c-%d", chainID)
	var outbounds []option.Outbound
	mainTag := TagProxy

	for index, p := range profiles {
		tagOut := fmt.Sprintf("%s-%d", chainTag, p.ID)

		if index == len(profiles)-1 {
			if existing, ok := c.globalTags[p.ID]; ok {
				if index == 0 {
					mainTag = existing
				}
				continue
			}
			tagOut = fmt.Sprintf("g-%d", p.ID)
			c.globalTags[p.ID] = tagOut
		}

		if index == 0 {
			if len(profiles) == 1 {
				tagOut = TagProxy
			} else {
				tagOut = c.readableTag(p.Name)
			}
			mainTag = tagOut
		}

		if err := c.appendChainNode(p, tagOut, &outbounds); err != nil {
			return "", nil, err
		}
	}

	return mainTag, outbounds, nil
}

func (c *buildCtx) buildOutbounds(in Input) ([]option.Outbound, string, error) {
	var outbounds []option.Outbound
	var mainTag string

	for _, rule := range c.settings.Rules {
		if rule.OutboundProfileID > 0 && rule.OutboundProfileID != in.Profile.ID {
			c.ensureProfileChain(rule.OutboundProfileID)
		}
	}

	useSelector := c.settings.IsSelector && !c.settings.ForTest && !c.settings.ForExport
	if useSelector {
		var tags []string
		defaultTag := ""
		for _, id := range c.settings.SelectorProfileIDs {
			p, ok := c.profiles[id]
			if !ok {
				continue
			}
			tag, chainOuts, err := c.buildChain(id, p)
			if err != nil {
				return nil, "", err
			}
			c.profileTags[id] = tag
			tags = append(tags, tag)
			outbounds = append(outbounds, chainOuts...)
			if id == in.Profile.ID {
				defaultTag = tag
			}
		}
		if len(tags) == 0 {
			return nil, "", profile.ErrProfileNotFound
		}
		if defaultTag == "" {
			defaultTag = tags[0]
		}
		selector := option.Outbound{
			Type: constant.TypeSelector,
			Tag:  TagProxy,
			Options: &option.SelectorOutboundOptions{
				Outbounds: tags,
				Default:   defaultTag,
			},
		}
		outbounds = append([]option.Outbound{selector}, outbounds...)
		mainTag = TagProxy
	} else {
		tag, chainOuts, err := c.buildChain(in.Profile.ID, in.Profile)
		if err != nil {
			return nil, "", err
		}
		c.profileTags[in.Profile.ID] = tag
		outbounds = append(outbounds, chainOuts...)
		mainTag = tag
	}

	outbounds = append(outbounds, c.extraOutbounds...)

	base := []option.Outbound{
		{Type: constant.TypeDirect, Tag: TagDirect, Options: &option.DirectOutboundOptions{}},
		{Type: constant.TypeDirect, Tag: TagBypass, Options: &option.DirectOutboundOptions{}},
		{Type: constant.TypeBlock, Tag: TagBlock, Options: &option.StubOptions{}},
	}
	outbounds = append(outbounds, base...)
	return outbounds, mainTag, nil
}

func (c *buildCtx) readableTag(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "node"
	}
	name = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, name)
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}
	name = strings.Trim(name, "-")
	if name == "" {
		name = "node"
	}
	tag := name
	for i := 0; ; i++ {
		if _, used := c.usedTags[tag]; !used {
			c.usedTags[tag] = struct{}{}
			return tag
		}
		tag = fmt.Sprintf("%s-%d", name, i+1)
	}
}

func setOutboundDetour(out *option.Outbound, detour string) {
	if w, ok := out.Options.(option.DialerOptionsWrapper); ok {
		d := w.TakeDialerOptions()
		d.Detour = detour
		w.ReplaceDialerOptions(d)
	}
}

func setEndpointDetour(ep *option.Endpoint, detour string) {
	if w, ok := ep.Options.(*option.WireGuardEndpointOptions); ok {
		w.Detour = detour
		ep.Options = w
	}
}

func (c *buildCtx) appendChainNode(p profile.Profile, tagOut string, outbounds *[]option.Outbound) error {
	if isNonBuildable(p) {
		if p.Type == profile.TypeSSR {
			return profile.ErrRemovedInSingBox
		}
		return profile.ErrUnsupportedType
	}
	if isWireGuard(p) {
		ep, err := wireguardEndpoint(p, tagOut)
		if err != nil {
			return err
		}
		c.linkDetourTo(tagOut, outbounds)
		c.extraEndpoints = append(c.extraEndpoints, ep)
		return nil
	}
	out, err := Outbound(p, tagOut)
	if err != nil {
		return err
	}
	if !c.settings.ForTest {
		setOutboundDomainStrategy(&out, domainStrategy(c.settings, false))
	}
	c.linkDetourTo(tagOut, outbounds)
	*outbounds = append(*outbounds, out)
	return nil
}

func (c *buildCtx) linkDetourTo(tagOut string, outbounds *[]option.Outbound) {
	if len(*outbounds) > 0 {
		setOutboundDetour(&(*outbounds)[len(*outbounds)-1], tagOut)
	} else if n := len(c.extraEndpoints); n > 0 {
		setEndpointDetour(&c.extraEndpoints[n-1], tagOut)
	}
}

func setOutboundDomainStrategy(out *option.Outbound, strategy option.DomainStrategy) {
	if w, ok := out.Options.(option.DialerOptionsWrapper); ok {
		d := w.TakeDialerOptions()
		d.DomainStrategy = strategy
		w.ReplaceDialerOptions(d)
	}
}

func (c *buildCtx) ruleSetList() []option.RuleSet {
	if len(c.ruleSets) == 0 {
		return nil
	}
	out := make([]option.RuleSet, 0, len(c.ruleSets))
	for _, rs := range c.ruleSets {
		out = append(out, rs)
	}
	return out
}
