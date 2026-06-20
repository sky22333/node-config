package profile

// RouteRule is a user-defined routing rule passed from the caller.
type RouteRule struct {
	Name     string `json:"name,omitempty"`
	Outbound string `json:"outbound"` // proxy, direct, bypass, block, or outbound tag

	// OutboundProfileID references another profile; Build resolves it via chain.
	OutboundProfileID int64 `json:"outbound_profile_id,omitempty"`

	Domains  []string `json:"domains,omitempty"`
	IPCIDR   []string `json:"ip_cidr,omitempty"`
	Packages []string `json:"packages,omitempty"`
	Ports    []uint16 `json:"ports,omitempty"`
	PortRanges []string `json:"port_ranges,omitempty"`
	SourceIPCIDR []string `json:"source_ip_cidr,omitempty"`
	SourcePorts []uint16 `json:"source_ports,omitempty"`
	SourcePortRanges []string `json:"source_port_ranges,omitempty"`
	Network  string   `json:"network,omitempty"`
	Protocol []string `json:"protocol,omitempty"`

	// RuleSetRefs: geoip:cn, geosite:google@ads (local binary rulesets).
	RuleSetRefs []string `json:"rule_set_refs,omitempty"`
	// RemoteRuleSets: rsip:https://... or rssite:https://...
	RemoteRuleSets []RemoteRuleSetRef `json:"remote_rule_sets,omitempty"`

	CustomConfig string `json:"custom_config,omitempty"`
}

// RemoteRuleSetRef is a remote sing-box rule-set source.
type RemoteRuleSetRef struct {
	URL  string `json:"url"`
	IsIP bool   `json:"is_ip,omitempty"` // rsip vs rssite
}
