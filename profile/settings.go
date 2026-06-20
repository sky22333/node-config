package profile

const (
	ModeProxy = "proxy"
	ModeVPN   = "vpn"

	IPv6Disable = "disable"
	IPv6Enable  = "enable"
	IPv6Prefer  = "prefer"
	IPv6Only    = "only"
)

// Settings holds runtime options injected by the caller (not read from platform storage).
type Settings struct {
	Mode      string `json:"mode"` // vpn or proxy
	ForTest   bool   `json:"for_test,omitempty"`
	ForExport bool   `json:"for_export,omitempty"`

	// Mixed inbound
	MixedPort    uint16 `json:"mixed_port,omitempty"`
	MixedListen  string `json:"mixed_listen,omitempty"`
	MixedUser    string `json:"mixed_user,omitempty"`
	MixedPass    string `json:"mixed_pass,omitempty"`
	AllowAccess  bool   `json:"allow_access,omitempty"` // listen on 0.0.0.0

	// VPN / TUN
	TunStack         string   `json:"tun_stack,omitempty"` // gvisor, system, mixed
	MTU              uint32   `json:"mtu,omitempty"`
	StrictRoute      bool     `json:"strict_route,omitempty"`
	IncludePackages  []string `json:"include_packages,omitempty"`
	ExcludePackages  []string `json:"exclude_packages,omitempty"`
	ResolveDest      bool     `json:"resolve_destination,omitempty"`

	// DNS
	RemoteDNS        []string `json:"remote_dns,omitempty"`
	DirectDNS        []string `json:"direct_dns,omitempty"`
	EnableFakeDNS    bool     `json:"enable_fake_dns,omitempty"`
	EnableDNSRouting bool     `json:"enable_dns_routing,omitempty"`

	// Route
	IPv6Mode          string      `json:"ipv6_mode,omitempty"`
	BypassPrivateIP   bool        `json:"bypass_private_ip,omitempty"`
	GlobalMode        bool        `json:"global_mode,omitempty"`
	BypassLAN         bool        `json:"bypass_lan,omitempty"`
	Sniff             bool        `json:"sniff,omitempty"`
	SniffOverrideDest bool        `json:"sniff_override_destination,omitempty"`
	Rules             []RouteRule `json:"rules,omitempty"`
	RuleSetUpdateInterval string  `json:"rule_set_update_interval,omitempty"` // e.g. "24h"

	// Selector group (when IsSelector, Profile is the selected member).
	IsSelector         bool    `json:"is_selector,omitempty"`
	SelectorProfileIDs []int64 `json:"selector_profile_ids,omitempty"`

	// Misc
	LogLevel        string `json:"log_level,omitempty"`
	EnableCacheFile bool   `json:"enable_cache_file,omitempty"`
	EnableClashAPI  bool   `json:"enable_clash_api,omitempty"`
	CustomConfig    string `json:"custom_config,omitempty"` // merge into root JSON

	FrontProxyID   int64 `json:"front_proxy_id,omitempty"`
	LandingProxyID int64 `json:"landing_proxy_id,omitempty"`
}

// DefaultSettings returns sensible defaults for proxy mode.
func DefaultSettings() Settings {
	return Settings{
		Mode:        ModeProxy,
		MixedPort:   2080,
		MixedListen: "127.0.0.1",
		LogLevel:    "info",
		IPv6Mode:    IPv6Enable,
		TunStack:    "mixed",
		MTU:         9000,
		RemoteDNS:   []string{"https://dns.google/dns-query"},
		DirectDNS:   []string{"223.5.5.5"},
	}
}

// VPNSettings returns defaults for VPN mode smoke tests.
func VPNSettings() Settings {
	s := DefaultSettings()
	s.Mode = ModeVPN
	s.EnableCacheFile = true
	return s
}
