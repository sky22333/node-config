package profile

import "encoding/json"

// Protocol type constants.
const (
	TypeSS        = "ss"
	TypeSSR       = "ssr"
	TypeVMess     = "vmess"
	TypeVLESS     = "vless"
	TypeTrojan    = "trojan"
	TypeTrojanGo  = "trojan-go"
	TypeSOCKS     = "socks"
	TypeHTTP      = "http"
	TypeHysteria  = "hysteria"
	TypeHysteria2 = "hysteria2"
	TypeTUIC      = "tuic"
	TypeSnell     = "snell" // not supported by sing-box; parse/export only
	TypeAnyTLS    = "anytls"
	TypeNaive     = "naive"
	TypeShadowTLS = "shadowtls"
	TypeSSH       = "ssh"
	TypeTor       = "tor"
	TypeWireGuard = "wireguard"
	TypeConfig    = "config"
	TypeChain     = "chain"
)

// Profile is the unified proxy node model.
type Profile struct {
	ID   int64  `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Type string `json:"type"`

	Server string `json:"server"`
	Port   uint16 `json:"port"`

	Method   string `json:"method,omitempty"`
	Password string `json:"password,omitempty"`
	UUID     string `json:"uuid,omitempty"`

	AlterID         int    `json:"alter_id,omitempty"`
	Encryption      string `json:"encryption,omitempty"`
	Flow            string `json:"flow,omitempty"`
	PacketEncoding  string `json:"packet_encoding,omitempty"`
	VlessEncryption string `json:"vless_encryption,omitempty"`

	HysteriaVersion int    `json:"hysteria_version,omitempty"`
	ServerPorts     string `json:"server_ports,omitempty"`
	HopInterval     string `json:"hop_interval,omitempty"`
	HopIntervalMax  string `json:"hop_interval_max,omitempty"`
	Obfuscation     string `json:"obfuscation,omitempty"`
	ObfsType        string `json:"obfs_type,omitempty"`
	ObfsMinSize     int    `json:"obfs_min_size,omitempty"`
	ObfsMaxSize     int    `json:"obfs_max_size,omitempty"`
	UploadMbps      int    `json:"upload_mbps,omitempty"`
	DownloadMbps    int    `json:"download_mbps,omitempty"`
	BBRProfile      string `json:"bbr_profile,omitempty"`

	Token             string `json:"token,omitempty"`
	CongestionControl string `json:"congestion_control,omitempty"`
	UDPRelayMode      string `json:"udp_relay_mode,omitempty"`
	DisableSNI        bool   `json:"disable_sni,omitempty"`
	ZeroRTTHandshake  bool   `json:"zero_rtt_handshake,omitempty"`

	// SSR (removed from sing-box 1.6+; parse/export only)
	Protocol      string `json:"protocol,omitempty"`
	ProtocolParam string `json:"protocol_param,omitempty"`
	Obfs          string `json:"obfs,omitempty"`
	ObfsParam     string `json:"obfs_param,omitempty"`

	// Snell (external; parse/export only)
	SnellVersion  int    `json:"snell_version,omitempty"`
	SnellObfsMode string `json:"snell_obfs_mode,omitempty"`
	SnellObfsHost string `json:"snell_obfs_host,omitempty"`
	SnellReuse    bool   `json:"snell_reuse,omitempty"`

	// Naive
	NaiveProto          string `json:"naive_proto,omitempty"` // https, quic
	InsecureConcurrency int    `json:"insecure_concurrency,omitempty"`
	ExtraHeaders        string `json:"extra_headers,omitempty"`
	NaiveQUIC           bool   `json:"naive_quic,omitempty"`

	// ShadowTLS
	ShadowTLSVersion int `json:"shadowtls_version,omitempty"`

	// SSH
	SSHUser              string   `json:"ssh_user,omitempty"`
	PrivateKey           string   `json:"private_key,omitempty"`
	PrivateKeyPath       string   `json:"private_key_path,omitempty"`
	PrivateKeyPassphrase string   `json:"private_key_passphrase,omitempty"`
	HostKey              []string `json:"host_key,omitempty"`

	// WireGuard (sing-box endpoint)
	LocalAddresses []string `json:"local_addresses,omitempty"`
	WGPrivateKey   string   `json:"wg_private_key,omitempty"`
	PeerPublicKey  string   `json:"peer_public_key,omitempty"`
	PreSharedKey   string   `json:"pre_shared_key,omitempty"`
	AllowedIPs     []string `json:"allowed_ips,omitempty"`
	Reserved       string   `json:"reserved,omitempty"`
	WGMTU          uint32   `json:"wg_mtu,omitempty"`

	// Tor
	TorExecutable string            `json:"tor_executable,omitempty"`
	TorDataDir    string            `json:"tor_data_directory,omitempty"`
	Torrc         map[string]string `json:"torrc,omitempty"`

	Plugin string `json:"plugin,omitempty"`

	SocksVersion string `json:"socks_version,omitempty"`
	Username     string `json:"username,omitempty"`

	TLS       *TLS       `json:"tls,omitempty"`
	Transport *Transport `json:"transport,omitempty"`

	Chain []int64 `json:"chain,omitempty"`

	RawConfig   json.RawMessage `json:"raw_config,omitempty"`
	RawOutbound json.RawMessage `json:"raw_outbound,omitempty"`

	CustomOutbound json.RawMessage `json:"custom_outbound,omitempty"`
	CustomConfig   json.RawMessage `json:"custom_config,omitempty"`

	ExternalPlugin string `json:"external_plugin,omitempty"`
}

// TLS holds TLS-related settings.
type TLS struct {
	Enabled         bool   `json:"enabled,omitempty"`
	Security        string `json:"security,omitempty"`
	SNI             string `json:"sni,omitempty"`
	ALPN            string `json:"alpn,omitempty"`
	AllowInsecure   bool   `json:"allow_insecure,omitempty"`
	RealityPubKey   string `json:"reality_public_key,omitempty"`
	RealityShortID  string `json:"reality_short_id,omitempty"`
	UTLSFingerprint string `json:"utls_fingerprint,omitempty"`
}

// Transport holds V2Ray-style transport settings.
type Transport struct {
	Type        string `json:"type,omitempty"`
	Host        string `json:"host,omitempty"`
	Path        string `json:"path,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
}
