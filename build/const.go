package build

const (
	TagProxy  = "proxy"
	TagDirect = "direct"
	TagBypass = "bypass"
	TagBlock  = "block"
	TagMixed  = "mixed-in"
	TagTun    = "tun-in"

	vlan4Client = "172.19.0.1/28"
	vlan6Client = "fdfe:dcba:9876::1/126"

	dnsLocal  = "dns-local"
	dnsDirect = "dns-direct"
	dnsRemote = "dns-remote"
	dnsFake   = "dns-fake"
	dnsBlock  = "dns-block"
)
