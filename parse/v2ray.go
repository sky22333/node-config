package parse

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"node-config/internal/b64"
	"node-config/internal/urlutil"
	"node-config/profile"
)

func parseV2Ray(raw string) (profile.Profile, error) {
	isVLESS := strings.HasPrefix(raw, "vless://")
	scheme := "vmess"
	pType := profile.TypeVMess
	if isVLESS {
		scheme = "vless"
		pType = profile.TypeVLESS
	}

	if !strings.Contains(raw, "?") {
		if p, err := parseV2RayN(raw); err == nil {
			return p, nil
		}
	}

	u, err := urlutil.ParseHTTPStyle(raw, scheme)
	if err != nil {
		return profile.Profile{}, profile.NewParseError(raw, profile.ErrInvalidFormat)
	}

	p := profile.Profile{
		Type:      pType,
		Server:    u.Hostname(),
		Port:      portFromURL(u),
		Name:      urlutil.FragmentName(u),
		Transport: &profile.Transport{Type: "tcp"},
	}

	if pass, ok := u.User.Password(); ok && pass != "" && !isVLESS {
		proto := u.User.Username()
		if idx := strings.LastIndex(pass, "-"); idx > 0 {
			if aid, err := strconv.Atoi(pass[idx+1:]); err == nil {
				p.AlterID = aid
				p.UUID = pass[:idx]
			}
		} else {
			p.UUID = pass
		}
		if strings.HasSuffix(proto, "+tls") {
			p.TLS = &profile.TLS{Enabled: true, Security: "tls"}
			if sni := u.Query().Get("tlsServerName"); sni != "" {
				p.TLS.SNI = sni
			}
			proto = strings.TrimSuffix(proto, "+tls")
		}
		applyLegacyTransport(&p, u, proto)
	} else {
		p.UUID = u.User.Username()
		if path := strings.Trim(strings.TrimPrefix(u.Path, "/"), "/"); path != "" {
			p.Transport.Path = path
		}
		applyDuckSoftQuery(&p, u, isVLESS)
	}

	if p.Encryption == "" && pType == profile.TypeVMess {
		p.Encryption = "auto"
	}
	return p, nil
}

func parseAlterID(pass string) int {
	if idx := strings.LastIndex(pass, "-"); idx > 0 {
		if aid, err := strconv.Atoi(pass[idx+1:]); err == nil {
			return aid
		}
	}
	return 0
}

type vmessQRCode struct {
	V   string `json:"v"`
	PS  string `json:"ps"`
	Add string `json:"add"`
	Port string `json:"port"`
	ID  string `json:"id"`
	Aid string `json:"aid"`
	Scy string `json:"scy"`
	Net string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
	TLS  string `json:"tls"`
	SNI  string `json:"sni"`
	ALPN string `json:"alpn"`
	FP   string `json:"fp"`
}

func parseV2RayN(raw string) (profile.Profile, error) {
	body := strings.TrimPrefix(strings.TrimPrefix(raw, "vmess://"), "vless://")
	decoded, err := b64.DecodeURLSafeString(body)
	if err != nil {
		return profile.Profile{}, err
	}
	var qr vmessQRCode
	if err := json.Unmarshal([]byte(decoded), &qr); err != nil {
		return profile.Profile{}, profile.ErrInvalidFormat
	}
	if qr.Add == "" || qr.Port == "" || qr.ID == "" || qr.Net == "" {
		return profile.Profile{}, profile.ErrInvalidFormat
	}
	port, _ := strconv.Atoi(qr.Port)
	aid, _ := strconv.Atoi(qr.Aid)

	p := profile.Profile{
		Type:       profile.TypeVMess,
		Name:       qr.PS,
		Server:     qr.Add,
		Port:       uint16(port),
		UUID:       qr.ID,
		AlterID:    aid,
		Encryption: qr.Scy,
		Transport:  &profile.Transport{Type: qr.Net, Host: qr.Host, Path: qr.Path},
	}
	if qr.Net == "tcp" && qr.Type == "http" {
		p.Transport.Type = "http"
	}
	if qr.TLS == "tls" || qr.TLS == "reality" {
		p.TLS = &profile.TLS{
			Enabled:         true,
			Security:        "tls",
			SNI:             qr.SNI,
			ALPN:            qr.ALPN,
			UTLSFingerprint: qr.FP,
		}
		if p.TLS.SNI == "" {
			p.TLS.SNI = qr.Host
		}
	}
	if p.Encryption == "" {
		p.Encryption = "auto"
	}
	return p, nil
}

func applyDuckSoftQuery(p *profile.Profile, u *url.URL, isVLESS bool) {
	q := u.Query()

	transportType := q.Get("type")
	if transportType == "" {
		transportType = "tcp"
	}
	if transportType == "h2" || q.Get("headerType") == "http" {
		transportType = "http"
	}
	if p.Transport == nil {
		p.Transport = &profile.Transport{}
	}
	p.Transport.Type = transportType

	sec := q.Get("security")
	if sec == "" {
		if isVLESS {
			sec = "none"
		} else {
			sec = "none"
		}
	}
	if sec == "tls" || sec == "reality" {
		p.TLS = &profile.TLS{Enabled: true, Security: sec}
		if q.Get("allowInsecure") == "1" || q.Get("allowInsecure") == "true" {
			p.TLS.AllowInsecure = true
		}
		if v := q.Get("sni"); v != "" {
			p.TLS.SNI = v
		}
		if v := q.Get("host"); v != "" && p.TLS.SNI == "" {
			p.TLS.SNI = v
		}
		if v := q.Get("alpn"); v != "" && v != "none" {
			p.TLS.ALPN = v
		}
		if v := q.Get("pbk"); v != "" {
			p.TLS.RealityPubKey = v
		}
		if v := q.Get("sid"); v != "" {
			p.TLS.RealityShortID = v
		}
	}

	switch transportType {
	case "http", "ws", "httpupgrade", "xhttp":
		if v := q.Get("host"); v != "" {
			p.Transport.Host = v
		}
		if v := q.Get("path"); v != "" {
			p.Transport.Path = v
		}
	case "grpc":
		if v := q.Get("serviceName"); v != "" {
			p.Transport.ServiceName = v
			p.Transport.Path = v
		}
	}

	if !isVLESS {
		if v := q.Get("encryption"); v != "" {
			p.Encryption = v
		}
	}
	switch q.Get("packetEncoding") {
	case "packet":
		p.PacketEncoding = "packetaddr"
	case "xudp":
		p.PacketEncoding = "xudp"
	}
	if isVLESS {
		if v := q.Get("flow"); v != "" {
			p.Flow = strings.TrimSuffix(v, "-udp443")
		}
		if v := q.Get("encryption"); v != "" && v != "none" {
			p.VlessEncryption = v
		}
	}
	if v := q.Get("fp"); v != "" {
		if p.TLS == nil {
			p.TLS = &profile.TLS{}
		}
		p.TLS.UTLSFingerprint = v
	}
}

func applyLegacyTransport(p *profile.Profile, u *url.URL, proto string) {
	if p.Transport == nil {
		p.Transport = &profile.Transport{Type: "tcp"}
	}
	switch proto {
	case "http":
		p.Transport.Type = "http"
		if v := u.Query().Get("path"); v != "" {
			p.Transport.Path = v
		}
		if v := u.Query().Get("host"); v != "" {
			p.Transport.Host = strings.ReplaceAll(v, "|", ",")
		}
	case "ws":
		p.Transport.Type = "ws"
		if v := u.Query().Get("path"); v != "" {
			p.Transport.Path = v
		}
		if v := u.Query().Get("host"); v != "" {
			p.Transport.Host = v
		}
	case "grpc":
		p.Transport.Type = "grpc"
		if v := u.Query().Get("serviceName"); v != "" {
			p.Transport.ServiceName = v
		}
	}
}
