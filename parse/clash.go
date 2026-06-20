package parse

import (
	"encoding/json"
	"strconv"
	"strings"

	"node-config/profile"

	"gopkg.in/yaml.v3"
)

func tryClashYAML(text string) ([]profile.Profile, bool) {
	if !strings.Contains(text, "proxies:") {
		return nil, false
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return nil, false
	}
	raw, ok := doc["proxies"]
	if !ok {
		return nil, false
	}
	list, ok := raw.([]any)
	if !ok || len(list) == 0 {
		return nil, false
	}
	var out []profile.Profile
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		p, err := clashProxy(m)
		if err != nil {
			continue
		}
		out = append(out, p)
	}
	return out, len(out) > 0
}

func clashProxy(m map[string]any) (profile.Profile, error) {
	typ, _ := m["type"].(string)
	name, _ := m["name"].(string)
	server, _ := m["server"].(string)
	port := intFromAny(m["port"])

	switch typ {
	case "ss":
		return profile.Profile{
			Type:     profile.TypeSS,
			Name:     name,
			Server:   server,
			Port:     uint16(port),
			Method:   clashCipher(str(m["cipher"])),
			Password: str(m["password"]),
			Plugin:   clashSSPlugin(m),
		}, nil
	case "socks5":
		return profile.Profile{
			Type:         profile.TypeSOCKS,
			Name:         name,
			Server:       server,
			Port:         uint16(port),
			Username:     str(m["username"]),
			Password:     str(m["password"]),
			SocksVersion: "5",
		}, nil
	case "trojan":
		p := profile.Profile{
			Type:     profile.TypeTrojan,
			Name:     name,
			Server:   server,
			Port:     uint16(port),
			Password: str(m["password"]),
			TLS:      &profile.TLS{Enabled: true, Security: "tls"},
		}
		if str(m["sni"]) != "" {
			p.TLS.SNI = str(m["sni"])
		}
		if m["skip-cert-verify"] == true || str(m["skip-cert-verify"]) == "true" {
			p.TLS.AllowInsecure = true
		}
		return p, nil
	case "http":
		p := profile.Profile{
			Type:     profile.TypeHTTP,
			Name:     name,
			Server:   server,
			Port:     uint16(port),
			Username: str(m["username"]),
			Password: str(m["password"]),
		}
		if m["tls"] == true || str(m["tls"]) == "true" {
			p.TLS = &profile.TLS{Enabled: true, Security: "tls", SNI: str(m["sni"])}
		}
		return p, nil
	case "vmess", "vless":
		return clashV2Ray(m, typ)
	case "hysteria2":
		return clashHysteria2(m), nil
	case "tuic":
		return clashTUIC(m), nil
	case "ssr":
		return clashSSR(m)
	case "anytls":
		return clashAnyTLS(m)
	case "wireguard":
		return clashWireGuard(m)
	case "snell":
		return clashSnell(m)
	case "ssh":
		return clashSSH(m)
	case "shadowtls":
		return clashShadowTLS(m)
	case "naive":
		return clashNaive(m)
	case "tor":
		return clashTor(m)
	default:
		return profile.Profile{}, profile.ErrUnsupportedType
	}
}

func clashSSPlugin(m map[string]any) string {
	plugin, _ := m["plugin"].(string)
	if plugin == "" {
		return ""
	}
	opts, _ := m["plugin-opts"].(map[string]any)
	switch plugin {
	case "obfs":
		return strings.Join([]string{
			"obfs-local",
			"obfs=" + str(opts["mode"]),
			"obfs-host=" + str(opts["host"]),
		}, ";")
	case "v2ray-plugin":
		parts := []string{"v2ray-plugin", "mode=" + str(opts["mode"])}
		if str(opts["mode"]) == "true" {
			parts = append(parts, "tls")
		}
		parts = append(parts, "host="+str(opts["host"]), "path="+str(opts["path"]))
		if opts["mux"] == true || str(opts["mux"]) == "true" {
			parts = append(parts, "mux=8")
		}
		return strings.Join(parts, ";")
	}
	return plugin
}

func clashCipher(c string) string {
	if c == "dummy" {
		return "none"
	}
	return c
}

func str(v any) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	default:
		return ""
	}
}

func intFromAny(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(x)
		return n
	default:
		return 0
	}
}

func tryJSON(text string) ([]profile.Profile, bool) {
	text = strings.TrimSpace(text)
	if text == "" || text[0] != '{' && text[0] != '[' {
		return nil, false
	}
	var raw any
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return nil, false
	}
	profiles := parseJSONValue(raw)
	return profiles, len(profiles) > 0
}

func parseJSONValue(v any) []profile.Profile {
	switch x := v.(type) {
	case map[string]any:
		return parseJSONObject(x)
	case []any:
		var out []profile.Profile
		for _, item := range x {
			out = append(out, parseJSONValue(item)...)
		}
		return out
	default:
		return nil
	}
}

func parseJSONObject(o map[string]any) []profile.Profile {
	if _, ok := o["method"]; ok {
		if _, ok2 := o["obfs"]; ok2 {
			return []profile.Profile{jsonSSR(o)}
		}
		return []profile.Profile{jsonSS(o)}
	}
	if _, ok := o["server"]; ok {
		if _, ok2 := o["up"]; ok2 {
			return nil // hysteria1 - later
		}
		if _, ok2 := o["up_mbps"]; ok2 {
			return nil
		}
	}
	return nil
}

func jsonSS(o map[string]any) profile.Profile {
	p := profile.Profile{
		Type:     profile.TypeSS,
		Server:   str(o["server"]),
		Port:     uint16(intFromAny(o["server_port"])),
		Method:   str(o["method"]),
		Password: str(o["password"]),
		Name:     str(o["remarks"]),
	}
	if pid := str(o["plugin"]); pid != "" {
		p.Plugin = pid + ";" + str(o["plugin_opts"])
	}
	return p
}

func jsonSSR(o map[string]any) profile.Profile {
	return profile.Profile{
		Type:          profile.TypeSSR,
		Server:        str(o["server"]),
		Port:          uint16(intFromAny(o["server_port"])),
		Method:        str(o["method"]),
		Password:      str(o["password"]),
		Name:          str(o["remarks"]),
		Protocol:      str(o["protocol"]),
		ProtocolParam: str(o["protocol_param"]),
		Obfs:          str(o["obfs"]),
		ObfsParam:     str(o["obfs_param"]),
	}
}
