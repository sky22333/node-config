package parse

import (
	"bufio"
	"encoding/base64"
	"strconv"
	"strings"

	"node-config/profile"
)

func tryWireGuardINI(text string) ([]profile.Profile, bool) {
	if !strings.Contains(text, "[Interface]") || !strings.Contains(text, "[Peer]") {
		return nil, false
	}
	doc := parseINI(text)
	iface := doc.get("Interface")
	if iface == nil {
		return nil, false
	}
	addrs := splitList(iface["Address"])
	if len(addrs) == 0 {
		return nil, false
	}
	priv := iface["PrivateKey"]
	if priv == "" {
		return nil, false
	}
	var mtu uint32
	if v := iface["MTU"]; v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			mtu = uint32(n)
		}
	}
	peers := doc.Sections["Peer"]
	if len(peers) == 0 {
		return nil, false
	}
	var out []profile.Profile
	for _, peer := range peers {
		ep := peer["Endpoint"]
		if ep == "" || !strings.Contains(ep, ":") {
			continue
		}
		host, portStr, _ := strings.Cut(ep, ":")
		port := intFromAny(portStr)
		if port == 0 {
			continue
		}
		pub := peer["PublicKey"]
		if pub == "" {
			continue
		}
		p := profile.Profile{
			Type:           profile.TypeWireGuard,
			Server:         host,
			Port:           uint16(port),
			LocalAddresses: expandAddresses(addrs),
			WGPrivateKey:   priv,
			PeerPublicKey:  pub,
			PreSharedKey:   peer["PresharedKey"],
			WGMTU:          mtu,
		}
		if v := peer["AllowedIPs"]; v != "" {
			p.AllowedIPs = splitList(v)
		}
		if v := peer["PersistentKeepalive"]; v != "" {
			_ = v
		}
		out = append(out, p)
	}
	return out, len(out) > 0
}

type iniDoc struct {
	Sections map[string][]map[string]string
}

func (d iniDoc) get(section string) map[string]string {
	if len(d.Sections[section]) == 0 {
		return nil
	}
	return d.Sections[section][0]
}

func parseINI(text string) iniDoc {
	doc := iniDoc{Sections: map[string][]map[string]string{}}
	var section string
	var cur map[string]string
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line[1 : len(line)-1]
			cur = map[string]string{}
			doc.Sections[section] = append(doc.Sections[section], cur)
			continue
		}
		if cur == nil {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if prev, ok := cur[k]; ok {
			cur[k] = prev + "," + v
		} else {
			cur[k] = v
		}
	}
	return doc
}

func expandAddresses(addrs []string) []string {
	var out []string
	for _, a := range addrs {
		for _, part := range splitList(a) {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if !strings.Contains(part, "/") {
				if strings.Contains(part, ":") {
					part += "/128"
				} else {
					part += "/32"
				}
			}
			out = append(out, part)
		}
	}
	return out
}

func splitList(s string) []string {
	s = strings.ReplaceAll(s, "\n", ",")
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseReserved(s string) []uint8 {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if strings.HasPrefix(s, "[") {
		s = strings.Trim(s, "[] ")
		parts := splitList(s)
		if len(parts) == 3 {
			out := make([]uint8, 3)
			for i, p := range parts {
				n, _ := strconv.Atoi(strings.TrimSpace(p))
				out[i] = uint8(n)
			}
			return out
		}
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 3 {
		return b
	}
	return nil
}
