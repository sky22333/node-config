package parse_test

import (
	"encoding/json"
	"testing"

	"node-config/build"
	"node-config/export"
	"node-config/internal/b64"
	"node-config/parse"
	"node-config/profile"
)

func TestParseVLESS(t *testing.T) {
	link := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?encryption=none&security=tls&sni=example.com&fp=chrome&type=ws&host=example.com&path=%2Fvless#node"
	profiles, err := parse.ParseLinks([]string{link})
	if err != nil {
		t.Fatal(err)
	}
	p := profiles[0]
	if p.Type != profile.TypeVLESS || p.UUID == "" || p.Server != "1.2.3.4" {
		t.Fatalf("unexpected: %+v", p)
	}
	if p.Transport == nil || p.Transport.Type != "ws" {
		t.Fatalf("transport: %+v", p.Transport)
	}
}

func TestParseVMessV2RayN(t *testing.T) {
	qr := map[string]string{
		"v": "2", "ps": "test", "add": "1.1.1.1", "port": "443",
		"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "aid": "0",
		"scy": "auto", "net": "ws", "host": "cdn.example.com", "path": "/ws", "tls": "tls", "sni": "cdn.example.com",
	}
	raw, _ := json.Marshal(qr)
	link := "vmess://" + b64.EncodeURLSafe(raw)
	profiles, err := parse.ParseLinks([]string{link})
	if err != nil {
		t.Fatal(err)
	}
	p := profiles[0]
	if p.Type != profile.TypeVMess || p.Server != "1.1.1.1" || p.Transport.Type != "ws" {
		t.Fatalf("unexpected: %+v", p)
	}
}

func TestParseHysteria2(t *testing.T) {
	link := "hy2://secret@hy.example.com:443?sni=hy.example.com&obfs-password=salamander#hy"
	profiles, err := parse.ParseLinks([]string{link})
	if err != nil {
		t.Fatal(err)
	}
	p := profiles[0]
	if p.Type != profile.TypeHysteria2 || p.Password != "secret" || p.Obfuscation != "salamander" {
		t.Fatalf("unexpected: %+v", p)
	}
}

func TestParseTUIC(t *testing.T) {
	link := "tuic://uuid:token@1.2.3.4:443?sni=example.com&congestion_control=bbr#tuic"
	profiles, err := parse.ParseLinks([]string{link})
	if err != nil {
		t.Fatal(err)
	}
	p := profiles[0]
	if p.UUID != "uuid" || p.Token != "token" {
		t.Fatalf("unexpected: %+v", p)
	}
}

func TestClashVMessVLESS(t *testing.T) {
	yaml := `proxies:
  - name: vless-node
    type: vless
    server: 1.2.3.4
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: example.com
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: example.com
`
	result, err := parse.ParseText(yaml, parse.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Profiles[0].Type != profile.TypeVLESS {
		t.Fatalf("got %+v", result.Profiles[0])
	}
}

func TestBuildVLESS(t *testing.T) {
	p := profile.Profile{
		Type: profile.TypeVLESS, Server: "1.2.3.4", Port: 443,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811",
		TLS:  &profile.TLS{Enabled: true, SNI: "example.com"},
	}
	_, err := build.Build(build.Input{Profile: p, Settings: profile.Settings{ForTest: true}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestExportVLESSRoundTrip(t *testing.T) {
	orig := profile.Profile{
		Type: profile.TypeVLESS, Name: "n", Server: "1.2.3.4", Port: 443,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811",
		TLS:  &profile.TLS{Enabled: true, Security: "tls", SNI: "example.com"},
		Transport: &profile.Transport{Type: "tcp"},
	}
	link, err := export.ToShareLink(orig)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := parse.ParseLinks([]string{link})
	if err != nil {
		t.Fatal(err)
	}
	if profiles[0].UUID != orig.UUID || profiles[0].Server != orig.Server {
		t.Fatalf("round trip: %+v", profiles[0])
	}
}
