package parse_test

import (
	"testing"

	"node-config/export"
	"node-config/parse"
)

func TestParseSS_SIP002(t *testing.T) {
	link := "ss://aes-256-gcm:test@127.0.0.1:8388#test-node"
	profiles, err := parse.ParseLinks([]string{link})
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 {
		t.Fatalf("got %d profiles", len(profiles))
	}
	p := profiles[0]
	if p.Type != "ss" || p.Server != "127.0.0.1" || p.Port != 8388 {
		t.Fatalf("unexpected profile: %+v", p)
	}
	if p.Method != "aes-256-gcm" || p.Password != "test" {
		t.Fatalf("unexpected creds: %+v", p)
	}
	if p.Name != "test-node" {
		t.Fatalf("name: %q", p.Name)
	}
}

func TestParseTrojan(t *testing.T) {
	link := "trojan://password123@example.com:443?sni=example.com#MyTrojan"
	profiles, err := parse.ParseLinks([]string{link})
	if err != nil {
		t.Fatal(err)
	}
	p := profiles[0]
	if p.Type != "trojan" || p.Password != "password123" || p.Server != "example.com" {
		t.Fatalf("unexpected: %+v", p)
	}
	if p.TLS == nil || p.TLS.SNI != "example.com" {
		t.Fatalf("tls: %+v", p.TLS)
	}
}

func TestParseSOCKS5(t *testing.T) {
	link := "socks5://user:pass@127.0.0.1:1080#local"
	profiles, err := parse.ParseLinks([]string{link})
	if err != nil {
		t.Fatal(err)
	}
	p := profiles[0]
	if p.Type != "socks" || p.Username != "user" || p.Password != "pass" {
		t.Fatalf("unexpected: %+v", p)
	}
}

func TestParseClashYAML(t *testing.T) {
	text := `proxies:
  - name: ss-node
    type: ss
    server: 1.2.3.4
    port: 443
    cipher: aes-128-gcm
    password: secret
`
	result, err := parse.ParseText(text, parse.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Profiles) != 1 {
		t.Fatalf("got %d", len(result.Profiles))
	}
	p := result.Profiles[0]
	if p.Name != "ss-node" || p.Method != "aes-128-gcm" {
		t.Fatalf("unexpected: %+v", p)
	}
}

func TestRoundTripSS(t *testing.T) {
	link := "ss://aes-256-gcm:test@127.0.0.1:8388#node"
	profiles, err := parse.ParseLinks([]string{link})
	if err != nil {
		t.Fatal(err)
	}
	out, err := export.ToShareLink(profiles[0])
	if err != nil {
		t.Fatal(err)
	}
	again, err := parse.ParseLinks([]string{out})
	if err != nil {
		t.Fatal(err)
	}
	if again[0].Method != profiles[0].Method || again[0].Password != profiles[0].Password {
		t.Fatalf("round trip failed: %s -> %+v", out, again[0])
	}
}

func TestSubscriptionURL(t *testing.T) {
	result, err := parse.ParseText("clash://install-config?url=https%3A%2F%2Fexample.com%2Fsub", parse.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if result.SubscriptionURL == "" {
		t.Fatal("expected subscription url")
	}
	if len(result.Profiles) != 0 {
		t.Fatal("should not parse profiles")
	}
}
