package parse_test

import (
	"testing"

	"node-config/parse"
)

func TestParseSSRClash(t *testing.T) {
	yaml := `proxies:
  - name: ssr1
    type: ssr
    server: 1.2.3.4
    port: 443
    cipher: aes-256-cfb
    password: pass
    protocol: origin
    obfs: plain
`
	r, err := parse.ParseText(yaml, parse.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Profiles) != 1 || r.Profiles[0].Type != "ssr" {
		t.Fatalf("%+v", r.Profiles)
	}
}

func TestParseAnyTLS(t *testing.T) {
	link := "anytls://password@example.com:443?sni=example.com#node"
	ps, err := parse.ParseLinks([]string{link})
	if err != nil {
		t.Fatal(err)
	}
	if ps[0].Type != "anytls" || ps[0].Password != "password" {
		t.Fatalf("%+v", ps[0])
	}
}

func TestParseNaive(t *testing.T) {
	link := "naive+https://user:pass@127.0.0.1:443?sni=example.com"
	ps, err := parse.ParseLinks([]string{link})
	if err != nil {
		t.Fatal(err)
	}
	if ps[0].Type != "naive" || ps[0].NaiveProto != "https" {
		t.Fatalf("%+v", ps[0])
	}
}

func TestParseWireGuardINI(t *testing.T) {
	conf := `[Interface]
Address = 10.0.0.2/32
PrivateKey = privkey

[Peer]
PublicKey = pubkey
Endpoint = 1.1.1.1:51820
`
	r, err := parse.ParseText(conf, parse.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Profiles) != 1 || r.Profiles[0].Type != "wireguard" {
		t.Fatalf("%+v", r.Profiles)
	}
}
