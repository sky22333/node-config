package build_test

import (
	"strings"
	"testing"

	"node-config/build"
	"node-config/profile"
)

func TestBuildAnyTLS(t *testing.T) {
	p := profile.Profile{
		Type: profile.TypeAnyTLS, Server: "1.1.1.1", Port: 443,
		Password: "pwd", TLS: &profile.TLS{Enabled: true, SNI: "example.com"},
	}
	out, err := build.Outbound(p, "proxy")
	if err != nil {
		t.Fatal(err)
	}
	if out.Type != "anytls" {
		t.Fatalf("type: %s", out.Type)
	}
}

func TestBuildWireGuardEndpoint(t *testing.T) {
	settings := profile.DefaultSettings()
	p := profile.Profile{
		Type: profile.TypeWireGuard, Server: "1.1.1.1", Port: 51820,
		WGPrivateKey: "priv", PeerPublicKey: "pub",
		LocalAddresses: []string{"10.0.0.2/32"},
	}
	result, err := build.Build(build.Input{Profile: p, Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Config, `"type":"wireguard"`) && !strings.Contains(result.Config, `"type": "wireguard"`) {
		t.Fatal("wireguard endpoint missing")
	}
}

func TestBuildSSRFails(t *testing.T) {
	p := profile.Profile{Type: profile.TypeSSR, Server: "1.1.1.1", Port: 443}
	_, err := build.Outbound(p, "proxy")
	if err != profile.ErrRemovedInSingBox {
		t.Fatalf("err: %v", err)
	}
}
