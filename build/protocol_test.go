package build_test

import (
	"strings"
	"testing"

	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

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

func TestBuildTrojanTransportDetails(t *testing.T) {
	p := profile.Profile{
		Type: profile.TypeTrojan, Server: "1.1.1.1", Port: 443, Password: "pwd",
		TLS:       &profile.TLS{Enabled: true, SNI: "example.com"},
		Transport: &profile.Transport{Type: "ws", Host: "cdn.example.com", Path: "/ws"},
	}
	out, err := build.Outbound(p, "proxy")
	if err != nil {
		t.Fatal(err)
	}
	opts, ok := out.Options.(*option.TrojanOutboundOptions)
	if !ok {
		t.Fatalf("options: %T", out.Options)
	}
	if opts.Transport == nil || opts.Transport.Type != constant.V2RayTransportTypeWebsocket || opts.Transport.WebsocketOptions.Path != "/ws" {
		t.Fatalf("transport not preserved: %+v", opts.Transport)
	}
}

func TestBuildHysteriaServerPorts(t *testing.T) {
	p := profile.Profile{
		Type: profile.TypeHysteria2, Server: "hy.example.com", Port: 443,
		ServerPorts: "20000:20100", Password: "pwd", HopInterval: "30s", HopIntervalMax: "1m",
		TLS: &profile.TLS{Enabled: true, SNI: "hy.example.com"},
	}
	out, err := build.Outbound(p, "proxy")
	if err != nil {
		t.Fatal(err)
	}
	opts, ok := out.Options.(*option.Hysteria2OutboundOptions)
	if !ok {
		t.Fatalf("options: %T", out.Options)
	}
	if opts.ServerPort != 0 || len(opts.ServerPorts) != 1 || opts.ServerPorts[0] != "20000:20100" {
		t.Fatalf("server ports not preserved: %+v", opts)
	}
	if opts.HopInterval == 0 || opts.HopIntervalMax == 0 {
		t.Fatalf("hop intervals not preserved: %+v", opts)
	}
}

func TestBuildWireGuardInvalidPrefix(t *testing.T) {
	p := profile.Profile{
		Type: profile.TypeWireGuard, Server: "1.1.1.1", Port: 51820,
		WGPrivateKey: "priv", PeerPublicKey: "pub",
		LocalAddresses: []string{"not-a-prefix"},
	}
	_, err := build.Build(build.Input{Profile: p, Settings: profile.DefaultSettings()})
	if err != profile.ErrInvalidFormat {
		t.Fatalf("err: %v", err)
	}
}
