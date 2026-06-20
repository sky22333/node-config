package build_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"

	"node-config/build"
	"node-config/profile"
)

var ssProfile = profile.Profile{
	Type:     profile.TypeSS,
	Server:   "127.0.0.1",
	Port:     8388,
	Method:   "aes-256-gcm",
	Password: "test",
}

func TestBuildSSForTest(t *testing.T) {
	result, err := build.Build(build.Input{
		Profile:  ssProfile,
		Settings: profile.Settings{ForTest: true, LogLevel: "info"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid([]byte(result.Config)) {
		t.Fatal("invalid json")
	}
	if result.MainOutboundTag != build.TagProxy {
		t.Fatalf("tag: %s", result.MainOutboundTag)
	}
}

func TestBuildProxyMode(t *testing.T) {
	settings := profile.DefaultSettings()
	result, err := build.Build(build.Input{Profile: ssProfile, Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result.Config, `"type":"tun"`) || strings.Contains(result.Config, `"type": "tun"`) {
		t.Fatal("proxy mode must not include tun inbound")
	}
	if !strings.Contains(result.Config, build.TagMixed) {
		t.Fatal("proxy mode must include mixed inbound")
	}
	assertDNSServers(t, result.Config, "dns-direct", "dns-remote")
}

func TestBuildVPNMode(t *testing.T) {
	settings := profile.VPNSettings()
	result, err := build.Build(build.Input{Profile: ssProfile, Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Config, `"type":"tun"`) && !strings.Contains(result.Config, `"type": "tun"`) {
		t.Fatal("vpn mode must include tun inbound")
	}
	if !strings.Contains(result.Config, `"auto_route":true`) && !strings.Contains(result.Config, `"auto_route": true`) {
		t.Fatal("vpn mode must enable auto_route")
	}
	if !strings.Contains(result.Config, build.TagTun) {
		t.Fatal("vpn mode must tag tun inbound")
	}
	assertDNSServers(t, result.Config, "dns-direct", "dns-remote")
}

func TestBuildVPNFakeDNS(t *testing.T) {
	settings := profile.VPNSettings()
	settings.EnableFakeDNS = true
	result, err := build.Build(build.Input{Profile: ssProfile, Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Config, `"tag":"dns-fake"`) && !strings.Contains(result.Config, `"tag": "dns-fake"`) {
		t.Fatal("fake dns server missing")
	}
}

func assertDNSServers(t *testing.T, config string, tags ...string) {
	t.Helper()
	for _, tag := range tags {
		if !strings.Contains(config, `"tag":"`+tag+`"`) && !strings.Contains(config, `"tag": "`+tag+`"`) {
			t.Fatalf("missing dns server tag %q", tag)
		}
	}
}

func TestBuildUnmarshal(t *testing.T) {
	result, err := build.Build(build.Input{
		Profile:  ssProfile,
		Settings: profile.DefaultSettings(),
	})
	if err != nil {
		t.Fatal(err)
	}
	var opts option.Options
	if err := sjson.UnmarshalContext(context.Background(), []byte(result.Config), &opts); err != nil {
		if !json.Valid([]byte(result.Config)) {
			t.Fatal(err)
		}
	}
}

func TestBuildChainDetour(t *testing.T) {
	exit := profile.Profile{ID: 1, Name: "exit", Type: profile.TypeSS, Server: "1.1.1.1", Port: 8388, Method: "aes-256-gcm", Password: "a"}
	entry := profile.Profile{ID: 2, Name: "entry", Type: profile.TypeSS, Server: "2.2.2.2", Port: 8388, Method: "aes-256-gcm", Password: "b"}
	settings := profile.DefaultSettings()
	settings.LandingProxyID = 2
	settings.FrontProxyID = 0
	result, err := build.Build(build.Input{
		Profile:  exit,
		Profiles: map[int64]profile.Profile{1: exit, 2: entry},
		Settings: settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Config, `"detour":"g-1"`) && !strings.Contains(result.Config, `"detour": "g-1"`) {
		t.Fatal("chain must link landing to global exit via detour")
	}
	if result.MainOutboundTag != "entry" {
		t.Fatalf("main tag should be landing readable name, got %q", result.MainOutboundTag)
	}
}

func TestBuildSelector(t *testing.T) {
	a := profile.Profile{ID: 1, Name: "a", Type: profile.TypeSS, Server: "1.1.1.1", Port: 8388, Method: "aes-256-gcm", Password: "a"}
	b := profile.Profile{ID: 2, Name: "b", Type: profile.TypeSS, Server: "2.2.2.2", Port: 8388, Method: "aes-256-gcm", Password: "b"}
	settings := profile.DefaultSettings()
	settings.IsSelector = true
	settings.SelectorProfileIDs = []int64{1, 2}
	result, err := build.Build(build.Input{
		Profile:  a,
		Profiles: map[int64]profile.Profile{1: a, 2: b},
		Settings: settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Config, `"type":"selector"`) && !strings.Contains(result.Config, `"type": "selector"`) {
		t.Fatal("selector outbound missing")
	}
	if result.MainOutboundTag != build.TagProxy {
		t.Fatalf("selector mode main tag: %s", result.MainOutboundTag)
	}
}

func TestBuildRuleSet(t *testing.T) {
	settings := profile.DefaultSettings()
	settings.Rules = []profile.RouteRule{{
		Outbound:    "direct",
		Domains:     []string{"geosite:cn"},
		RuleSetRefs: []string{"geosite:cn"},
	}}
	result, err := build.Build(build.Input{Profile: ssProfile, Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Config, `"tag":"geosite:cn"`) && !strings.Contains(result.Config, `"tag": "geosite:cn"`) {
		t.Fatal("local rule_set missing")
	}
	if !strings.Contains(result.Config, `"rule_set"`) {
		t.Fatal("route rule should reference rule_set")
	}
}

func TestBuildRemoteRuleSet(t *testing.T) {
	settings := profile.DefaultSettings()
	settings.RuleSetUpdateInterval = "24h"
	settings.Rules = []profile.RouteRule{{
		Outbound: "proxy",
		Domains:  []string{"domain:example.com"},
		RemoteRuleSets: []profile.RemoteRuleSetRef{{
			URL: "https://example.com/rule.srs",
		}},
	}}
	result, err := build.Build(build.Input{Profile: ssProfile, Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Config, `"type":"remote"`) && !strings.Contains(result.Config, `"type": "remote"`) {
		t.Fatal("remote rule_set missing")
	}
}
