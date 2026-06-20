package build

import (
	"context"

	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"

	"node-config/profile"
)

// Input is passed to Build.
type Input struct {
	Profile  profile.Profile           `json:"profile"`
	Profiles map[int64]profile.Profile `json:"profiles,omitempty"`
	Settings profile.Settings          `json:"settings"`
}

// Result is returned by Build.
type Result struct {
	Config          string `json:"config"`
	MainOutboundTag string `json:"main_outbound_tag"`
}

// Build generates a sing-box configuration JSON string.
func Build(in Input) (*Result, error) {
	if in.Profile.Type == profile.TypeConfig && len(in.Profile.RawConfig) > 0 {
		return &Result{
			Config:          string(in.Profile.RawConfig),
			MainOutboundTag: in.Profile.Name,
		}, nil
	}

	bc := newBuildCtx(in)
	outbounds, mainTag, err := bc.buildOutbounds(in)
	if err != nil {
		return nil, err
	}

	opts := option.Options{
		Log:       &option.LogOptions{Level: bc.settings.LogLevel},
		DNS:       buildDNS(bc),
		Inbounds:  buildInbounds(bc.settings),
		Endpoints: bc.extraEndpoints,
		Outbounds: outbounds,
		Route:     buildRoute(bc, mainTag),
	}

	if !bc.settings.ForTest && bc.settings.EnableCacheFile {
		opts.Experimental = &option.ExperimentalOptions{
			CacheFile: &option.CacheFileOptions{
				Enabled:     true,
				Path:        "../cache/cache.db",
				StoreFakeIP: bc.settings.EnableFakeDNS,
			},
		}
	}
	if !bc.settings.ForTest && bc.settings.EnableClashAPI {
		if opts.Experimental == nil {
			opts.Experimental = &option.ExperimentalOptions{}
		}
		opts.Experimental.ClashAPI = &option.ClashAPIOptions{
			ExternalController: "127.0.0.1:9090",
			ExternalUI:         "../files/yacd",
		}
	}

	raw, err := sjson.MarshalContext(context.Background(), opts)
	if err != nil {
		return nil, err
	}

	config := string(raw)
	if bc.settings.CustomConfig != "" {
		config, err = mergeJSON(config, bc.settings.CustomConfig)
		if err != nil {
			return nil, err
		}
	}
	if len(in.Profile.CustomConfig) > 0 {
		config, err = mergeJSON(config, string(in.Profile.CustomConfig))
		if err != nil {
			return nil, err
		}
	}

	return &Result{Config: config, MainOutboundTag: mainTag}, nil
}

func mergeJSON(base, patch string) (string, error) {
	var a, b map[string]any
	if err := sjson.Unmarshal([]byte(base), &a); err != nil {
		return "", err
	}
	if err := sjson.Unmarshal([]byte(patch), &b); err != nil {
		return "", err
	}
	mergeMap(a, b)
	out, err := sjson.Marshal(a)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func mergeMap(dst, src map[string]any) {
	for k, v := range src {
		if vMap, ok := v.(map[string]any); ok {
			if dstMap, ok := dst[k].(map[string]any); ok {
				mergeMap(dstMap, vMap)
				continue
			}
		}
		dst[k] = v
	}
}
