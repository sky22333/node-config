package build

import (
	"encoding/json"

	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	"node-config/profile"
)

func rawOutbound(raw []byte, tag string) (option.Outbound, error) {
	if len(raw) == 0 {
		return option.Outbound{}, profile.ErrInvalidFormat
	}
	var base struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &base); err != nil || base.Type == "" {
		return option.Outbound{}, profile.ErrInvalidFormat
	}
	patched, err := mergeTagJSON(raw, tag)
	if err != nil {
		return option.Outbound{}, err
	}
	out := option.Outbound{Type: base.Type, Tag: tag}
	opts, err := unmarshalOutboundOptions(base.Type, patched)
	if err != nil {
		return option.Outbound{}, err
	}
	out.Options = opts
	return out, nil
}

func mergeTagJSON(raw []byte, tag string) ([]byte, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	tagB, _ := json.Marshal(tag)
	m["tag"] = tagB
	return json.Marshal(m)
}

func unmarshalOutboundOptions(typ string, raw []byte) (any, error) {
	switch typ {
	case constant.TypeShadowsocks:
		o := &option.ShadowsocksOutboundOptions{}
		return o, json.Unmarshal(raw, o)
	case constant.TypeVMess:
		o := &option.VMessOutboundOptions{}
		return o, json.Unmarshal(raw, o)
	case constant.TypeVLESS:
		o := &option.VLESSOutboundOptions{}
		return o, json.Unmarshal(raw, o)
	case constant.TypeTrojan:
		o := &option.TrojanOutboundOptions{}
		return o, json.Unmarshal(raw, o)
	case constant.TypeSOCKS:
		o := &option.SOCKSOutboundOptions{}
		return o, json.Unmarshal(raw, o)
	case constant.TypeHTTP:
		o := &option.HTTPOutboundOptions{}
		return o, json.Unmarshal(raw, o)
	case constant.TypeHysteria:
		o := &option.HysteriaOutboundOptions{}
		return o, json.Unmarshal(raw, o)
	case constant.TypeHysteria2:
		o := &option.Hysteria2OutboundOptions{}
		return o, json.Unmarshal(raw, o)
	case constant.TypeTUIC:
		o := &option.TUICOutboundOptions{}
		return o, json.Unmarshal(raw, o)
	case constant.TypeNaive:
		o := &option.NaiveOutboundOptions{}
		return o, json.Unmarshal(raw, o)
	case constant.TypeAnyTLS:
		o := &option.AnyTLSOutboundOptions{}
		return o, json.Unmarshal(raw, o)
	case constant.TypeShadowTLS:
		o := &option.ShadowTLSOutboundOptions{}
		return o, json.Unmarshal(raw, o)
	case constant.TypeSSH:
		o := &option.SSHOutboundOptions{}
		return o, json.Unmarshal(raw, o)
	case constant.TypeTor:
		o := &option.TorOutboundOptions{}
		return o, json.Unmarshal(raw, o)
	case constant.TypeDirect:
		o := &option.DirectOutboundOptions{}
		return o, json.Unmarshal(raw, o)
	case constant.TypeSelector:
		o := &option.SelectorOutboundOptions{}
		return o, json.Unmarshal(raw, o)
	case constant.TypeURLTest:
		o := &option.URLTestOutboundOptions{}
		return o, json.Unmarshal(raw, o)
	default:
		return nil, profile.ErrUnsupportedType
	}
}
