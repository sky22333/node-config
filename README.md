## node-config

独立 Go 库：代理链接 / 订阅解析与 sing-box 配置生成。

## 要求

- Go 1.26+
- sing-box v1.14.0-alpha.32

## 安装（本地包）

```bash
# 在消费方 go.mod 中：
require node-config v0.0.0
replace node-config => ../node-config
```

## 公共 API

```go
import (
    "node-config/parse"
    "node-config/export"
    "node-config/build"
    "node-config/profile"
)

// 解析订阅或链接
result, err := parse.ParseText(text, parse.Options{})

// 导出 share link
link, err := export.ToShareLink(profile)

// 生成 sing-box 配置
// 链式 / 分组 / 规则
out, err := build.Build(build.Input{
    Profile: mainProfile,
    Profiles: map[int64]profile.Profile{ /* 所有相关节点 */ },
    Settings: profile.Settings{
        FrontProxyID:   frontID,
        LandingProxyID: landingID,
        IsSelector:     true,
        SelectorProfileIDs: []int64{1, 2, 3},
        Rules: []profile.RouteRule{{
            Outbound: "direct",
            Domains:  []string{"geosite:cn", "domain:example.com"},
            RemoteRuleSets: []profile.RemoteRuleSetRef{{
                URL: "https://cdn.example.com/geoip-cn.srs",
            }},
        }},
    },
})
```

## CLI

```bash
go run ./cmd parse -f subscription.yaml
go run ./cmd export -p profile.json
go run ./cmd build -p profile.json
```

## 模块

| 包 | 职责 |
|----|------|
| `profile` | 统一数据模型与 Settings |
| `parse` | 链接 / 订阅解析 |
| `export` | Profile 导出与 outbound 互转 |
| `build` | sing-box 配置生成 |

## 开发

```bash
go test ./...
```
