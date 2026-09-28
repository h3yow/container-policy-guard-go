# 验证方式

## 1. 单元测试

```bash
go test ./... -v
```

测试按关注点拆分，日志中会打印**输入**（镜像引用、摘要、签名数量与密钥 id、
策略版本）与**判定依据**（命中规则、生效规则、签名/证明校验明细、拒绝原因）：

| 测试文件 | 覆盖点 |
| --- | --- |
| `guard_test.go` | 双签放行、默认拒绝、并发一致性与缓存命中、拒绝结论缓存为拒绝、策略更新失效、坏策略重载保留旧版本 |
| `sigverify_scenarios_test.go` | 验签失败（篡改）、未知密钥、吊销密钥、签名缺失、摘要算法差异、弱摘要算法、证明缺失、证明验签失败、证明有效、元数据版本不兼容、字段缺失、引用不在清单 |
| `loadfail_multi_test.go` | 策略语法/缺字段/冲突三类加载错误可区分、多签计数、一吊销一有效、轮换密钥仍可验证旧镜像 |
| `policy/policy_test.go` | JSON 策略加载、同优先级 allow/deny 冲突、内置默认拒绝、摘要前缀校验 |
| `sigverify/sigverify_test.go` | 多签统计、篡改、未知密钥、摘要算法差异、不支持的摘要算法、摘要不匹配、证明缺失与验签失败区分、无签名证明的存在性校验 |
| `resultcache/cache_test.go` | 缓存读写、按策略版本隔离、按镜像失效、清空 |
| `internal/yamlish/yamlish_test.go` | YAML 子集解析（映射/序列/流序列/块标量/注释）与语法错误拒绝 |

## 2. 可运行示例（CLI）

`cmd/cpguard` 用本地清单、策略文件与公钥库对单个引用做判定，退出码
`0` 表示放行、`1` 表示拒绝、`2` 参数错误、`3` 装配失败、`4` 内部错误：

```bash
# 内置策略（无外部 allow 规则 -> 默认拒绝）
go run ./cmd/cpguard --ref registry.example.com/base:1.0

# 外部策略（要求 2 个签名；CLI 不携带签名 -> SIGNATURE_MISSING）
go run ./cmd/cpguard --policy testdata/policy.yaml \
  --manifest testdata/manifest.yaml --keyring testdata/keyring.yaml \
  --ref registry.example.com/base:1.0

# 元数据版本不兼容 / 弱摘要算法 / 引用不在清单 / 坏策略装配失败
go run ./cmd/cpguard --ref registry.example.com/legacy:1
go run ./cmd/cpguard --ref registry.example.com/weak:1
go run ./cmd/cpguard --ref registry.example.com/nope:9
go run ./cmd/cpguard --policy testdata/policy-bad-syntax.yaml \
  --ref registry.example.com/base:1.0
```

## 3. 测试夹具

- `testdata/policy.yaml` / `policy-v2.yaml`：外部策略 v1 与更新后的 v2；
- `testdata/policy-bad-{syntax,missing,conflict}.yaml`：语法错误、关键字段
  缺失、规则冲突三类坏策略；
- `testdata/manifest.yaml`：本地镜像清单，包含正常镜像、`apiVersion:
  guard.image/v0` 的不兼容镜像与 `sha1` 弱摘要镜像；
- `testdata/keyring.yaml`：`active` / `rotated` / `revoked` 三种状态的信任公钥。

> 说明：为保证离线可构建，仓库内置了一个极简 YAML 子集解析器
> （`internal/yamlish`），策略/清单/公钥库同时支持 JSON；签名使用
> Ed25519/RSA/ECDSA，测试密钥在运行期生成，私钥不落盘。
