# container-policy-guard-go

一套**本地**容器镜像准入判定流程：用本地清单与策略文件模拟镜像元数据与准入
规则，统一加载内置规则与外部策略，在并发请求下给出一致、可解释的结论。
不访问网络，默认拒绝（fail-closed）。

## 能力

- **统一策略加载与判定**：内置规则与 YAML/JSON 外部策略文件合并；语法错误、
  关键字段缺失、规则互相冲突都显式报错或给出可区分拒绝原因，不静默放行。
- **并发评估与缓存**：同一请求的并发评估做 singleflight 合并；缓存键随
  策略版本、镜像标识与请求输入指纹变化；策略更新原子切换版本并清空缓存；
  拒绝结论原样缓存，永远不会被当成通过复用。
- **本地签名/证明校验**：多签计数、公钥轮换（rotated 仍可验证旧镜像）、
  吊销（revoked 一律无效）、摘要算法差异分别处理；验签失败、证明缺失、
  元数据版本不兼容使用不同原因码区分。
- **可解释结论**：`Decision` 携带原因码、命中规则与逐条判定轨迹，可通过
  `Explain()` 输出，单测日志同时打印输入与判定依据。

## 目录结构

```
guard.go                 编排器：装配、评估管线、缓存、并发合并、热重载
policy/                  策略加载/校验/合并/仲裁，镜像清单与元数据
sigverify/               信任公钥库、签名与证明的本地密码学校验
resultcache/             随策略版本与镜像标识失效的并发安全缓存
internal/yamlish/        离线 YAML 子集解析（JSON 走标准库）
internal/testdata/       测试用密钥/签名/夹具生成工具
cmd/cpguard/             可运行的判定 CLI
testdata/                策略、清单、公钥库样例与坏策略夹具
docs/                    策略模型、缓存失效规则、验证方式文档
```

## 快速开始

```bash
go test ./... -v
go run ./cmd/cpguard --policy testdata/policy.yaml \
  --manifest testdata/manifest.yaml --keyring testdata/keyring.yaml \
  --ref registry.example.com/base:1.0
```

## 文档

- [策略模型](docs/policy-model.md)
- [并发评估、缓存与失效](docs/cache-and-invalidation.md)
- [验证方式](docs/verification.md)
