# container-policy-guard-go

本地容器镜像准入判定流程：用**本地清单文件**模拟镜像元数据、用**策略 JSON 文件 + 进程内置规则**模拟准入规则，在并发请求下给出一致、可解释的准入结论。全程无外部依赖（仅标准库）。

## 目录结构

| 包 | 职责 |
| --- | --- |
| `policy` | 内置规则与外部策略文件的统一加载、字段校验、跨来源冲突检测 |
| `manifest` | 本地镜像清单（元数据/签名/证明）的加载、字段与版本校验 |
| `signature` | 本地公钥环（轮换/吊销）、多签校验、摘要算法差异处理、证明校验 |
| `guard` | 准入评估器：规则选择、要求执行、并发安全、结论缓存与失效 |
| `cmd/guarddemo` | 端到端演示：加载 → 并发评估 → 策略更新后重评 |
| `testdata/` | 示例策略、公钥环与 8 个覆盖各种边界的本地清单 |

## 策略模型

策略由若干**来源**合并而成，来源只有两类：

- `builtin`：进程内置规则（`policy.BuiltinSource`）；
- `file:<path>`：外部 JSON 策略文件（`policy.FileSource`），解析时
  `DisallowUnknownFields`，拼写错误的字段直接判语法错误。

单条规则结构：

```json
{
  "name": "external-deny-legacy",
  "source": "file",
  "priority": 200,
  "action": "deny",
  "imageRefs": ["registry.local/app/legacy:*"],
  "requires": ["signature", "attestation:sbom"],
  "reason": "human readable explanation"
}
```

规则语义：

1. **匹配**：`imageRefs` 支持 `path.Match` 通配；省略时匹配全部镜像。
2. **优先级**：数字越大越优先；只取最高优先级那一层规则。
3. **冲突 fail-closed**：同一镜像在最高优先级层同时存在 `allow` 与 `deny`
   规则（含内置与外部文件之间），判定为 `policy_conflict` 拒绝；加载阶段还会
   静态检测同优先级、镜像范围重叠、动作相反的规则，直接拒绝加载。
4. **默认拒绝**：没有任何规则命中且无 `defaultRule` 时返回
   `no_matching_rule`；`deny` 规则返回 `explicit_deny`（携带规则 `reason`）。
5. **放行条件**：`allow` 规则的 `requires` 必须全部满足，支持
   `signature` 与 `attestation:<type>`。

策略快照 `Bundle` 同时携带：

- `Version`：策略声明的版本号（取所有来源最大值）；
- `Revision`：所有来源**原始内容**的 SHA-256 指纹，任何来源内容变化都会变。

## 失败原因（可区分，绝不静默放行）

| Reason | 含义 |
| --- | --- |
| `policy_syntax_error` | 策略 JSON 语法/字段取值非法 |
| `policy_missing_field` | 关键字段缺失（version、rule.name、action 等） |
| `policy_conflict` | 同优先级规则动作相反/多个 defaultRule |
| `policy_unavailable` | 评估时没有可用策略（fail-closed） |
| `no_matching_rule` | 无规则命中且无默认规则（默认拒绝） |
| `explicit_deny` | 命中显式 deny 规则 |
| `manifest_not_found` / `manifest_missing_field` / `manifest_version_incompatible` | 清单问题三类分开 |
| `signature_missing` | 镜像没有任何签名 |
| `signature_verification_failed` | 签名值重算比对不一致（被篡改） |
| `signing_key_revoked` | 签名公钥在吊销链上 |
| `signing_key_unknown` | 公钥环中无对应公钥 |
| `digest_algorithm_mismatch` | 签名摘要算法与清单声明不一致（如签名按 sha512、清单写 sha256） |
| `digest_algorithm_unsupported` | 使用了不支持的摘要算法（仅接受 sha256/sha512） |
| `attestation_missing` / `attestation_invalid` | 证明缺失与证明无效分开 |

### 签名与公钥模型

- **多签**：多个签名中任一合法即通过（兼容轮换过渡期）；全部失败时按最严重
  原因拒绝，严重度：吊销 > 不支持的摘要算法 > 摘要算法不一致 > 未知公钥 > 验签失败。
- **公钥轮换**：`rotated` 键带 `rotatedBy` 指向新键，旧镜像签名沿轮换链
  仍可验证；`revoked` 键的签名一律拒绝。
- **模拟实现**：无真实密码学运算，签名/证明为确定性组合值
  `sig|<keyID>|<sigAlg>|<digestAlg>|<digest>`，校验时重算比对，从而真实区分
  “值被篡改”“键不可信”“算法不匹配”等路径。

## 缓存与失效规则

`guard.resultCache` 的键是 `(policyVersion, revision, imageID)` 三元组：

1. **只缓存通过结论**：任何 deny（含清单暂时拉不到、验签失败等）都不写入缓存，
   故障恢复后立即重评，拒绝结论不会被固化为“通过”或长期挡住镜像。
2. **策略更新双保险失效**：
   - 版本号或内容指纹变化后，旧键自然查不到；
   - `Evaluator.UpdatePolicy` 还会原子替换策略快照并整体清空缓存，
     “版本号没改但文件内容变了”同样失效。
3. **并发一致**：评估器全程读写锁保护；同一镜像的并发请求由内置
   singleflight 合并为一次计算（见 `TestSingleflightSharesComputation`），
   其余请求共享同一结论。

## 验证方式

```bash
# 全部单测（含竞态检测）
go test -race -count=1 ./...

# 覆盖率
go test -cover ./...

# 端到端演示：并发评估 4 个镜像，随后切换策略版本再评估
go run ./cmd/guarddemo
```

测试覆盖的边界：

- 64 goroutine 并发评估同一镜像，结论全部一致且只落 1 条缓存；
- 策略更新（版本变化 / 仅内容指纹变化）后旧结论不复用；
- 先拒绝（清单缺失）后恢复，拒绝结论未被缓存、恢复后放行；
- 验签失败、公钥吊销、未知公钥、多签混合、轮换旧键、摘要算法不一致/不支持；
- 证明缺失与证明无效分开；
- 清单字段缺失、元数据版本不兼容、清单不存在三类原因分开；
- 策略语法错误、关键字段缺失、规则冲突在加载阶段即拒绝。

单测通过 `t.Logf` 打印每个用例的**输入**（镜像标识、签名键、算法）与
**判定依据**（命中规则、reason、detail），`go test -v` 可查看；
评估器自身也通过标准 `log` 输出 `evaluate/cache=hit/policy updated` 审计行。
