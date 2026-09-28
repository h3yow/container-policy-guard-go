# 策略模型

本系统在本地完成容器镜像准入判定：**不访问网络**，镜像元数据来自本地清单文件，
准入规则来自内置规则与外部策略文件，签名/证明来自随镜像提供的本地文件。
任何无法给出肯定放行结论的情形，一律**默认拒绝**，并给出可区分的拒绝原因。

## 1. 统一规则表示

内置规则与外部策略文件共用同一个结构（`policy.Rule`）：

| 字段 | 含义 |
| --- | --- |
| `id` | 规则唯一标识；外部文件内重复 id 在加载阶段按**规则冲突**拒绝 |
| `source` | `builtin`（内置）或 `file`（外部文件） |
| `repository` | 仓库匹配，支持 `path.Match` 通配（`*`、`?`、`[...]`） |
| `imageName` | 镜像名精确匹配 |
| `tagPattern` | 标签匹配，支持 `path.Match` 通配 |
| `requiredSignatures` | 需要的**有效**签名数量（多签） |
| `requireAttestations` | 必须存在且通过校验的证明类型列表，如 `provenance`、`sbom` |
| `allowedDigestAlgorithms` | 允许的镜像摘要算法，如 `sha256` |
| `effect` | `allow` 或 `deny` |
| `priority` | 优先级，数值越大越先生效 |

策略文件（YAML 或 JSON）形如：

```yaml
version: pol-v1
rules:
  - id: org/allow-signed-images
    repository: registry.example.com/*
    requiredSignatures: 2
    allowedDigestAlgorithms: [sha256, sha384, sha512]
    effect: allow
    priority: 100
```

## 2. 内置规则与外部策略的合并

- 内置策略（`policy.BuiltinPolicy`）始终存在，例如
  `builtin/signed-library` 对官方 `docker.io/library/*` 要求签名与强摘要算法。
- 外部策略加载后与内置规则合并；同 `id` 的外部规则**覆盖**内置规则。
- 外部文件内重复 `id`、缺少必填字段（`version`、`id`、`effect`、匹配器）、
  非法通配符、非法摘要算法，分别在加载阶段按 **syntax / missing_field /
  conflict** 三类错误拒绝，装配失败，不会静默放行。

## 3. 匹配与冲突仲裁

评估器（`policy.Evaluator`）对镜像元数据逐条匹配规则：

1. 收集所有命中规则及其依据（`Match`，含规则 id、来源、动作、命中原因）。
2. 无任何规则命中 → 拒绝（`NO_MATCHING_RULE`，默认拒绝）。
3. 取最高优先级的命中规则：
   - 同时存在 `allow` 与 `deny` → **规则冲突**，拒绝（`RULES_DISAGREE`），
     不做猜测；
   - 只有 `deny` → 显式拒绝（`EXPLICIT_DENY`）；
   - 只有 `allow` → 作为生效规则，继续执行签名/证明/摘要约束。

## 4. 签名与证明校验（sigverify）

签名载荷格式为 `image|<digestAlg>|<digest>`，证明载荷格式为
`attest|<digestAlg>|<digest>|<type>|<payload>`，与 `sigverify` 包内实现一致。

- **多签**：逐个签名独立验证，按“通过校验的签名数”计数，对照
  `requiredSignatures`；吊销密钥、未知密钥的签名不计入。
- **公钥轮换**：状态为 `rotated` 的密钥仍可验证**既有**镜像的签名（兼容旧镜像），
  状态为 `revoked` 的密钥任何签名一律无效。
- **吊销**：使用吊销密钥的签名给出 `key_revoked` 失败，最终映射为
  `SIGNING_KEY_REVOKED`。
- **未知密钥**：公钥库中不存在的密钥给出 `key_unknown` 失败。
- **摘要算法差异**：镜像声明的摘要算法不受支持（如 `sha1`）→
  `UNSUPPORTED_DIGEST_ALGORITHM`；签名声明的算法与镜像不一致也单独记录。
- **摘要不匹配**：签名覆盖的摘要与镜像摘要不一致 → `digest_mismatch`。
- **证明缺失 vs 验签失败**：规则要求的证明类型在镜像上不存在 →
  `ATTESTATION_MISSING`；存在但签名被篡改/密钥非法 →
  `ATTESTATION_VERIFY_FAILED`；两类原因严格区分。

## 5. 可区分的拒绝原因

所有拒绝都映射为明确的原因码（`guard.Reason`），并写入判定轨迹：

| 原因码 | 触发场景 |
| --- | --- |
| `POLICY_SYNTAX_ERROR` | 策略文件语法错误（装配期） |
| `POLICY_MISSING_FIELD` | 策略缺少 version/id/effect/匹配器等必填字段（装配期） |
| `POLICY_CONFLICT` | 规则 id 重复或同优先级 allow/deny 冲突（装配/评估期） |
| `IMAGE_META_MISSING` | 镜像引用不在清单中，或仓库/摘要等关键字段缺失 |
| `META_VERSION_INCOMPATIBLE` | 元数据 `apiVersion` 不在支持列表（当前 `guard.image/v1`） |
| `NO_MATCHING_RULE` | 没有任何规则命中（默认拒绝） |
| `RULES_DISAGREE` | 最高优先级命中规则 allow/deny 互相矛盾 |
| `EXPLICIT_DENY` | 命中显式 deny 规则 |
| `SIGNATURE_MISSING` | 规则要求签名但镜像未携带任何签名 |
| `SIGNATURE_VERIFY_FAILED` | 签名数量不足、未知密钥、摘要不匹配、密码学验签失败 |
| `SIGNING_KEY_REVOKED` | 签名使用了已吊销密钥 |
| `ATTESTATION_MISSING` | 缺少规则要求的证明类型 |
| `ATTESTATION_VERIFY_FAILED` | 证明存在但验签失败/密钥非法 |
| `UNSUPPORTED_DIGEST_ALGORITHM` | 镜像或签名使用了 sha1 等不受支持的摘要算法 |
| `INTERNAL_ERROR` | 未预期的内部错误（同样拒绝） |
