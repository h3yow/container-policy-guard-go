// Package guard 实现本地容器镜像准入判定流程：
// 加载内置规则与外部策略文件，对镜像元数据、签名与证明进行统一判定，
// 并提供随策略版本与镜像标识失效的并发安全结果缓存。
package guard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/h3yow/container-policy-guard-go/policy"
	"github.com/h3yow/container-policy-guard-go/resultcache"
	"github.com/h3yow/container-policy-guard-go/sigverify"
)

// Decision 是一次准入评估的最终结论。
type Decision struct {
	Allowed      bool
	Reason       Reason
	Detail       string
	MatchedRules []policy.Match
	ImageRef     string
	ImageDigest  string
	PolicyVer    string
	// Trace 按顺序记录判定依据，供日志输出与人工解释。
	Trace []string
}

// Explain 返回多行的人类可读判定依据。
func (d *Decision) Explain() string {
	var b strings.Builder
	verdict := "DENY"
	if d.Allowed {
		verdict = "ALLOW"
	}
	fmt.Fprintf(&b, "verdict=%s ref=%s digest=%s policyVersion=%s", verdict, d.ImageRef, d.ImageDigest, d.PolicyVer)
	if d.Reason != ReasonAllow {
		fmt.Fprintf(&b, " reason=%s detail=%q", d.Reason, d.Detail)
	}
	for _, line := range d.Trace {
		b.WriteString("\n  - " + line)
	}
	return b.String()
}

// Request 描述一次镜像准入评估请求。
type Request struct {
	// Reference 是镜像引用（仓库:标签或仓库@摘要）。
	Meta policy.ImageMeta
	// Signatures 是随镜像提供的本地签名集合。
	Signatures []sigverify.Signature
	// Attestations 是随镜像提供的本地证明集合。
	Attestations []sigverify.Attestation
}

// Config 是 Guard 的装配配置。
type Config struct {
	// PolicyPath 为外部策略文件路径；为空表示只用内置规则。
	PolicyPath string
	// ManifestPath 为本地镜像清单文件路径（YAML/JSON）。
	ManifestPath string
	// KeyringPath 为信任公钥库文件路径（YAML/JSON）。
	KeyringPath string
}

// Guard 是准入判定器，装配策略、签名验证与缓存。
type Guard struct {
	cfg Config

	mu        sync.RWMutex
	evaluator *policy.Evaluator
	keyring   *sigverify.Keyring
	manifest  *policy.Manifest
	version   string
	cache     *resultcache.Cache[*Decision]

	// inflight 用于合并同一缓存键的并发评估，保证并发请求结论一致。
	inflightMu sync.Mutex
	inflight   map[resultcache.Key][]*waiter
}

type waiter struct {
	ch chan *Decision
}

// New 根据配置装配 Guard。策略语法错误、关键字段缺失等问题在此显式报错，
// 不会静默放行。
func New(ctx context.Context, cfg Config) (*Guard, error) {
	g := &Guard{
		cfg:      cfg,
		cache:    resultcache.New[*Decision](),
		inflight: map[resultcache.Key][]*waiter{},
	}
	if cfg.ManifestPath != "" {
		m, err := policy.LoadManifest(ctx, cfg.ManifestPath)
		if err != nil {
			return nil, err // 关键字段缺失/语法错误：装配失败，绝不放行
		}
		g.manifest = m
	}
	if cfg.KeyringPath != "" {
		kr, err := sigverify.LoadKeyring(ctx, cfg.KeyringPath)
		if err != nil {
			return nil, err
		}
		g.keyring = kr
	}
	if err := g.reloadPolicyLocked(ctx); err != nil {
		return nil, err
	}
	return g, nil
}

// Evaluate 对单个请求执行准入评估，结果按 (策略版本, 镜像标识, 元数据摘要)
// 缓存。允许与拒绝结论都会原样缓存——拒绝结论永远以拒绝返回，绝不会被改写
// 成通过；策略重载产生新版本号后旧键自然失效，并额外清空缓存双保险。
func (g *Guard) Evaluate(ctx context.Context, req Request) (*Decision, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	g.mu.RLock()
	version := g.version
	g.mu.RUnlock()

	meta := req.Meta

	// 快照当前评估所需依赖。
	g.mu.RLock()
	eval := g.evaluator
	kr := g.keyring
	g.mu.RUnlock()

	ref := firstNonEmpty(meta.Reference, meta.Repository+":"+meta.Tag)
	key := resultcache.Key{
		PolicyVersion: version,
		ImageRef:      ref,
		MetaDigest:    requestFingerprint(meta, req),
	}

	if d, ok := g.cache.Get(key); ok {
		trace := append([]string(nil), d.Trace...)
		trace = append(trace, "cache: HIT key(policyVersion="+version+", ref="+ref+")")
		cp := *d
		cp.Trace = trace
		return &cp, nil
	}

	return g.evaluateInflight(key, version, eval, kr, meta, req)
}

// EvaluateRef 按镜像引用从已加载的本地清单补全元数据后执行评估。
// 清单中找不到引用时返回 IMAGE_META_MISSING 结论（默认拒绝，不报错中断）。
func (g *Guard) EvaluateRef(ctx context.Context, ref string, sigs []sigverify.Signature, atts []sigverify.Attestation) (*Decision, error) {
	meta, ok := g.LookupMeta(ref)
	if !ok {
		g.mu.RLock()
		version := g.version
		g.mu.RUnlock()
		d := &Decision{
			Allowed:   false,
			Reason:    ReasonMetaMissing,
			Detail:    "image reference not found in local manifest: " + ref,
			ImageRef:  ref,
			PolicyVer: version,
			Trace: []string{
				"input ref=" + ref,
				"denied: IMAGE_META_MISSING — reference not present in local manifest",
			},
		}
		return d, nil
	}
	return g.Evaluate(ctx, Request{Meta: meta, Signatures: sigs, Attestations: atts})
}

// evaluateInflight 合并同键并发请求：只有一个 goroutine 真正计算，
// 其余等待同一结论，确保并发下结论严格一致。
func (g *Guard) evaluateInflight(
	key resultcache.Key,
	version string,
	eval *policy.Evaluator,
	kr *sigverify.Keyring,
	meta policy.ImageMeta,
	req Request,
) (*Decision, error) {
	g.inflightMu.Lock()
	if ws, busy := g.inflight[key]; busy {
		w := &waiter{ch: make(chan *Decision, 1)}
		g.inflight[key] = append(ws, w)
		g.inflightMu.Unlock()
		d := <-w.ch
		return d, nil
	}
	g.inflight[key] = nil
	g.inflightMu.Unlock()

	d := g.compute(version, eval, kr, meta, req)

	g.cache.Set(key, d) // 允许/拒绝结论都缓存，原样存取
	g.inflightMu.Lock()
	ws := g.inflight[key]
	delete(g.inflight, key)
	g.inflightMu.Unlock()
	for _, w := range ws {
		w.ch <- d
	}
	return d, nil
}

func (g *Guard) compute(
	version string,
	eval *policy.Evaluator,
	kr *sigverify.Keyring,
	meta policy.ImageMeta,
	req Request,
) *Decision {
	ref := firstNonEmpty(meta.Reference, meta.Repository+":"+meta.Tag)
	base := func(reason Reason, detail string) *Decision {
		return &Decision{
			Allowed:     false,
			Reason:      reason,
			Detail:      detail,
			ImageRef:    ref,
			ImageDigest: meta.Digest,
			PolicyVer:   version,
			Trace: []string{
				"input ref=" + ref + " repository=" + meta.Repository + " tag=" + meta.Tag +
					" digest=" + meta.Digest + " digestAlg=" + meta.DigestAlg,
				"policy version=" + version,
				"denied: " + string(reason) + " — " + detail,
			},
		}
	}

	// 1) 元数据：缺失关键信息默认拒绝。
	if strings.TrimSpace(meta.Repository) == "" || strings.TrimSpace(meta.Digest) == "" {
		return base(ReasonMetaMissing, "image metadata missing: repository and digest are required")
	}
	// 2) 元数据 API 版本不兼容，单独区分。
	if !contains(policy.SupportedMetaAPIVersions, meta.APIVersion) {
		return base(ReasonMetaVersionIncompatible,
			"image meta apiVersion "+quote(meta.APIVersion)+" not in "+strings.Join(policy.SupportedMetaAPIVersions, ","))
	}
	if err := policy.Validate(meta); err != nil {
		return base(ReasonMetaMissing, err.Error())
	}
	if !policy.KnownDigestAlg(meta.DigestAlg) {
		return base(ReasonUnsupportedDigestAlgorithm,
			"image digest algorithm not supported: "+meta.DigestAlg)
	}

	// 3) 策略匹配与冲突仲裁。
	pr := eval.Evaluate(meta)
	d := &Decision{
		ImageRef:     ref,
		ImageDigest:  meta.Digest,
		PolicyVer:    version,
		MatchedRules: pr.Matches,
	}
	for _, m := range pr.Matches {
		d.Trace = append(d.Trace, fmt.Sprintf("match rule=%s source=%s effect=%s [%s]", m.RuleID, m.Source, m.Effect, m.Detail))
	}
	if len(pr.Matches) == 0 {
		d.Reason = ReasonNoMatchingRule
		d.Detail = "no policy rule matched this image; default deny"
		d.Trace = append(d.Trace, "denied: NO_MATCHING_RULE — default deny")
		return d
	}
	if pr.Winner == nil {
		d.Reason = ReasonRulesDisagree
		d.Detail = "highest-priority matched rules disagree on allow/deny"
		d.Trace = append(d.Trace, "denied: RULES_DISAGREE — conflicting rules at same top priority")
		return d
	}
	d.Trace = append(d.Trace, fmt.Sprintf("winner rule=%s effect=%s priority=%d", pr.Winner.ID, pr.Winner.Effect, pr.Winner.Priority))
	if pr.Winner.Effect == policy.EffectDeny {
		d.Reason = ReasonExplicitDeny
		d.Detail = "matched deny rule " + pr.Winner.ID
		d.Trace = append(d.Trace, "denied: EXPLICIT_DENY — rule "+pr.Winner.ID)
		return d
	}

	// 4) 胜出规则为 allow：执行摘要算法、签名数量、证明类型的约束。
	rule := pr.Winner
	if len(rule.AllowedDigests) > 0 && !contains(rule.AllowedDigests, meta.DigestAlg) {
		d.Reason = ReasonUnsupportedDigestAlgorithm
		d.Detail = fmt.Sprintf("digest algorithm %s not allowed by rule %s (allowed: %s)",
			meta.DigestAlg, rule.ID, strings.Join(rule.AllowedDigests, ","))
		d.Trace = append(d.Trace, "denied: UNSUPPORTED_DIGEST_ALGORITHM — "+d.Detail)
		return d
	}
	d.Trace = append(d.Trace, "digest algorithm "+meta.DigestAlg+" accepted")

	if rule.RequiredSigs > 0 {
		if kr == nil {
			d.Reason = ReasonInternal
			d.Detail = "rule requires signatures but no keyring configured"
			d.Trace = append(d.Trace, "denied: INTERNAL_ERROR — keyring not configured")
			return d
		}
		valid, sigFailures, err := kr.VerifySignatures(meta.Digest, meta.DigestAlg, req.Signatures)
		if err != nil {
			return mapSigError(d, err)
		}
		for _, f := range sigFailures {
			d.Trace = append(d.Trace, "signature check: "+string(f.Kind)+" — "+f.Detail)
		}
		d.Trace = append(d.Trace, fmt.Sprintf("signature valid=%d required=%d total=%d", valid, rule.RequiredSigs, len(req.Signatures)))
		if valid < rule.RequiredSigs {
			if len(req.Signatures) == 0 {
				d.Reason = ReasonSignatureMissing
				d.Detail = fmt.Sprintf("rule %s requires %d valid signature(s), image carries none", rule.ID, rule.RequiredSigs)
				d.Trace = append(d.Trace, "denied: SIGNATURE_MISSING — "+d.Detail)
				return d
			}
			if reason, detail := classifySigFailures(sigFailures); reason != ReasonAllow {
				d.Reason = reason
				d.Detail = detail
				d.Trace = append(d.Trace, "denied: "+string(reason)+" — "+detail)
				return d
			}
			d.Reason = ReasonSignatureVerifyFailed
			d.Detail = fmt.Sprintf("only %d of %d required valid signature(s)", valid, rule.RequiredSigs)
			d.Trace = append(d.Trace, "denied: SIGNATURE_VERIFY_FAILED — "+d.Detail)
			return d
		}
	}

	if len(rule.RequireAttest) > 0 {
		presentValid, attFailures, err := kr.VerifyAttestations(meta.Digest, meta.DigestAlg, rule.RequireAttest, req.Attestations)
		if err != nil {
			return mapSigError(d, err)
		}
		for _, f := range attFailures {
			d.Trace = append(d.Trace, "attestation check: "+string(f.Kind)+" — "+f.Detail)
		}
		d.Trace = append(d.Trace, fmt.Sprintf("attestations validTypes=%d requiredTypes=%d", presentValid, len(rule.RequireAttest)))
		if presentValid < len(rule.RequireAttest) {
			hasMissing, hasOther := false, false
			var otherDetail string
			for _, f := range attFailures {
				if f.Kind == sigverify.SigFailureMissing {
					hasMissing = true
				} else {
					hasOther = true
					otherDetail = f.Detail
				}
			}
			if hasMissing && !hasOther {
				d.Reason = ReasonAttestationMissing
				d.Detail = fmt.Sprintf("required attestation types missing: %s", strings.Join(rule.RequireAttest, ","))
				d.Trace = append(d.Trace, "denied: ATTESTATION_MISSING — "+d.Detail)
				return d
			}
			if hasMissing {
				d.Reason = ReasonAttestationMissing
				d.Detail = "one or more required attestation types are missing"
				d.Trace = append(d.Trace, "denied: ATTESTATION_MISSING — "+d.Detail)
				return d
			}
			d.Reason = ReasonAttestationVerifyFailed
			d.Detail = firstNonEmpty(otherDetail, "required attestations present but failed verification")
			d.Trace = append(d.Trace, "denied: ATTESTATION_VERIFY_FAILED — "+d.Detail)
			return d
		}
	}

	d.Allowed = true
	d.Trace = append(d.Trace, "ALLOW — all constraints of rule "+rule.ID+" satisfied")
	return d
}

func mapSigError(d *Decision, err error) *Decision {
	sf, ok := err.(*sigverify.SigFailure)
	if !ok {
		d.Reason = ReasonInternal
		d.Detail = err.Error()
		d.Trace = append(d.Trace, "denied: INTERNAL_ERROR — "+err.Error())
		return d
	}
	switch sf.Kind {
	case sigverify.SigFailureUnsupportedDigAlg:
		d.Reason = ReasonUnsupportedDigestAlgorithm
	default:
		d.Reason = ReasonSignatureVerifyFailed
	}
	d.Detail = sf.Detail
	d.Trace = append(d.Trace, "denied: "+string(d.Reason)+" — "+sf.Detail)
	return d
}

func classifySigFailures(fs []sigverify.SigFailure) (Reason, string) {
	// 可区分原因的优先级：吊销 > 未知密钥 > 算法不支持 > 摘要不匹配 > 验签失败。
	priority := []sigverify.SigFailureKind{
		sigverify.SigFailureKeyRevoked,
		sigverify.SigFailureKeyUnknown,
		sigverify.SigFailureUnsupportedDigAlg,
		sigverify.SigFailureDigestMismatch,
		sigverify.SigFailureVerify,
	}
	for _, kind := range priority {
		for _, f := range fs {
			if f.Kind == kind {
				switch kind {
				case sigverify.SigFailureKeyRevoked:
					return ReasonKeyRevoked, f.Detail
				case sigverify.SigFailureUnsupportedDigAlg:
					return ReasonUnsupportedDigestAlgorithm, f.Detail
				default:
					return ReasonSignatureVerifyFailed, f.Detail
				}
			}
		}
	}
	return ReasonAllow, ""
}

// Reload 重新加载外部策略文件：先完整加载并校验，成功后原子切换版本并清空
// 缓存；加载失败时保留旧策略继续服务（旧策略同样默认拒绝，不会静默放行）。
func (g *Guard) Reload(ctx context.Context) error {
	return g.reloadPolicyLocked(ctx)
}

func (g *Guard) reloadPolicyLocked(ctx context.Context) error {
	pol := policy.BuiltinPolicy()
	if g.cfg.PolicyPath != "" {
		ext, err := policy.LoadFile(ctx, g.cfg.PolicyPath)
		if err != nil {
			return err // 语法错误/字段缺失/冲突：拒绝装配，绝不忽略
		}
		merged, err := policy.Merge(pol, ext)
		if err != nil {
			return err
		}
		pol = merged
	}
	g.mu.Lock()
	g.evaluator = policy.NewEvaluator(pol)
	g.version = pol.Version
	g.mu.Unlock()
	g.cache.Clear() // 新版本：旧结论一律不得复用
	return nil
}

// PolicyVersion 返回当前策略版本标识。
func (g *Guard) PolicyVersion() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.version
}

// CacheLen 返回当前缓存条目数（主要用于测试）。
func (g *Guard) CacheLen() int { return g.cache.Len() }

// CacheClear 手动清空缓存（主要用于测试）。
func (g *Guard) CacheClear() { g.cache.Clear() }

// LookupMeta 使用已加载清单按引用补全元数据。
func (g *Guard) LookupMeta(ref string) (policy.ImageMeta, bool) {
	g.mu.RLock()
	m := g.manifest
	g.mu.RUnlock()
	if m == nil {
		return policy.ImageMeta{}, false
	}
	return m.Lookup(ref)
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func quote(s string) string { return "\"" + s + "\"" }

// requestFingerprint 计算“元数据 + 签名输入 + 证明输入”的内容指纹，
// 使同镜像但签名/证明不同的请求得到不同缓存键，避免错误复用结论。
func requestFingerprint(m policy.ImageMeta, req Request) string {
	h := sha256.New()
	fmt.Fprintf(h, "meta=%s|%s|%s|%s|%s|%s|%s|%v|%v\n",
		m.APIVersion, m.Reference, m.Repository, m.ImageName, m.Tag, m.Digest, m.DigestAlg,
		m.SignerNames, m.AttestTypes)
	// 签名按 keyId/算法/摘要/签名值规范化计入。
	for _, s := range req.Signatures {
		fmt.Fprintf(h, "sig=%s|%s|%s|%s|%x\n", s.KeyID, s.Algorithm, s.Digest, s.DigestAlg, s.Value)
	}
	for _, a := range req.Attestations {
		fmt.Fprintf(h, "att=%s|%s|%s|%s|%x|%x\n", a.Type, a.KeyID, a.Digest, a.DigestAlg, a.Payload, a.Value)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Reason 是可区分的拒绝原因码。
type Reason string

// 拒绝原因码：任何失败均默认拒绝，且调用方可以区分具体原因。
const (
	ReasonAllow                      Reason = ""
	ReasonPolicySyntax               Reason = "POLICY_SYNTAX_ERROR"
	ReasonPolicyMissingField         Reason = "POLICY_MISSING_FIELD"
	ReasonPolicyConflict             Reason = "POLICY_CONFLICT"
	ReasonMetaMissing                Reason = "IMAGE_META_MISSING"
	ReasonMetaVersionIncompatible    Reason = "META_VERSION_INCOMPATIBLE"
	ReasonNoMatchingRule             Reason = "NO_MATCHING_RULE"
	ReasonRulesDisagree              Reason = "RULES_DISAGREE"
	ReasonExplicitDeny               Reason = "EXPLICIT_DENY"
	ReasonSignatureVerifyFailed      Reason = "SIGNATURE_VERIFY_FAILED"
	ReasonSignatureMissing           Reason = "SIGNATURE_MISSING"
	ReasonAttestationMissing         Reason = "ATTESTATION_MISSING"
	ReasonAttestationVerifyFailed    Reason = "ATTESTATION_VERIFY_FAILED"
	ReasonUnsupportedDigestAlgorithm Reason = "UNSUPPORTED_DIGEST_ALGORITHM"
	ReasonKeyRevoked                 Reason = "SIGNING_KEY_REVOKED"
	ReasonInternal                   Reason = "INTERNAL_ERROR"
)
