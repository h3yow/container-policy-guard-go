package guard

import (
	"context"
	"log"
	"strings"
	"sync"

	"github.com/h3yow/container-policy-guard-go/manifest"
	"github.com/h3yow/container-policy-guard-go/policy"
	"github.com/h3yow/container-policy-guard-go/signature"
)

// Evaluator 并发安全地执行准入评估并缓存结论。
type Evaluator struct {
	mu        sync.RWMutex
	bundle    *policy.Bundle
	manifests manifest.Source
	verifier  *signature.Verifier
	cache     *resultCache
	flights   flightGroup
	logger    *log.Logger
}

// NewEvaluator 创建评估器；bundle 为 nil 时进入 fail-closed 状态，
// 任何评估都返回 policy_unavailable，而不是放行。
func NewEvaluator(bundle *policy.Bundle, ms manifest.Source, v *signature.Verifier) *Evaluator {
	return &Evaluator{
		bundle:    bundle,
		manifests: ms,
		verifier:  v,
		cache:     newResultCache(),
		logger:    log.Default(),
	}
}

// WithLogger 注入日志器（测试中可捕获日志）。
func (e *Evaluator) WithLogger(l *log.Logger) *Evaluator {
	e.logger = l
	return e
}

// UpdatePolicy 原子替换策略快照并使全部旧结论失效。
func (e *Evaluator) UpdatePolicy(bundle *policy.Bundle) {
	e.mu.Lock()
	e.bundle = bundle
	e.cache.invalidate()
	e.mu.Unlock()
	e.logger.Printf("[guard] policy updated -> version=%d revision=%.12s cache=invalidated", safeVersion(bundle), safeRev(bundle))
}

// Evaluate 评估单个镜像；同镜像的并发评估共享一次计算（singleflight），
// 保证并发请求下结论一致。
func (e *Evaluator) Evaluate(ctx context.Context, imageID string) *Decision {
	e.mu.RLock()
	bundle := e.bundle
	ms := e.manifests
	v := e.verifier
	cache := e.cache
	e.mu.RUnlock()

	if bundle == nil || bundle.Policy == nil {
		d := &Decision{Allowed: false, ImageID: imageID, Reason: ReasonPolicyUnavailable, Detail: "no policy loaded (fail-closed)"}
		e.logger.Printf("[guard] evaluate image=%q decision=deny reason=%s detail=%q", imageID, d.Reason, d.Detail)
		return d
	}

	// 1) 先读缓存（只可能命中通过结论）。
	if d, ok := cache.get(bundle.Version, bundle.Revision, imageID); ok {
		e.logger.Printf("[guard] evaluate image=%q cache=hit decision=allow rule=%q", imageID, d.MatchedRule)
		return d
	}

	// 2) 同键并发去重。
	d := e.flights.do("eval:"+imageID, func() *Decision {
		// double-check：可能在等待锁期间已被别的 goroutine 算完。
		if d2, ok := cache.get(bundle.Version, bundle.Revision, imageID); ok {
			return d2
		}
		return e.evaluate(ctx, bundle, ms, v, imageID)
	})

	if d.Allowed {
		cache.put(bundle.Version, bundle.Revision, d)
	}
	e.logger.Printf("[guard] evaluate image=%q decision=%s reason=%q rule=%q basis=%s",
		imageID, allowWord(d.Allowed), d.Reason, d.MatchedRule, d.Detail)
	return d
}

func (e *Evaluator) evaluate(
	ctx context.Context,
	bundle *policy.Bundle,
	ms manifest.Source,
	v *signature.Verifier,
	imageID string,
) *Decision {
	pol := bundle.Policy

	// 1) 选择规则：取最高优先级（不依赖规则已排序）；
	// 同优先级存在相反动作 -> 冲突，拒绝。
	rules := pol.MatchedRules(imageID)
	var chosen *policy.Rule
	if len(rules) > 0 {
		top := rules[0].Priority
		for _, r := range rules[1:] {
			if r.Priority > top {
				top = r.Priority
			}
		}
		var sameTier []policy.Rule
		for _, r := range rules {
			if r.Priority == top {
				sameTier = append(sameTier, r)
			}
		}
		allow, deny := false, false
		for _, r := range sameTier {
			switch r.Action {
			case policy.ActionAllow:
				allow = true
			case policy.ActionDeny:
				deny = true
			}
		}
		if allow && deny {
			return deny0(imageID, bundle, "", ReasonPolicyConflict,
				"equal-priority rules disagree on image: "+ruleNames(sameTier))
		}
		chosen = &sameTier[0]
	} else if pol.DefaultRule != nil {
		chosen = pol.DefaultRule
	} else {
		return deny0(imageID, bundle, "", ReasonNoMatchingRule,
			"no rule matches and no defaultRule defined (default-deny)")
	}

	// 2) 显式拒绝规则：不做后续校验，直接拒绝（可解释）。
	if chosen.Action == policy.ActionDeny {
		detail := "explicit deny by rule " + chosen.Name
		if chosen.Reason != "" {
			detail += ": " + chosen.Reason
		}
		return deny0(imageID, bundle, chosen.Name, ReasonExplicitDeny, detail)
	}

	// 3) 加载并校验本地清单（字段缺失/版本不兼容/不存在分别处理）。
	m, err := ms.Get(ctx, imageID)
	if err != nil {
		return deny0(imageID, bundle, chosen.Name, mapManifestErr(err), err.Error())
	}

	// 4) 执行规则要求的签名与证明校验。
	for _, req := range chosen.Requires {
		switch {
		case req == "signature":
			if serr := v.Verify(ctx, m); serr != nil {
				return deny0(imageID, bundle, chosen.Name, mapSigFailure(serr), serr.Error())
			}
		case strings.HasPrefix(req, "attestation:"):
			attType := strings.TrimPrefix(req, "attestation:")
			if aerr := v.VerifyAttestation(ctx, m, attType); aerr != nil {
				return deny0(imageID, bundle, chosen.Name, mapAttFailure(aerr), aerr.Error())
			}
		}
	}

	return &Decision{
		Allowed:       true,
		ImageID:       imageID,
		Reason:        ReasonAllow,
		Detail:        "allowed by rule " + chosen.Name + " with all " + itoa(len(chosen.Requires)) + " requirement(s) satisfied",
		PolicyVersion: bundle.Version,
		MatchedRule:   chosen.Name,
	}
}

func mapManifestErr(err error) Reason {
	if le, ok := err.(*manifest.LoadError); ok {
		switch le.Type {
		case manifest.ManifestErrNotFound:
			return ReasonManifestNotFound
		case manifest.ManifestErrMissingField:
			return ReasonManifestMissingField
		case manifest.ManifestErrVersionIncompat:
			return ReasonManifestVersionIncompat
		}
	}
	return ReasonManifestNotFound
}

func mapSigFailure(err error) Reason {
	if f, ok := err.(*signature.Failure); ok {
		switch f.Reason {
		case signature.FailNoSignature:
			return ReasonSignatureMissing
		case signature.FailVerification:
			return ReasonSignatureVerifyFailed
		case signature.FailKeyRevoked:
			return ReasonSigningKeyRevoked
		case signature.FailKeyUnknown:
			return ReasonSigningKeyUnknown
		case signature.FailDigestAlgMismatch:
			return ReasonDigestAlgorithmMismatch
		case signature.FailDigestAlgUnsupported:
			return ReasonDigestAlgorithmUnsupport
		}
	}
	return ReasonSignatureVerifyFailed
}

func mapAttFailure(err error) Reason {
	if f, ok := err.(*signature.Failure); ok {
		switch f.Reason {
		case signature.FailAttestationMissing:
			return ReasonAttestationMissing
		case signature.FailAttestationInvalid:
			return ReasonAttestationInvalid
		}
	}
	return ReasonAttestationInvalid
}

func deny0(imageID string, b *policy.Bundle, rule string, reason Reason, detail string) *Decision {
	return &Decision{Allowed: false, ImageID: imageID, Reason: reason, Detail: detail, PolicyVersion: b.Version, MatchedRule: rule}
}

func ruleNames(rs []policy.Rule) string {
	names := make([]string, 0, len(rs))
	for _, r := range rs {
		names = append(names, r.Name+"("+string(r.Action)+")")
	}
	return strings.Join(names, ",")
}

func safeVersion(b *policy.Bundle) int {
	if b == nil {
		return 0
	}
	return b.Version
}

func safeRev(b *policy.Bundle) string {
	if b == nil {
		return "-"
	}
	return b.Revision
}

func allowWord(ok bool) string {
	if ok {
		return "allow"
	}
	return "deny"
}

// ---------- 极简 singleflight ----------

type flightCall struct {
	wg sync.WaitGroup
	d  *Decision
}

type flightGroup struct {
	mu sync.Mutex
	m  map[string]*flightCall
}

func (g *flightGroup) do(key string, fn func() *Decision) *Decision {
	g.mu.Lock()
	if g.m == nil {
		g.m = map[string]*flightCall{}
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.d
	}
	c := &flightCall{}
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	c.d = fn()
	c.wg.Done()

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()
	return c.d
}
