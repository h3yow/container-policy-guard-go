// Package policy 负责内置规则与外部策略文件的加载、校验与判定。
package policy

import (
	"context"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/h3yow/container-policy-guard-go/internal/yamlish"
)

// Effect 是单条规则命中后的处置动作。
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// Source 标识规则来源。
type Source string

const (
	SourceBuiltin Source = "builtin"
	SourceFile    Source = "file"
)

// 加载错误类别，与 guard 层拒绝原因一一对应。
const (
	LoadKindSyntax       = "syntax"
	LoadKindMissingField = "missing_field"
	LoadKindConflict     = "conflict"
)

// Rule 是准入规则的统一表示，内置规则与文件规则共用该结构。
type Rule struct {
	ID             string            `json:"id" yaml:"id"`
	Source         Source            `json:"source,omitempty" yaml:"source,omitempty"`
	Repository     string            `json:"repository,omitempty" yaml:"repository,omitempty"`
	ImageName      string            `json:"imageName,omitempty" yaml:"imageName,omitempty"`
	TagPattern     string            `json:"tagPattern,omitempty" yaml:"tagPattern,omitempty"`
	RequiredSigs   int               `json:"requiredSignatures,omitempty" yaml:"requiredSignatures,omitempty"`
	RequireAttest  []string          `json:"requireAttestations,omitempty" yaml:"requireAttestations,omitempty"`
	AllowedDigests []string          `json:"allowedDigestAlgorithms,omitempty" yaml:"allowedDigestAlgorithms,omitempty"`
	Effect         Effect            `json:"effect" yaml:"effect"`
	Priority       int               `json:"priority,omitempty" yaml:"priority,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// Policy 是加载并校验后的完整策略集。
type Policy struct {
	Version string `json:"version" yaml:"version"`
	Rules   []Rule `json:"rules" yaml:"rules"`
}

// Match 记录一条规则的命中信息，用于可解释结论。
type Match struct {
	RuleID string
	Source Source
	Effect Effect
	Detail string
}

// Result 是策略层判定结果。
type Result struct {
	Matches []Match
	// Winner 是最高优先级且通过仲裁的生效规则；无生效规则时为 nil。
	Winner *Rule
	Allow  bool
}

// LoadError 区分策略加载阶段的错误类别。
type LoadError struct {
	Kind string
	File string
	Msg  string
}

func (e *LoadError) Error() string {
	if e == nil {
		return ""
	}
	return e.Kind + ": " + e.Msg + " (" + e.File + ")"
}

// LoadFile 从 YAML 或 JSON 文件加载外部策略，并做语法与字段校验。
// 语法错误、关键字段缺失、同文件内规则冲突都会显式报错，绝不忽略。
func LoadFile(ctx context.Context, path string) (*Policy, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &LoadError{Kind: LoadKindSyntax, File: path, Msg: "cannot read policy file: " + err.Error()}
	}
	var p Policy
	if err := yamlish.Unmarshal(data, &p); err != nil {
		return nil, &LoadError{Kind: LoadKindSyntax, File: path, Msg: err.Error()}
	}
	if err := validatePolicy(&p, path); err != nil {
		return nil, err
	}
	for i := range p.Rules {
		p.Rules[i].Source = SourceFile
	}
	return &p, nil
}

func validatePolicy(p *Policy, file string) error {
	if strings.TrimSpace(p.Version) == "" {
		return &LoadError{Kind: LoadKindMissingField, File: file, Msg: "policy.version is required and must be non-empty"}
	}
	if len(p.Rules) == 0 {
		return &LoadError{Kind: LoadKindMissingField, File: file, Msg: "policy.rules must contain at least one rule"}
	}
	seen := map[string]int{}
	for i := range p.Rules {
		r := &p.Rules[i]
		if strings.TrimSpace(r.ID) == "" {
			return &LoadError{Kind: LoadKindMissingField, File: file, Msg: "rules[].id is required"}
		}
		if prev, dup := seen[r.ID]; dup {
			return &LoadError{Kind: LoadKindConflict, File: file,
				Msg: "duplicate rule id " + r.ID + " at rules[" + itoa(prev) + "] and rules[" + itoa(i) + "]"}
		}
		seen[r.ID] = i
		if r.Effect != EffectAllow && r.Effect != EffectDeny {
			return &LoadError{Kind: LoadKindMissingField, File: file,
				Msg: "rule " + r.ID + ": effect must be 'allow' or 'deny', got " + quote(string(r.Effect))}
		}
		if r.Repository == "" && r.ImageName == "" && r.TagPattern == "" {
			return &LoadError{Kind: LoadKindMissingField, File: file,
				Msg: "rule " + r.ID + ": at least one matcher (repository/imageName/tagPattern) is required"}
		}
		if r.TagPattern != "" {
			if _, err := path.Match(r.TagPattern, "probe"); err != nil {
				return &LoadError{Kind: LoadKindSyntax, File: file,
					Msg: "rule " + r.ID + ": invalid tagPattern: " + err.Error()}
			}
		}
		if r.Repository != "" {
			if _, err := path.Match(r.Repository, "probe"); err != nil {
				return &LoadError{Kind: LoadKindSyntax, File: file,
					Msg: "rule " + r.ID + ": invalid repository glob: " + err.Error()}
			}
		}
		for _, alg := range r.AllowedDigests {
			if !knownDigestAlg(alg) {
				return &LoadError{Kind: LoadKindSyntax, File: file,
					Msg: "rule " + r.ID + ": unsupported digest algorithm " + alg}
			}
		}
		if r.RequiredSigs < 0 {
			return &LoadError{Kind: LoadKindMissingField, File: file,
				Msg: "rule " + r.ID + ": requiredSignatures must be >= 0"}
		}
	}
	return nil
}

// BuiltinPolicy 返回内置默认策略：
//   - builtin/signed-library：官方 docker.io/library 仓库镜像需 1 个有效
//     签名，且摘要算法限定为 sha256/sha384/sha512。
//
// 内置策略不放置兜底 deny 规则：默认拒绝由评估器语义保证——没有任何规则
// 允许镜像时结论即为拒绝（NO_MATCHING_RULE）。策略文件可以显式添加 deny
// 规则，命中时给出 EXPLICIT_DENY 原因。
func BuiltinPolicy() *Policy {
	return &Policy{
		Version: "builtin-v1",
		Rules: []Rule{
			{
				ID:             "builtin/signed-library",
				Source:         SourceBuiltin,
				Repository:     "docker.io/library/*",
				RequiredSigs:   1,
				AllowedDigests: []string{"sha256", "sha384", "sha512"},
				Effect:         EffectAllow,
				Priority:       10,
			},
		},
	}
}

// Merge 合并内置策略与文件策略。
// 外部规则与内置规则同 ID 时视为显式覆盖；外部文件内部的重复 ID 已在
// LoadFile 阶段按冲突拒绝。合并后的版本以外部策略版本为准（内置规则固定）。
func Merge(builtin *Policy, external *Policy) (*Policy, error) {
	if builtin == nil {
		builtin = &Policy{Version: "builtin-v1"}
	}
	out := &Policy{Version: builtin.Version}
	index := map[string]int{}
	add := func(r Rule) {
		if pos, ok := index[r.ID]; ok {
			out.Rules[pos] = r
			return
		}
		index[r.ID] = len(out.Rules)
		out.Rules = append(out.Rules, r)
	}
	for _, r := range builtin.Rules {
		add(r)
	}
	if external != nil {
		out.Version = external.Version
		for _, r := range external.Rules {
			add(r)
		}
	}
	return out, nil
}

// Evaluator 对镜像元数据执行策略匹配与冲突仲裁。
type Evaluator struct {
	pol *Policy
}

// NewEvaluator 构造策略评估器。
func NewEvaluator(p *Policy) *Evaluator {
	return &Evaluator{pol: p}
}

// Version 返回策略版本。
func (e *Evaluator) Version() string {
	if e == nil || e.pol == nil {
		return ""
	}
	return e.pol.Version
}

// Evaluate 对镜像元数据进行策略匹配：
//   - 无任何规则命中（连兜底规则都没有）→ Result.Winner == nil，调用方默认拒绝；
//   - 最高优先级的命中规则同时包含 allow 与 deny → 冲突，Result.Winner == nil；
//   - 否则最高优先级规则为唯一生效规则。
func (e *Evaluator) Evaluate(meta ImageMeta) *Result {
	res := &Result{}
	type scored struct {
		rule Rule
		why  string
	}
	var hit []scored
	for _, r := range e.pol.Rules {
		if why, ok := matchRule(r, meta); ok {
			hit = append(hit, scored{r, why})
		}
	}
	if len(hit) == 0 {
		return res
	}
	sort.SliceStable(hit, func(i, j int) bool { return hit[i].rule.Priority > hit[j].rule.Priority })
	top := hit[0].rule.Priority
	var allow, deny []scored
	for _, s := range hit {
		res.Matches = append(res.Matches, Match{
			RuleID: s.rule.ID, Source: s.rule.Source, Effect: s.rule.Effect, Detail: s.why,
		})
		if s.rule.Priority != top {
			continue
		}
		switch s.rule.Effect {
		case EffectAllow:
			allow = append(allow, s)
		case EffectDeny:
			deny = append(deny, s)
		}
	}
	if len(allow) > 0 && len(deny) > 0 {
		// 同优先级规则互相矛盾：不做猜测，交由调用方按冲突拒绝。
		return res
	}
	if len(allow) > 0 {
		r := allow[0].rule
		res.Winner = &r
		res.Allow = true
	} else {
		r := deny[0].rule
		res.Winner = &r
	}
	return res
}

func matchRule(r Rule, meta ImageMeta) (string, bool) {
	var why []string
	if r.Repository != "" {
		ok, err := path.Match(r.Repository, meta.Repository)
		if err != nil || !ok {
			return "", false
		}
		why = append(why, "repository "+meta.Repository+" matches "+r.Repository)
	}
	if r.ImageName != "" {
		if r.ImageName != meta.ImageName {
			return "", false
		}
		why = append(why, "imageName == "+r.ImageName)
	}
	if r.TagPattern != "" {
		ok, err := path.Match(r.TagPattern, meta.Tag)
		if err != nil || !ok {
			return "", false
		}
		why = append(why, "tag "+meta.Tag+" matches "+r.TagPattern)
	}
	return strings.Join(why, "; "), true
}

func knownDigestAlg(alg string) bool {
	switch alg {
	case "sha256", "sha384", "sha512":
		return true
	default:
		return false
	}
}

func quote(s string) string { return "\"" + s + "\"" }

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
