package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
)

// LoadErrorType 用于区分不同的策略加载失败原因。
type LoadErrorType string

const (
	// LoadErrSyntax 策略文件 JSON 语法/取值非法。
	LoadErrSyntax LoadErrorType = "policy_syntax_error"
	// LoadErrMissing 关键字段缺失（version、规则名、动作等）。
	LoadErrMissing LoadErrorType = "policy_missing_field"
	// LoadErrConflict 不同来源的规则对同一镜像给出矛盾结论。
	LoadErrConflict LoadErrorType = "policy_conflict"
)

// LoadError 携带可区分的拒绝原因，绝不静默放行。
type LoadError struct {
	Type   LoadErrorType
	Source string
	Detail string
}

func (e *LoadError) Error() string {
	return fmt.Sprintf("%s: source=%s detail=%s", e.Type, e.Source, e.Detail)
}

// Bundle 是一次加载得到的不可变策略快照。
// Version 为声明版本号；Revision 为全部来源原始内容的指纹，
// 任何来源内容变化都会改变 Revision，确保旧缓存结论不会被复用。
type Bundle struct {
	Version  int
	Revision string
	Sources  []string
	Policy   *Policy
}

// Source 是策略来源（内置或外部文件）。
type Source interface {
	Name() string
	Load(ctx context.Context) (raw []byte, version int, pol *Policy, err error)
}

// ---------- 内置来源 ----------

// BuiltinSource 提供进程内置规则。
type BuiltinSource struct {
	Ver int
	Pol *Policy
}

func (s *BuiltinSource) Name() string { return "builtin" }

func (s *BuiltinSource) Load(_ context.Context) ([]byte, int, *Policy, error) {
	if s.Pol == nil {
		return nil, 0, nil, &LoadError{Type: LoadErrMissing, Source: s.Name(), Detail: "builtin policy is nil"}
	}
	raw, _ := json.Marshal(s.Pol)
	return raw, s.Ver, s.Pol, nil
}

// ---------- 文件来源 ----------

// FileSource 从外部 JSON 文件加载策略。
type FileSource struct {
	Path string
}

func (s *FileSource) Name() string { return "file:" + s.Path }

func (s *FileSource) Load(_ context.Context) ([]byte, int, *Policy, error) {
	raw, err := os.ReadFile(s.Path)
	if err != nil {
		return nil, 0, nil, &LoadError{Type: LoadErrSyntax, Source: s.Name(), Detail: "cannot read policy file: " + err.Error()}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var pol Policy
	if err := dec.Decode(&pol); err != nil {
		return nil, 0, nil, &LoadError{Type: LoadErrSyntax, Source: s.Name(), Detail: err.Error()}
	}
	if dec.More() {
		return nil, 0, nil, &LoadError{Type: LoadErrSyntax, Source: s.Name(), Detail: "unexpected trailing JSON value"}
	}
	pol.Source = s.Name()
	return raw, pol.Version, &pol, nil
}

// ---------- 单来源字段校验 ----------

// Validate 检查一份策略的必填字段与取值合法性。
func Validate(p *Policy, source string) error {
	if p.Version <= 0 {
		return &LoadError{Type: LoadErrMissing, Source: source, Detail: "policy.version must be > 0"}
	}
	if len(p.Rules) == 0 && p.DefaultRule == nil {
		return &LoadError{Type: LoadErrMissing, Source: source, Detail: "policy has neither rules nor defaultRule (fail-closed)"}
	}
	names := map[string]bool{}
	checkRule := func(r *Rule, where string) error {
		if strings.TrimSpace(r.Name) == "" {
			return &LoadError{Type: LoadErrMissing, Source: source, Detail: where + ": rule.name is required"}
		}
		if names[r.Name] {
			return &LoadError{Type: LoadErrConflict, Source: source, Detail: "duplicate rule name: " + r.Name}
		}
		names[r.Name] = true
		switch r.Action {
		case ActionAllow, ActionDeny:
		default:
			return &LoadError{Type: LoadErrSyntax, Source: source, Detail: fmt.Sprintf("%s: rule %q has invalid action %q", where, r.Name, r.Action)}
		}
		for _, req := range r.Requires {
			if req != "signature" && !strings.HasPrefix(req, "attestation:") {
				return &LoadError{Type: LoadErrSyntax, Source: source, Detail: fmt.Sprintf("rule %q: invalid require token %q", r.Name, req)}
			}
			if strings.HasPrefix(req, "attestation:") && strings.TrimPrefix(req, "attestation:") == "" {
				return &LoadError{Type: LoadErrSyntax, Source: source, Detail: fmt.Sprintf("rule %q: attestation require needs a type", r.Name)}
			}
		}
		for _, pat := range r.ImageRefs {
			if _, err := matchPattern(pat, "x"); err != nil {
				return &LoadError{Type: LoadErrSyntax, Source: source, Detail: fmt.Sprintf("rule %q: invalid imageRef pattern %q: %v", r.Name, pat, err)}
			}
		}
		return nil
	}
	for i := range p.Rules {
		if err := checkRule(&p.Rules[i], "rules["+itoa(i)+"]"); err != nil {
			return err
		}
	}
	if p.DefaultRule != nil {
		if p.DefaultRule.ImageRefs != nil {
			return &LoadError{Type: LoadErrSyntax, Source: source, Detail: "defaultRule must not declare imageRefs"}
		}
		if err := checkRule(p.DefaultRule, "defaultRule"); err != nil {
			return err
		}
	}
	return nil
}

// ---------- 合并加载 ----------

// LoadAll 加载并合并所有来源；任一来源出错或合并后存在冲突均返回错误（fail-closed）。
func LoadAll(ctx context.Context, sources []Source) (*Bundle, error) {
	if len(sources) == 0 {
		return nil, &LoadError{Type: LoadErrMissing, Source: "*", Detail: "no policy sources configured"}
	}
	merged := &Policy{}
	bundle := &Bundle{}
	maxVersion := 0
	h := sha256.New()

	for _, src := range sources {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		raw, ver, pol, err := src.Load(ctx)
		if err != nil {
			return nil, err
		}
		if err := Validate(pol, src.Name()); err != nil {
			return nil, err
		}
		h.Write([]byte(src.Name()))
		h.Write(raw)
		if ver > maxVersion {
			maxVersion = ver
		}
		bundle.Sources = append(bundle.Sources, src.Name())
		merged.Rules = append(merged.Rules, pol.Rules...)
		if pol.DefaultRule != nil {
			if merged.DefaultRule != nil {
				return nil, &LoadError{Type: LoadErrConflict, Source: src.Name(), Detail: "multiple defaultRule declared across sources"}
			}
			merged.DefaultRule = pol.DefaultRule
		}
	}
	merged.Version = maxVersion
	merged.Source = strings.Join(bundle.Sources, ",")

	if err := detectCrossSourceConflicts(merged); err != nil {
		return nil, err
	}

	// 稳定排序：优先级降序，名字升序，保证判定可解释、可复现。
	sort.SliceStable(merged.Rules, func(i, j int) bool {
		if merged.Rules[i].Priority != merged.Rules[j].Priority {
			return merged.Rules[i].Priority > merged.Rules[j].Priority
		}
		return merged.Rules[i].Name < merged.Rules[j].Name
	})

	bundle.Version = maxVersion
	bundle.Revision = hex.EncodeToString(h.Sum(nil))
	bundle.Policy = merged
	return bundle, nil
}

// detectCrossSourceConflicts 检查同优先级、动作相反且镜像范围有交集的规则。
func detectCrossSourceConflicts(p *Policy) error {
	for i := 0; i < len(p.Rules); i++ {
		for j := i + 1; j < len(p.Rules); j++ {
			a, b := p.Rules[i], p.Rules[j]
			if a.Priority != b.Priority || a.Action == b.Action {
				continue
			}
			if patternsOverlap(a.ImageRefs, b.ImageRefs) {
				return &LoadError{
					Type:   LoadErrConflict,
					Source: a.Source + " vs " + b.Source,
					Detail: fmt.Sprintf("rules %q (%s) and %q (%s) have equal priority %d and opposite actions over overlapping images",
						a.Name, a.Action, b.Name, b.Action, a.Priority),
				}
			}
		}
	}
	return nil
}

// patternsOverlap 判断两组镜像模式是否可能命中同一镜像。
// 空模式集合表示匹配全部镜像；这里做保守判定：任一组为空或存在相同模式即视为重叠。
func patternsOverlap(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return true
	}
	set := map[string]struct{}{}
	for _, p := range a {
		set[p] = struct{}{}
	}
	for _, p := range b {
		if _, ok := set[p]; ok {
			return true
		}
	}
	return false
}

func matchPattern(pattern, name string) (matched bool, err error) {
	return path.Match(pattern, name)
}

func itoa(i int) string { return fmt.Sprintf("%d", i) }
