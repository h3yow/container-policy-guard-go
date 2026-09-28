package policy

import "path"

// Action 表示规则对一个镜像的处置。
type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
)

// Policy 是一份准入策略：内置规则与外部规则的统一表示。
//
// 合并模型：所有来源的规则进入同一个扁平集合，按 Priority 判定
// （数字越大优先级越高）；同一镜像若有相同优先级且处置相反的规则，
// 视为策略冲突，fail-closed（拒绝）。
type Policy struct {
	Version int `json:"version"`
	// Source 仅用于日志/错误信息，标注该快照来自哪些来源。
	Source      string `json:"-"`
	DefaultRule *Rule  `json:"defaultRule,omitempty"`
	Rules       []Rule `json:"rules"`
}

// Rule 描述一条来源规则。
type Rule struct {
	Name string `json:"name"`
	// Source 为 builtin 或 file，仅用于可解释性输出。
	Source string `json:"source"`
	// Priority 数字越大优先级越高。
	Priority int    `json:"priority"`
	Action   Action `json:"action"`
	// ImageRefs 支持 path.Match 通配（如 registry.local/app/*:v1），
	// 为空时匹配所有镜像。
	ImageRefs []string `json:"imageRefs,omitempty"`
	// Requires 为该规则放行前必须满足的校验：signature / attestation:<type>
	Requires []string `json:"requires,omitempty"`
	// Reason 是显式拒绝时返回给调用方的人类可读原因。
	Reason string `json:"reason,omitempty"`
}

// Matches 判断规则是否适用于给定镜像标识（repository:tag）。
func (r *Rule) Matches(imageID string) bool {
	if len(r.ImageRefs) == 0 {
		return true
	}
	for _, pattern := range r.ImageRefs {
		matched, err := path.Match(pattern, imageID)
		if err != nil {
			// 非法模式不匹配任何镜像，而不是静默放行。
			continue
		}
		if matched {
			return true
		}
	}
	return false
}

// MatchedRules 返回策略中适用于该镜像的全部规则（未排序）。
func (p *Policy) MatchedRules(imageID string) []Rule {
	var out []Rule
	for _, r := range p.Rules {
		if r.Matches(imageID) {
			out = append(out, r)
		}
	}
	return out
}
