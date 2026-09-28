package signature

import (
	"fmt"
	"time"
)

// KeyState 表示公钥状态。
type KeyState string

const (
	// KeyActive 当前签名公钥。
	KeyActive KeyState = "active"
	// KeyRotated 已轮换的历史公钥，在有效期内仍可验证旧镜像。
	KeyRotated KeyState = "rotated"
	// KeyRevoked 已吊销公钥，其签名一律拒绝。
	KeyRevoked KeyState = "revoked"
)

// PublicKey 是本地模拟的公钥条目。
type PublicKey struct {
	ID        string
	State     KeyState
	Alg       string // 签名算法，如 ed25519
	RotatedBy string // 轮换后的新公钥 ID（仅 rotated 状态有值）
	NotBefore time.Time
	NotAfter  time.Time
}

// Keyring 维护公钥及其轮换/吊销状态。
type Keyring struct {
	keys map[string]*PublicKey
}

// NewKeyring 创建空公钥环。
func NewKeyring() *Keyring { return &Keyring{keys: map[string]*PublicKey{}} }

// Add 加入公钥；重复 ID 直接覆盖以便测试中模拟轮换。
func (k *Keyring) Add(key PublicKey) {
	cp := key
	k.keys[key.ID] = &cp
}

// Lookup 查询公钥。
func (k *Keyring) Lookup(id string) (*PublicKey, bool) {
	key, ok := k.keys[id]
	return key, ok
}

// ActiveChain 返回从 id 出发沿轮换链收集到的、当前可用于验签的公钥：
//   - 命中 revoked：立即停止，调用方可据此给出“已吊销”的可区分原因；
//   - rotated 且在有效期内：继续沿 RotatedBy 向新键追溯（旧镜像兼容）；
//   - active 且在有效期内：链终点。
func (k *Keyring) ActiveChain(id string) ([]*PublicKey, error) {
	var chain []*PublicKey
	visited := map[string]bool{}
	cur := id
	now := time.Now()
	for cur != "" {
		if visited[cur] {
			return nil, fmt.Errorf("rotation cycle detected at key %s", cur)
		}
		visited[cur] = true
		key, ok := k.keys[cur]
		if !ok {
			return chain, nil // 链上未知键交由调用方区分处理
		}
		if key.State == KeyRevoked {
			return chain, &KeyRevokedError{KeyID: cur}
		}
		if !key.NotBefore.IsZero() && now.Before(key.NotBefore) {
			cur = key.RotatedBy
			continue
		}
		if !key.NotAfter.IsZero() && now.After(key.NotAfter) {
			cur = key.RotatedBy
			continue
		}
		chain = append(chain, key)
		if key.State == KeyActive || key.RotatedBy == "" {
			break
		}
		cur = key.RotatedBy
	}
	return chain, nil
}

// KeyRevokedError 表示轮换链上遇到已吊销公钥。
type KeyRevokedError struct{ KeyID string }

func (e *KeyRevokedError) Error() string { return "signing key revoked: " + e.KeyID }
