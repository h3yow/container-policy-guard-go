package guard

import "sync"

// cacheEntry 是一条缓存结论。只允许缓存 Allowed 的结论：
// 任何失败（拒绝）结论都不得写入，避免瞬时故障被长期固化。
type cacheEntry struct {
	policyVersion int
	policyRev     string
	decision      *Decision
}

// resultCache 以 (policyVersion, revision, imageID) 为键。
// 策略更新（版本号或内容指纹变化）后旧结论自然查不到，
// UpdatePolicy 时还会主动清空整个存储，双保险。
type resultCache struct {
	mu    sync.RWMutex
	store map[string]cacheEntry
}

func newResultCache() *resultCache { return &resultCache{store: map[string]cacheEntry{}} }

func cacheKey(version int, rev, imageID string) string {
	// 版本号 + 内容指纹 + 镜像标识三者共同决定缓存条目。
	return itoa(version) + "|" + rev + "|" + imageID
}

func (c *resultCache) get(version int, rev, imageID string) (*Decision, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.store[cacheKey(version, rev, imageID)]
	if !ok {
		return nil, false
	}
	if e.policyVersion != version || e.policyRev != rev {
		return nil, false
	}
	// 返回副本，避免调用方修改缓存内对象。
	d := e.decision
	cp := *d
	return &cp, true
}

func (c *resultCache) put(version int, rev string, d *Decision) {
	if d == nil || !d.Allowed {
		return // 失败结论绝不缓存
	}
	cp := *d
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store[cacheKey(version, rev, d.ImageID)] = cacheEntry{
		policyVersion: version,
		policyRev:     rev,
		decision:      &cp,
	}
}

// invalidate 清空全部缓存结论（策略更新时调用）。
func (c *resultCache) invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store = map[string]cacheEntry{}
}

// len 仅供测试观察缓存状态。
func (c *resultCache) len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.store)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}
