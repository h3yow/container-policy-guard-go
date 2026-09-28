// Package resultcache 提供随策略版本与镜像标识失效的并发安全结果缓存。
package resultcache

import "sync"

// Key 是缓存键：策略版本 + 镜像标识 + 元数据摘要。
// 三个维度任一变化都会得到不同的键，从而保证：
//   - 策略更新（新版本）后不会复用旧结论；
//   - 不同镜像的结论互不串用；
//   - 同引用但清单内容变化（摘要变化）后不会复用旧结论。
type Key struct {
	PolicyVersion string
	ImageRef      string
	MetaDigest    string
}

type entry[V any] struct {
	value V
}

// Cache 是泛型并发安全缓存。写入策略由调用方保证：
// 失败结论必须带可区分原因原样缓存，绝不允许被改写成通过。
type Cache[V any] struct {
	mu sync.RWMutex
	m  map[Key]entry[V]
}

// New 创建空缓存。
func New[V any]() *Cache[V] {
	return &Cache[V]{m: make(map[Key]entry[V])}
}

// Get 读取缓存。
func (c *Cache[V]) Get(k Key) (V, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.m[k]
	return e.value, ok
}

// Set 写入缓存。
func (c *Cache[V]) Set(k Key, v V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[k] = entry[V]{value: v}
}

// InvalidatePolicy 使某个策略版本的全部结论失效。
// 典型用法：策略重载后用旧版本号清理，或直接 Clear。
func (c *Cache[V]) InvalidatePolicy(version string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.m {
		if k.PolicyVersion == version {
			delete(c.m, k)
		}
	}
}

// InvalidateImage 使某个镜像标识的全部结论失效（清单变更时使用）。
func (c *Cache[V]) InvalidateImage(imageRef string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.m {
		if k.ImageRef == imageRef {
			delete(c.m, k)
		}
	}
}

// Len 返回缓存条目数（主要用于测试）。
func (c *Cache[V]) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.m)
}

// Clear 清空全部缓存。策略版本切换时调用，确保旧结论不复用。
func (c *Cache[V]) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m = make(map[Key]entry[V])
}
