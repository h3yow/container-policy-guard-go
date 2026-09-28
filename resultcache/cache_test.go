package resultcache

import "testing"

func TestCacheSetGet(t *testing.T) {
	c := New[string]()
	k := Key{PolicyVersion: "v1", ImageRef: "img:1", MetaDigest: "abc"}
	if _, ok := c.Get(k); ok {
		t.Fatalf("empty cache hit")
	}
	c.Set(k, "allow")
	if v, ok := c.Get(k); !ok || v != "allow" {
		t.Fatalf("get = %q,%v", v, ok)
	}
}

func TestCachePolicyVersionIsolation(t *testing.T) {
	c := New[int]()
	k1 := Key{PolicyVersion: "v1", ImageRef: "img:1", MetaDigest: "h"}
	c.Set(k1, 1)
	k2 := Key{PolicyVersion: "v2", ImageRef: "img:1", MetaDigest: "h"}
	if _, ok := c.Get(k2); ok {
		t.Fatalf("new policy version must not see old decision")
	}
	c.Set(k2, 2)
	if c.Len() != 2 {
		t.Fatalf("len=%d", c.Len())
	}
	c.InvalidatePolicy("v1")
	if _, ok := c.Get(k1); ok {
		t.Fatalf("v1 decision should be invalidated")
	}
	if v, ok := c.Get(k2); !ok || v != 2 {
		t.Fatalf("v2 decision should survive")
	}
}

func TestCacheImageInvalidation(t *testing.T) {
	c := New[int]()
	a := Key{PolicyVersion: "v1", ImageRef: "img-a", MetaDigest: "h1"}
	b := Key{PolicyVersion: "v1", ImageRef: "img-b", MetaDigest: "h2"}
	c.Set(a, 1)
	c.Set(b, 2)
	c.InvalidateImage("img-a")
	if _, ok := c.Get(a); ok {
		t.Fatalf("img-a should be invalidated")
	}
	if _, ok := c.Get(b); !ok {
		t.Fatalf("img-b should survive")
	}
	c.Clear()
	if c.Len() != 0 {
		t.Fatalf("clear failed")
	}
}
