package guard

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"sync"
	"testing"

	"github.com/h3yow/container-policy-guard-go/manifest"
	"github.com/h3yow/container-policy-guard-go/policy"
	"github.com/h3yow/container-policy-guard-go/signature"
)

const D256 = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func goodManifest(id string) *manifest.Manifest {
	return &manifest.Manifest{
		APIVersion: "v1", ImageID: id,
		Repository: "repo/img", Tag: "v1", Digest: D256, DigestAlg: "sha256",
		Signatures: []manifest.Signature{{KeyID: "k1", Alg: "ed25519", DigestAlg: "sha256",
			Value: signature.ComposeSignatureValue("k1", "ed25519", "sha256", D256)}},
		Attestations: []manifest.Attestation{{Type: "sbom", KeyID: "k1",
			Value: signature.ComposeAttestationValue("sbom", "k1", "sha256", D256)}},
	}
}

func keyring() *signature.Keyring {
	kr := signature.NewKeyring()
	kr.Add(signature.PublicKey{ID: "k1", State: signature.KeyActive, Alg: "ed25519"})
	return kr
}

func bundleV1() *policy.Bundle {
	pol := &policy.Policy{Version: 1, Rules: []policy.Rule{
		{Name: "deny-all", Source: "builtin", Priority: 0, Action: policy.ActionDeny},
		{Name: "allow-signed", Source: "builtin", Priority: 10, Action: policy.ActionAllow,
			Requires: []string{"signature", "attestation:sbom"}},
	}}
	return &policy.Bundle{Version: 1, Revision: "rev-v1", Policy: pol}
}

func bundleV2() *policy.Bundle {
	pol := &policy.Policy{Version: 2, Rules: []policy.Rule{
		{Name: "allow-anything", Source: "builtin", Priority: 10, Action: policy.ActionAllow},
	}}
	return &policy.Bundle{Version: 2, Revision: "rev-v2", Policy: pol}
}

func newLoggedEvaluator(t *testing.T, b *policy.Bundle, ms manifest.Source) (*Evaluator, *bytes.Buffer) {
	t.Helper()
	buf := &bytes.Buffer{}
	ev := NewEvaluator(b, ms, signature.NewVerifier(keyring())).
		WithLogger(log.New(buf, "", log.LstdFlags))
	return ev, buf
}

func TestConcurrentEvaluationConsistent(t *testing.T) {
	id := "repo/img:v1"
	ms := &manifest.StaticSource{Items: map[string]*manifest.Manifest{id: goodManifest(id)}}
	ev, _ := newLoggedEvaluator(t, bundleV1(), ms)

	const n = 64
	var wg sync.WaitGroup
	results := make([]*Decision, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			results[idx] = ev.Evaluate(context.Background(), id)
		}(i)
	}
	close(start)
	wg.Wait()

	for i, d := range results {
		t.Logf("goroutine=%d input=%s decision=%+v", i, id, d)
		if !d.Allowed || d.MatchedRule != "allow-signed" || d.Reason != ReasonAllow {
			t.Fatalf("inconsistent result at %d: %+v", i, d)
		}
	}
	if ev.cache.len() != 1 {
		t.Fatalf("want exactly 1 cached allow entry, got %d", ev.cache.len())
	}
}

func TestCacheInvalidatedOnPolicyUpdate(t *testing.T) {
	id := "repo/img:v1"
	ms := &manifest.StaticSource{Items: map[string]*manifest.Manifest{id: goodManifest(id)}}
	ev, buf := newLoggedEvaluator(t, bundleV1(), ms)

	d1 := ev.Evaluate(context.Background(), id)
	if !d1.Allowed || d1.PolicyVersion != 1 {
		t.Fatalf("v1: %+v", d1)
	}
	if !bytes.Contains(buf.Bytes(), []byte("cache=hit")) {
		// 第二次评估应命中缓存
		ev.Evaluate(context.Background(), id)
	}
	if ev.cache.len() != 1 {
		t.Fatalf("pre-update cache len = %d", ev.cache.len())
	}

	ev.UpdatePolicy(bundleV2())
	if ev.cache.len() != 0 {
		t.Fatalf("cache must be empty after policy update, got %d", ev.cache.len())
	}
	// v2 策略不要求签名，换成一个无签清单也必须按新策略重算。
	d2 := ev.Evaluate(context.Background(), id)
	t.Logf("after update input=%s decision=%+v", id, d2)
	if d2.PolicyVersion != 2 || d2.MatchedRule != "allow-anything" {
		t.Fatalf("stale conclusion reused after policy update: %+v", d2)
	}
}

func TestRevisionChangeInvalidatesEvenWithoutExplicitUpdate(t *testing.T) {
	id := "repo/img:v1"
	ms := &manifest.StaticSource{Items: map[string]*manifest.Manifest{id: goodManifest(id)}}
	ev, _ := newLoggedEvaluator(t, bundleV1(), ms)
	d1 := ev.Evaluate(context.Background(), id)
	if !d1.Allowed {
		t.Fatalf("first eval: %+v", d1)
	}
	// 同版本号但内容指纹不同（模拟“版本号没改、内容改了”）。
	b2 := bundleV1()
	b2.Revision = "rev-changed"
	ev.UpdatePolicy(b2)
	if ev.cache.len() != 0 {
		t.Fatal("revision change must invalidate cache")
	}
}

func TestFailedDecisionsAreNotCached(t *testing.T) {
	id := "repo/img:v1"
	// 空来源：清单缺失 -> 拒绝。
	ev, _ := newLoggedEvaluator(t, bundleV1(),
		&manifest.StaticSource{Items: map[string]*manifest.Manifest{}})

	d1 := ev.Evaluate(context.Background(), id)
	if d1.Allowed || d1.Reason != ReasonManifestNotFound {
		t.Fatalf("first: %+v", d1)
	}
	if ev.cache.len() != 0 {
		t.Fatalf("deny decision must not be cached, len=%d", ev.cache.len())
	}

	// 随后清单出现（故障恢复），必须重新评估并放行，不能复用旧的拒绝结论。
	ev.manifests = &manifest.StaticSource{Items: map[string]*manifest.Manifest{id: goodManifest(id)}}
	d2 := ev.Evaluate(context.Background(), id)
	t.Logf("after recovery input=%s decision=%+v", id, d2)
	if !d2.Allowed {
		t.Fatalf("recovery denied: %+v (stale deny cached?)", d2)
	}
}

func TestDistinctDenyReasons(t *testing.T) {
	base := goodManifest("repo/img:v1")

	noDigest := *goodManifest("repo/img:v1")
	noDigest.Digest = ""

	badVersion := *goodManifest("repo/img:v1")
	badVersion.APIVersion = "v9"

	tampered := *goodManifest("repo/img:v1")
	tampered.Signatures[0].Value = "sig|TAMPERED"

	noAtt := *goodManifest("repo/img:v1")
	noAtt.Attestations = nil

	cases := []struct {
		name string
		id   string
		m    *manifest.Manifest
		want Reason
	}{
		{"manifest not found", "repo/missing:v1", nil, ReasonManifestNotFound},
		{"missing digest field", "repo/img:v1", &noDigest, ReasonManifestMissingField},
		{"incompatible metadata version", "repo/img:v1", &badVersion, ReasonManifestVersionIncompat},
		{"signature verify failed", "repo/img:v1", &tampered, ReasonSignatureVerifyFailed},
		{"attestation missing", "repo/img:v1", &noAtt, ReasonAttestationMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			items := map[string]*manifest.Manifest{}
			if tc.m != nil {
				items[tc.id] = tc.m
			}
			ev, _ := newLoggedEvaluator(t, bundleV1(), &manifest.StaticSource{Items: items})
			d := ev.Evaluate(context.Background(), tc.id)
			t.Logf("input=%s case=%s basis=%q", tc.id, tc.name, d.Detail)
			if d.Allowed {
				t.Fatalf("want deny %s, got allow", tc.want)
			}
			if d.Reason != tc.want {
				t.Fatalf("want reason %s, got %s", tc.want, d.Reason)
			}
		})
	}
	_ = base
}

func TestNoPolicyIsFailClosed(t *testing.T) {
	ev, _ := newLoggedEvaluator(t, nil, &manifest.StaticSource{})
	d := ev.Evaluate(context.Background(), "repo/x:v1")
	if d.Allowed || d.Reason != ReasonPolicyUnavailable {
		t.Fatalf("nil policy must fail closed, got %+v", d)
	}
}

func TestEqualPriorityConflictDenies(t *testing.T) {
	pol := &policy.Policy{Version: 1, Rules: []policy.Rule{
		{Name: "a", Priority: 5, Action: policy.ActionAllow},
		{Name: "b", Priority: 5, Action: policy.ActionDeny},
	}}
	b := &policy.Bundle{Version: 1, Revision: "r", Policy: pol}
	ms := &manifest.StaticSource{Items: map[string]*manifest.Manifest{"repo/x:v1": goodManifest("repo/x:v1")}}
	ev, _ := newLoggedEvaluator(t, b, ms)
	d := ev.Evaluate(context.Background(), "repo/x:v1")
	if d.Allowed || d.Reason != ReasonPolicyConflict {
		t.Fatalf("conflict must deny distinctly, got %+v", d)
	}
}

func TestSingleflightSharesComputation(t *testing.T) {
	id := "repo/img:v1"
	ms := &countingSource{inner: &manifest.StaticSource{Items: map[string]*manifest.Manifest{id: goodManifest(id)}}}
	ev, _ := newLoggedEvaluator(t, bundleV1(), ms)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); ev.Evaluate(context.Background(), id) }()
	}
	wg.Wait()
	if ms.calls != 1 {
		t.Fatalf("singleflight should coalesce to 1 manifest fetch, got %d", ms.calls)
	}
}

type countingSource struct {
	inner manifest.Source
	calls int
	mu    sync.Mutex
}

func (c *countingSource) Get(ctx context.Context, id string) (*manifest.Manifest, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return c.inner.Get(ctx, id)
}

func ExampleDecision_loggingBasis() {
	id := "repo/img:v1"
	buf := &bytes.Buffer{}
	ev := NewEvaluator(bundleV1(),
		&manifest.StaticSource{Items: map[string]*manifest.Manifest{id: goodManifest(id)}},
		signature.NewVerifier(keyring())).WithLogger(log.New(buf, "", 0))
	d := ev.Evaluate(context.Background(), id)
	fmt.Println(d.Allowed, d.MatchedRule)
	// Output: true allow-signed
}
