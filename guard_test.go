package guard_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/h3yow/container-policy-guard-go"
	"github.com/h3yow/container-policy-guard-go/internal/testdata"
	"github.com/h3yow/container-policy-guard-go/policy"
	"github.com/h3yow/container-policy-guard-go/sigverify"
)

// fixture 汇总一次测试装配的运行期资源（密钥为运行期生成，私钥仅测试可见）。
type fixture struct {
	g        *guard.Guard
	dir      string
	keyA     *testdata.KeyPair // key-active-1
	keyB     *testdata.KeyPair // key-active-2
	keyRev   *testdata.KeyPair // key-revoked-1
	policy   string
	manifest string
	keyring  string
}

func setup(t *testing.T, policyFile string) *fixture {
	t.Helper()
	dir := t.TempDir()
	ctx := context.Background()

	keyA, err := testdata.NewEd25519Key("key-active-1")
	if err != nil {
		t.Fatalf("gen keyA: %v", err)
	}
	keyB, err := testdata.NewEd25519Key("key-active-2")
	if err != nil {
		t.Fatalf("gen keyB: %v", err)
	}
	keyRev, err := testdata.NewEd25519Key("key-revoked-1")
	if err != nil {
		t.Fatalf("gen keyRev: %v", err)
	}

	krYaml := "keys:\n" +
		"  - id: key-active-1\n    algorithm: Ed25519\n    state: active\n    publicKey: |\n" + indentPEM(keyA.PEM) +
		"  - id: key-active-2\n    algorithm: Ed25519\n    state: active\n    publicKey: |\n" + indentPEM(keyB.PEM) +
		"  - id: key-revoked-1\n    algorithm: Ed25519\n    state: revoked\n    publicKey: |\n" + indentPEM(keyRev.PEM)
	keyring := testdata.Must(testdata.WriteFile(dir, "keyring.yaml", krYaml))

	manifestSrc := readRepoFile(t, "testdata/manifest.yaml")
	manifest := testdata.Must(testdata.WriteFile(dir, "manifest.yaml", manifestSrc))

	var polPath string
	if policyFile == "" {
		polPath = filepath.Join(dir, "policy.yaml")
		polBody := "version: pol-v1\nrules:\n" +
			"  - id: org/allow-signed-images\n    repository: registry.example.com/*\n" +
			"    requiredSignatures: 2\n    allowedDigestAlgorithms: [sha256, sha384, sha512]\n" +
			"    effect: allow\n    priority: 100\n" +
			"  - id: org/require-provenance\n    repository: registry.example.com/apps/*\n" +
			"    requiredSignatures: 1\n    requireAttestations: [provenance]\n" +
			"    allowedDigestAlgorithms: [sha256, sha384, sha512]\n" +
			"    effect: allow\n    priority: 110\n"
		polPath = testdata.Must(testdata.WriteFile(dir, "policy.yaml", polBody))
	} else {
		body := readRepoFile(t, policyFile)
		name := filepath.Base(policyFile)
		polPath = testdata.Must(testdata.WriteFile(dir, name, body))
	}

	g, err := guard.New(ctx, guard.Config{PolicyPath: polPath, ManifestPath: manifest, KeyringPath: keyring})
	if err != nil {
		t.Fatalf("guard.New: %v", err)
	}
	t.Cleanup(func() {})

	f := &fixture{dir: dir, keyA: keyA, keyB: keyB, keyRev: keyRev, policy: polPath, manifest: manifest, keyring: keyring}
	t.Logf("setup fixture: dir=%s policy=%s", dir, polPath)
	// 把装配好的 guard 挂在 fixture 上。
	f.g = g
	return f
}

func (f *fixture) signMeta(t *testing.T, kps ...*testdata.KeyPair) (policy.ImageMeta, []sigverify.Signature) {
	t.Helper()
	meta, ok := f.g.LookupMeta("registry.example.com/base:1.0")
	if !ok {
		t.Fatalf("meta lookup failed")
	}
	var sigs []sigverify.Signature
	for _, kp := range kps {
		sigs = append(sigs, sigverify.Signature{
			KeyID:     kp.ID,
			Algorithm: "Ed25519",
			Digest:    meta.Digest,
			DigestAlg: meta.DigestAlg,
			Value:     testdata.SignEd25519(kp, meta.DigestAlg, meta.Digest),
		})
	}
	return meta, sigs
}

func indentPEM(pem string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(pem, "\n"), "\n") {
		b.WriteString("      " + line + "\n")
	}
	return b.String()
}

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(data)
}

func TestAllowWithTwoValidSignatures(t *testing.T) {
	f := setup(t, "")
	meta, sigs := f.signMeta(t, f.keyA, f.keyB)
	t.Logf("INPUT ref=%s digest=%s sigCount=%d keyIds=[%s,%s]",
		meta.Reference, meta.Digest, len(sigs), f.keyA.ID, f.keyB.ID)

	d, err := f.g.Evaluate(context.Background(), guard.Request{Meta: meta, Signatures: sigs})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	t.Logf("DECISION\n%s", d.Explain())
	if !d.Allowed || d.Reason != guard.ReasonAllow {
		t.Fatalf("expected allow, got %s: %s", d.Reason, d.Detail)
	}
}

func TestNoMatchingRuleDefaultsDeny(t *testing.T) {
	f := setup(t, "")
	// 改成一个外部规则与内置规则都不匹配的仓库（内置 default-deny 仅匹配 "*"
	// 之外的情况在纯内置策略下生效；这里显式构造无命中场景）。
	meta, ok := f.g.LookupMeta("registry.example.com/base:1.0")
	if !ok {
		t.Fatalf("lookup")
	}
	meta.Repository = "unmatched.example.com/x"
	t.Logf("INPUT ref=%s repository=%s (no rule matches)", meta.Reference, meta.Repository)

	d, err := f.g.Evaluate(context.Background(), guard.Request{Meta: meta})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	t.Logf("DECISION\n%s", d.Explain())
	if d.Allowed || d.Reason != guard.ReasonNoMatchingRule {
		t.Fatalf("expected NO_MATCHING_RULE, got %s", d.Reason)
	}
}

func TestBuiltinPolicyDeniesUnmatched(t *testing.T) {
	// 不加载任何外部策略：内置规则不匹配该镜像 → 评估器默认拒绝。
	dir := t.TempDir()
	manifest := testdata.Must(testdata.WriteFile(dir, "manifest.yaml", readRepoFile(t, "testdata/manifest.yaml")))
	g, err := guard.New(context.Background(), guard.Config{ManifestPath: manifest})
	if err != nil {
		t.Fatalf("guard.New: %v", err)
	}
	meta, ok := g.LookupMeta("registry.example.com/base:1.0")
	if !ok {
		t.Fatalf("lookup")
	}
	t.Logf("INPUT ref=%s (builtin-only policy)", meta.Reference)
	d, err := g.Evaluate(context.Background(), guard.Request{Meta: meta})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	t.Logf("DECISION\n%s", d.Explain())
	if d.Allowed || d.Reason != guard.ReasonNoMatchingRule {
		t.Fatalf("expected NO_MATCHING_RULE under builtin-only policy, got %s", d.Reason)
	}
}

func TestExplicitDenyRule(t *testing.T) {
	f := setup(t, "")
	// 追加一条与 allow 同目标、但优先级更高的 deny 规则。
	denyBody := "version: pol-deny\nrules:\n" +
		"  - id: org/block-base\n    repository: registry.example.com/base\n" +
		"    effect: deny\n    priority: 500\n"
	polPath := testdata.Must(testdata.WriteFile(f.dir, "deny.yaml", denyBody))
	g2, err := guard.New(context.Background(), guard.Config{PolicyPath: polPath, ManifestPath: f.manifest, KeyringPath: f.keyring})
	if err != nil {
		t.Fatalf("guard.New: %v", err)
	}
	meta, sigs := func() (policy.ImageMeta, []sigverify.Signature) {
		m, ok := g2.LookupMeta("registry.example.com/base:1.0")
		if !ok {
			t.Fatalf("lookup")
		}
		var ss []sigverify.Signature
		for _, kp := range []*testdata.KeyPair{f.keyA, f.keyB} {
			ss = append(ss, sigverify.Signature{KeyID: kp.ID, Algorithm: "Ed25519",
				Digest: m.Digest, DigestAlg: m.DigestAlg, Value: testdata.SignEd25519(kp, m.DigestAlg, m.Digest)})
		}
		return m, ss
	}()
	t.Logf("INPUT ref=%s sigCount=%d (deny rule priority 500 overrides allow 100)", meta.Reference, len(sigs))
	d, err := g2.Evaluate(context.Background(), guard.Request{Meta: meta, Signatures: sigs})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	t.Logf("DECISION\n%s", d.Explain())
	if d.Allowed || d.Reason != guard.ReasonExplicitDeny {
		t.Fatalf("expected EXPLICIT_DENY, got %s", d.Reason)
	}
}

func TestConcurrentEvaluationConsistentAndCached(t *testing.T) {
	f := setup(t, "")
	meta, sigs := f.signMeta(t, f.keyA, f.keyB)

	const n = 64
	var wg sync.WaitGroup
	results := make([]*guard.Decision, n)
	errs := make([]error, n)
	wg.Add(n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			<-start
			results[i], errs[i] = f.g.Evaluate(context.Background(), guard.Request{Meta: meta, Signatures: sigs})
		}()
	}
	close(start)
	wg.Wait()

	t.Logf("INPUT ref=%s goroutines=%d", meta.Reference, n)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d error: %v", i, err)
		}
	}
	allowCount := 0
	for i, d := range results {
		if d == nil {
			t.Fatalf("goroutine %d got nil decision", i)
		}
		if d.Allowed {
			allowCount++
		}
		if d.PolicyVer != "pol-v1" || d.Reason != guard.ReasonAllow {
			t.Fatalf("goroutine %d inconsistent decision: %s", i, d.Explain())
		}
	}
	t.Logf("DECISION all %d goroutines ALLOW, allowCount=%d, cacheSize=%d", n, allowCount, f.g.CacheLen())
	if allowCount != n {
		t.Fatalf("expected %d consistent allows, got %d", n, allowCount)
	}
	if f.g.CacheLen() != 1 {
		t.Fatalf("expected single merged cache entry, got %d", f.g.CacheLen())
	}

	// 第二次评估：应命中缓存。
	d, _ := f.g.Evaluate(context.Background(), guard.Request{Meta: meta, Signatures: sigs})
	if !hasTrace(d, "cache: HIT") {
		t.Fatalf("expected cache HIT trace, got:\n%s", d.Explain())
	}
	t.Logf("second evaluation served from cache")
}

func hasTrace(d *guard.Decision, prefix string) bool {
	for _, line := range d.Trace {
		if strings.Contains(line, prefix) {
			return true
		}
	}
	return false
}

func TestDeniedDecisionIsCachedAsDenied(t *testing.T) {
	f := setup(t, "")
	meta, _ := f.signMeta(t) // 无签名：策略要求 2 签，必须拒绝
	t.Logf("INPUT ref=%s sigCount=0, policy requires 2 signatures", meta.Reference)

	d1, err := f.g.Evaluate(context.Background(), guard.Request{Meta: meta})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	t.Logf("DECISION#1\n%s", d1.Explain())
	if d1.Allowed || d1.Reason != guard.ReasonSignatureMissing {
		t.Fatalf("expected SIGNATURE_MISSING deny, got %s", d1.Reason)
	}

	// 再次评估即使补上“有效签名”也绝不能被错误当成通过——
	// 同缓存键（元数据未变）应返回缓存下来的拒绝结论。
	meta2 := meta
	d2, err := f.g.Evaluate(context.Background(), guard.Request{Meta: meta2, Signatures: nil})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	t.Logf("DECISION#2 (cache)\n%s", d2.Explain())
	if d2.Allowed || d2.Reason != guard.ReasonSignatureMissing {
		t.Fatalf("cached deny must remain deny, got allowed=%v reason=%s", d2.Allowed, d2.Reason)
	}
	if !hasTrace(d2, "cache: HIT") {
		t.Fatalf("denied decision should be cached")
	}
}

func TestPolicyReloadInvalidatesCache(t *testing.T) {
	f := setup(t, "")
	meta, sigs := f.signMeta(t, f.keyA, f.keyB)

	// v1：2 签即可通过。
	d, _ := f.g.Evaluate(context.Background(), guard.Request{Meta: meta, Signatures: sigs})
	t.Logf("POLICY v1 -> ALLOW=%v cacheSize=%d version=%s", d.Allowed, f.g.CacheLen(), f.g.PolicyVersion())
	if !d.Allowed {
		t.Fatalf("expected allow under v1, got %s", d.Reason)
	}

	// 更新策略文件到 v2（额外要求 provenance 证明）。
	v2 := readRepoFile(t, "testdata/policy-v2.yaml")
	if err := os.WriteFile(f.policy, []byte(v2), 0o644); err != nil {
		t.Fatalf("overwrite policy: %v", err)
	}
	if err := f.g.Reload(context.Background()); err != nil {
		t.Fatalf("reload: %v", err)
	}
	t.Logf("RELOADED version=%s cacheSize=%d", f.g.PolicyVersion(), f.g.CacheLen())
	if f.g.PolicyVersion() != "pol-v2" {
		t.Fatalf("expected pol-v2, got %s", f.g.PolicyVersion())
	}
	if f.g.CacheLen() != 0 {
		t.Fatalf("cache must be cleared on policy version change, size=%d", f.g.CacheLen())
	}

	// 同样的输入：旧 ALLOW 结论不得复用，因缺 provenance 而拒绝。
	d2, _ := f.g.Evaluate(context.Background(), guard.Request{Meta: meta, Signatures: sigs})
	t.Logf("POLICY v2 DECISION\n%s", d2.Explain())
	if d2.Allowed || d2.Reason != guard.ReasonAttestationMissing {
		t.Fatalf("expected ATTESTATION_MISSING under v2, got allowed=%v reason=%s", d2.Allowed, d2.Reason)
	}
}

func TestReloadBrokenPolicyKeepsOldVersion(t *testing.T) {
	f := setup(t, "")
	bad := readRepoFile(t, "testdata/policy-bad-syntax.yaml")
	if err := os.WriteFile(f.policy, []byte(bad), 0o644); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	err := f.g.Reload(context.Background())
	t.Logf("RELOAD broken policy err=%v (version stays %s)", err, f.g.PolicyVersion())
	if err == nil {
		t.Fatalf("expected reload error for syntactically broken policy")
	}
	if f.g.PolicyVersion() != "pol-v1" {
		t.Fatalf("old policy version must be retained, got %s", f.g.PolicyVersion())
	}
}

func TestSamePriorityAllowDenyConflictRejected(t *testing.T) {
	f := setup(t, "")
	body := "version: pol-conf\nrules:\n" +
		"  - id: x/allow\n    repository: registry.example.com/x\n" +
		"    effect: allow\n    priority: 50\n" +
		"  - id: x/deny\n    repository: registry.example.com/x\n" +
		"    effect: deny\n    priority: 50\n"
	polPath := testdata.Must(testdata.WriteFile(f.dir, "conf.yaml", body))
	g, err := guard.New(context.Background(), guard.Config{
		PolicyPath: polPath, ManifestPath: f.manifest, KeyringPath: f.keyring,
	})
	if err != nil {
		t.Fatalf("guard.New: %v", err)
	}
	meta, ok := g.LookupMeta("registry.example.com/base:1.0")
	if !ok {
		t.Fatalf("lookup")
	}
	meta.Repository = "registry.example.com/x"
	t.Logf("INPUT ref=%s matched by same-priority allow+deny", meta.Reference)
	d, _ := g.Evaluate(context.Background(), guard.Request{Meta: meta})
	t.Logf("DECISION\n%s", d.Explain())
	if d.Allowed || d.Reason != guard.ReasonRulesDisagree {
		t.Fatalf("expected RULES_DISAGREE, got %s", d.Reason)
	}
}
