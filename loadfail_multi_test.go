package guard_test

import (
	"context"
	"strings"
	"testing"

	"github.com/h3yow/container-policy-guard-go"
	"github.com/h3yow/container-policy-guard-go/internal/testdata"
	"github.com/h3yow/container-policy-guard-go/policy"
	"github.com/h3yow/container-policy-guard-go/sigverify"
)

// 策略文件加载期三类错误必须可区分，且装配失败（绝不静默放行）。
func TestNewRejectsBrokenPolicies(t *testing.T) {
	cases := []struct {
		file   string
		reason guard.Reason
	}{
		{"testdata/policy-bad-syntax.yaml", guard.ReasonPolicySyntax},
		{"testdata/policy-bad-missing.yaml", guard.ReasonPolicyMissingField},
		{"testdata/policy-bad-conflict.yaml", guard.ReasonPolicyConflict},
	}
	for _, tc := range cases {
		t.Run(string(tc.reason), func(t *testing.T) {
			dir := t.TempDir()
			pol := testdata.Must(testdata.WriteFile(dir, "policy.yaml", readRepoFile(t, tc.file)))
			manifest := testdata.Must(testdata.WriteFile(dir, "manifest.yaml", readRepoFile(t, "testdata/manifest.yaml")))
			_, err := guard.New(context.Background(), guard.Config{PolicyPath: pol, ManifestPath: manifest})
			if err == nil {
				t.Fatalf("expected New to reject %s", tc.file)
			}
			t.Logf("INPUT policy=%s -> rejectErr=%q (expected reason=%s)", tc.file, err.Error(), tc.reason)
			le, ok := err.(*policy.LoadError)
			if !ok {
				t.Fatalf("expected *policy.LoadError, got %T: %v", err, err)
			}
			switch tc.reason {
			case guard.ReasonPolicySyntax:
				if le.Kind != policy.LoadKindSyntax {
					t.Fatalf("expected syntax kind, got %s (%v)", le.Kind, err)
				}
			case guard.ReasonPolicyMissingField:
				if le.Kind != policy.LoadKindMissingField {
					t.Fatalf("expected missing_field kind, got %s (%v)", le.Kind, err)
				}
			case guard.ReasonPolicyConflict:
				if le.Kind != policy.LoadKindConflict {
					t.Fatalf("expected conflict kind, got %s (%v)", le.Kind, err)
				}
			}
			if !strings.Contains(err.Error(), le.Kind) {
				t.Fatalf("error message should carry kind: %v", err)
			}
		})
	}
}

func setupMultiSigPolicy(t *testing.T, f *fixture, distinct bool) *guard.Guard {
	t.Helper()
	distinctLine := ""
	if distinct {
		distinctLine = "    distinctKeys: true\n"
	}
	body := "version: pol-multi\nrules:\n" +
		"  - id: org/multi\n    repository: registry.example.com/*\n" +
		"    requiredSignatures: 2\n" + distinctLine +
		"    allowedDigestAlgorithms: [sha256, sha384, sha512]\n" +
		"    effect: allow\n    priority: 100\n"
	polPath := testdata.Must(testdata.WriteFile(f.dir, "multi.yaml", body))
	g, err := guard.New(context.Background(), guard.Config{
		PolicyPath: polPath, ManifestPath: f.manifest, KeyringPath: f.keyring,
	})
	if err != nil {
		t.Fatalf("guard.New: %v", err)
	}
	return g
}

func TestMultiSignatureCountRequiresTwo(t *testing.T) {
	f := setup(t, "")
	g := setupMultiSigPolicy(t, f, false)
	meta := mustBaseMeta(t, f)
	one := []sigverify.Signature{sigFor(f.keyA, meta)}
	t.Logf("INPUT ref=%s validSigs=1 required=2", meta.Reference)
	d, _ := g.Evaluate(context.Background(), guard.Request{Meta: meta, Signatures: one})
	t.Logf("DECISION\n%s", d.Explain())
	if d.Allowed || d.Reason != guard.ReasonSignatureVerifyFailed {
		t.Fatalf("one valid signature should not satisfy 2-signature rule, got %s", d.Reason)
	}

	two := []sigverify.Signature{sigFor(f.keyA, meta), sigFor(f.keyB, meta)}
	d2, _ := g.Evaluate(context.Background(), guard.Request{Meta: meta, Signatures: two})
	t.Logf("SECOND INPUT validSigs=2 -> ALLOW=%v", d2.Allowed)
	if !d2.Allowed {
		t.Fatalf("two valid signatures should satisfy rule, got %s: %s", d2.Reason, d2.Detail)
	}
}

func TestMultiSignatureOneRevokedOneValid(t *testing.T) {
	f := setup(t, "")
	g := setupMultiSigPolicy(t, f, false)
	meta := mustBaseMeta(t, f)
	sigs := []sigverify.Signature{sigFor(f.keyA, meta), sigFor(f.keyRev, meta)}
	t.Logf("INPUT ref=%s sigKeys=[active,revoked] required=2", meta.Reference)
	d, _ := g.Evaluate(context.Background(), guard.Request{Meta: meta, Signatures: sigs})
	t.Logf("DECISION\n%s", d.Explain())
	// 数量不足（吊销签名无效），且失败原因里吊销优先、可区分。
	if d.Allowed {
		t.Fatalf("revoked signature must not count toward multi-signature requirement")
	}
	if d.Reason != guard.ReasonKeyRevoked {
		t.Fatalf("expected SIGNING_KEY_REVOKED to surface distinctly, got %s", d.Reason)
	}
}

// 轮换下线的密钥仍可验证旧镜像，但不能用来“凑”新签名场景之外的判定——
// 本实现语义：rotated 密钥对既有镜像的签名依然有效（兼容旧镜像）。
func TestRotatedKeyStillVerifiesExistingImage(t *testing.T) {
	f := setup(t, "")
	// 给夹具公钥库补一把 rotated 密钥。
	keyRot, err := testdata.NewEd25519Key("key-rotated-1")
	if err != nil {
		t.Fatalf("gen rotated key: %v", err)
	}
	kr := "keys:\n" +
		"  - id: key-active-1\n    algorithm: Ed25519\n    state: active\n    publicKey: |\n" + indentPEM(f.keyA.PEM) +
		"  - id: key-rotated-1\n    algorithm: Ed25519\n    state: rotated\n    publicKey: |\n" + indentPEM(keyRot.PEM)
	keyringPath := testdata.Must(testdata.WriteFile(f.dir, "keyring-rot.yaml", kr))

	body := "version: pol-rot\nrules:\n" +
		"  - id: org/one\n    repository: registry.example.com/*\n" +
		"    requiredSignatures: 1\n    allowedDigestAlgorithms: [sha256, sha384, sha512]\n" +
		"    effect: allow\n    priority: 100\n"
	polPath := testdata.Must(testdata.WriteFile(f.dir, "rot.yaml", body))
	g, err := guard.New(context.Background(), guard.Config{
		PolicyPath: polPath, ManifestPath: f.manifest, KeyringPath: keyringPath,
	})
	if err != nil {
		t.Fatalf("guard.New: %v", err)
	}
	meta := mustBaseMetaFrom(t, g)
	s := sigverify.Signature{
		KeyID: "key-rotated-1", Algorithm: "Ed25519", Digest: meta.Digest, DigestAlg: meta.DigestAlg,
		Value: testdata.SignEd25519(keyRot, meta.DigestAlg, meta.Digest),
	}
	t.Logf("INPUT ref=%s signed by rotated key (existing image)", meta.Reference)
	d, _ := g.Evaluate(context.Background(), guard.Request{Meta: meta, Signatures: []sigverify.Signature{s}})
	t.Logf("DECISION\n%s", d.Explain())
	if !d.Allowed {
		t.Fatalf("rotated-out key should still verify existing images, got %s: %s", d.Reason, d.Detail)
	}
}

func mustBaseMeta(t *testing.T, f *fixture) policy.ImageMeta {
	t.Helper()
	meta, ok := f.g.LookupMeta("registry.example.com/base:1.0")
	if !ok {
		t.Fatalf("lookup base")
	}
	return meta
}

func mustBaseMetaFrom(t *testing.T, g *guard.Guard) policy.ImageMeta {
	t.Helper()
	meta, ok := g.LookupMeta("registry.example.com/base:1.0")
	if !ok {
		t.Fatalf("lookup base")
	}
	return meta
}
