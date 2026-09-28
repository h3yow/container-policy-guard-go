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

func sigFor(kp *testdata.KeyPair, meta policy.ImageMeta) sigverify.Signature {
	return sigverify.Signature{
		KeyID:     kp.ID,
		Algorithm: "Ed25519",
		Digest:    meta.Digest,
		DigestAlg: meta.DigestAlg,
		Value:     testdata.SignEd25519(kp, meta.DigestAlg, meta.Digest),
	}
}

// 一把需要 1 签 + 1 份 provenance 的策略，供证明类用例使用。
func setupAttestPolicy(t *testing.T, f *fixture) *guard.Guard {
	t.Helper()
	body := "version: pol-attest\nrules:\n" +
		"  - id: org/attest\n    repository: registry.example.com/apps/*\n" +
		"    requiredSignatures: 1\n    requireAttestations: [provenance]\n" +
		"    allowedDigestAlgorithms: [sha256, sha384, sha512]\n" +
		"    effect: allow\n    priority: 100\n"
	polPath := testdata.Must(testdata.WriteFile(f.dir, "attest.yaml", body))
	g, err := guard.New(context.Background(), guard.Config{
		PolicyPath: polPath, ManifestPath: f.manifest, KeyringPath: f.keyring,
	})
	if err != nil {
		t.Fatalf("guard.New: %v", err)
	}
	return g
}

func TestSignatureTamperedVerifyFailed(t *testing.T) {
	f := setup(t, "")
	meta := mustAppMeta(t, f)
	s := sigFor(f.keyA, meta)
	s.Value = append(append([]byte(nil), s.Value...), 0x01) // 篡改签名
	t.Logf("INPUT ref=%s signature tampered=true keyId=%s", meta.Reference, s.KeyID)

	d, err := f.g.Evaluate(context.Background(), guard.Request{Meta: meta, Signatures: []sigverify.Signature{s}})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	t.Logf("DECISION\n%s", d.Explain())
	if d.Allowed || d.Reason != guard.ReasonSignatureVerifyFailed {
		t.Fatalf("expected SIGNATURE_VERIFY_FAILED, got %s", d.Reason)
	}
}

func TestSignatureUnknownKey(t *testing.T) {
	f := setup(t, "")
	meta := mustAppMeta(t, f)
	unknown, _ := testdata.NewEd25519Key("key-not-in-keyring")
	s := sigFor(unknown, meta)
	t.Logf("INPUT ref=%s signature keyId=%s (not trusted)", meta.Reference, s.KeyID)

	d, _ := f.g.Evaluate(context.Background(), guard.Request{Meta: meta, Signatures: []sigverify.Signature{s}})
	t.Logf("DECISION\n%s", d.Explain())
	if d.Allowed || d.Reason != guard.ReasonSignatureVerifyFailed {
		t.Fatalf("unknown key must yield SIGNATURE_VERIFY_FAILED, got %s", d.Reason)
	}
	if !strings.Contains(d.Explain(), "key_unknown") {
		t.Fatalf("trace should record key_unknown:\n%s", d.Explain())
	}
}

func TestSignatureRevokedKey(t *testing.T) {
	f := setup(t, "")
	meta := mustAppMeta(t, f)
	s := sigFor(f.keyRev, meta)
	t.Logf("INPUT ref=%s signature keyId=%s (revoked)", meta.Reference, s.KeyID)

	d, _ := f.g.Evaluate(context.Background(), guard.Request{Meta: meta, Signatures: []sigverify.Signature{s}})
	t.Logf("DECISION\n%s", d.Explain())
	if d.Allowed || d.Reason != guard.ReasonKeyRevoked {
		t.Fatalf("revoked key must yield SIGNING_KEY_REVOKED, got %s", d.Reason)
	}
}

func TestSignatureMissingEntirely(t *testing.T) {
	f := setup(t, "")
	meta := mustAppMeta(t, f)
	t.Logf("INPUT ref=%s sigCount=0", meta.Reference)
	d, _ := f.g.Evaluate(context.Background(), guard.Request{Meta: meta})
	t.Logf("DECISION\n%s", d.Explain())
	if d.Allowed || d.Reason != guard.ReasonSignatureMissing {
		t.Fatalf("expected SIGNATURE_MISSING, got %s", d.Reason)
	}
}

func TestDigestAlgorithmMismatch(t *testing.T) {
	f := setup(t, "")
	meta := mustAppMeta(t, f)
	s := sigFor(f.keyA, meta)
	s.DigestAlg = "sha512" // 签名声明的摘要算法与镜像元数据不一致
	t.Logf("INPUT ref=%s manifestAlg=sha256 signatureAlg=sha512", meta.Reference)
	d, _ := f.g.Evaluate(context.Background(), guard.Request{Meta: meta, Signatures: []sigverify.Signature{s}})
	t.Logf("DECISION\n%s", d.Explain())
	if d.Allowed || d.Reason != guard.ReasonUnsupportedDigestAlgorithm {
		t.Fatalf("expected UNSUPPORTED_DIGEST_ALGORITHM, got %s", d.Reason)
	}
}

func TestWeakDigestAlgorithmRejected(t *testing.T) {
	f := setup(t, "")
	meta, ok := f.g.LookupMeta("registry.example.com/weak:1")
	if !ok {
		t.Fatalf("lookup weak image")
	}
	t.Logf("INPUT ref=%s digestAlg=%s", meta.Reference, meta.DigestAlg)
	d, _ := f.g.Evaluate(context.Background(), guard.Request{Meta: meta})
	t.Logf("DECISION\n%s", d.Explain())
	if d.Allowed || d.Reason != guard.ReasonUnsupportedDigestAlgorithm {
		t.Fatalf("sha1 must yield UNSUPPORTED_DIGEST_ALGORITHM, got %s", d.Reason)
	}
}

func TestAttestationMissing(t *testing.T) {
	f := setup(t, "")
	g := setupAttestPolicy(t, f)
	meta := mustAppMeta(t, f)
	s := sigFor(f.keyA, meta)
	t.Logf("INPUT ref=%s sigCount=1 attestationCount=0 (provenance required)", meta.Reference)
	d, _ := g.Evaluate(context.Background(), guard.Request{Meta: meta, Signatures: []sigverify.Signature{s}})
	t.Logf("DECISION\n%s", d.Explain())
	if d.Allowed || d.Reason != guard.ReasonAttestationMissing {
		t.Fatalf("expected ATTESTATION_MISSING, got %s", d.Reason)
	}
}

func TestAttestationVerifyFailed(t *testing.T) {
	f := setup(t, "")
	g := setupAttestPolicy(t, f)
	meta := mustAppMeta(t, f)
	s := sigFor(f.keyA, meta)
	payload := []byte(`{"builder":"ci"}`)
	badSig := testdata.SignEd25519Attest(f.keyA, meta.DigestAlg, meta.Digest, "provenance", payload)
	badSig[0] ^= 0xFF // 篡改证明签名
	att := sigverify.Attestation{
		Type: "provenance", KeyID: f.keyA.ID, Digest: meta.Digest, DigestAlg: meta.DigestAlg,
		Payload: payload, Value: badSig,
	}
	t.Logf("INPUT ref=%s attestation=provenance signatureTampered=true", meta.Reference)
	d, _ := g.Evaluate(context.Background(), guard.Request{
		Meta: meta, Signatures: []sigverify.Signature{s}, Attestations: []sigverify.Attestation{att},
	})
	t.Logf("DECISION\n%s", d.Explain())
	if d.Allowed || d.Reason != guard.ReasonAttestationVerifyFailed {
		t.Fatalf("expected ATTESTATION_VERIFY_FAILED, got %s", d.Reason)
	}
}

func TestAttestationPresentAndValid(t *testing.T) {
	f := setup(t, "")
	g := setupAttestPolicy(t, f)
	meta := mustAppMeta(t, f)
	s := sigFor(f.keyA, meta)
	payload := []byte(`{"builder":"ci"}`)
	att := sigverify.Attestation{
		Type: "provenance", KeyID: f.keyA.ID, Digest: meta.Digest, DigestAlg: meta.DigestAlg,
		Payload: payload, Value: testdata.SignEd25519Attest(f.keyA, meta.DigestAlg, meta.Digest, "provenance", payload),
	}
	t.Logf("INPUT ref=%s sig=valid attestation=provenance valid", meta.Reference)
	d, _ := g.Evaluate(context.Background(), guard.Request{
		Meta: meta, Signatures: []sigverify.Signature{s}, Attestations: []sigverify.Attestation{att},
	})
	t.Logf("DECISION\n%s", d.Explain())
	if !d.Allowed {
		t.Fatalf("expected allow with valid signed provenance, got %s: %s", d.Reason, d.Detail)
	}
}

func TestMetaVersionIncompatible(t *testing.T) {
	f := setup(t, "")
	meta, ok := f.g.LookupMeta("registry.example.com/legacy:1")
	if !ok {
		t.Fatalf("lookup legacy")
	}
	t.Logf("INPUT ref=%s apiVersion=%s", meta.Reference, meta.APIVersion)
	d, _ := f.g.Evaluate(context.Background(), guard.Request{Meta: meta})
	t.Logf("DECISION\n%s", d.Explain())
	if d.Allowed || d.Reason != guard.ReasonMetaVersionIncompatible {
		t.Fatalf("expected META_VERSION_INCOMPATIBLE, got %s", d.Reason)
	}
}

func TestMetaMissingFields(t *testing.T) {
	f := setup(t, "")
	meta := policy.ImageMeta{APIVersion: "guard.image/v1", Repository: "", Digest: ""}
	t.Logf("INPUT meta with empty repository and digest")
	d, _ := f.g.Evaluate(context.Background(), guard.Request{Meta: meta})
	t.Logf("DECISION\n%s", d.Explain())
	if d.Allowed || d.Reason != guard.ReasonMetaMissing {
		t.Fatalf("expected IMAGE_META_MISSING, got %s", d.Reason)
	}
}

func TestReferenceNotInManifest(t *testing.T) {
	f := setup(t, "")
	ref := "registry.example.com/does-not-exist:9.9"
	t.Logf("INPUT ref=%s (absent from manifest)", ref)
	d, _ := f.g.EvaluateRef(context.Background(), ref, nil, nil)
	t.Logf("DECISION\n%s", d.Explain())
	if d.Allowed || d.Reason != guard.ReasonMetaMissing {
		t.Fatalf("expected IMAGE_META_MISSING for unknown ref, got %s", d.Reason)
	}
}

// mustAppMeta 返回 apps/web 镜像元数据（命中 apps/* 规则）。
func mustAppMeta(t *testing.T, f *fixture) policy.ImageMeta {
	t.Helper()
	meta, ok := f.g.LookupMeta("registry.example.com/apps/web:2.3")
	if !ok {
		t.Fatalf("lookup apps/web")
	}
	return meta
}
