package sigverify_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/h3yow/container-policy-guard-go/internal/testdata"
	"github.com/h3yow/container-policy-guard-go/sigverify"
)

type ring struct {
	k1, k2, krev *testdata.KeyPair
	keyring      *sigverify.Keyring
	path         string
}

func newRing(t *testing.T) ring {
	t.Helper()
	dir := t.TempDir()
	k1, _ := testdata.NewEd25519Key("k1")
	k2, _ := testdata.NewEd25519Key("k2")
	krev, _ := testdata.NewEd25519Key("krev")
	body := "keys:\n" +
		"  - id: k1\n    algorithm: Ed25519\n    state: active\n    publicKey: |\n" + indent(k1.PEM) +
		"  - id: k2\n    algorithm: Ed25519\n    state: rotated\n    publicKey: |\n" + indent(k2.PEM) +
		"  - id: krev\n    algorithm: Ed25519\n    state: revoked\n    publicKey: |\n" + indent(krev.PEM)
	p := filepath.Join(dir, "keyring.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	kr, err := sigverify.LoadKeyring(context.Background(), p)
	if err != nil {
		t.Fatalf("load keyring: %v", err)
	}
	return ring{k1, k2, krev, kr, p}
}

func indent(pem string) string {
	out := ""
	for _, line := range splitLines(pem) {
		out += "      " + line + "\n"
	}
	return out
}

func splitLines(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '\n' {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(r)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

const digest = "sha256:deadbeef"

func imageSig(kp *testdata.KeyPair) sigverify.Signature {
	return sigverify.Signature{
		KeyID: kp.ID, Algorithm: "Ed25519", Digest: digest, DigestAlg: "sha256",
		Value: testdata.SignEd25519(kp, "sha256", digest),
	}
}

func hasKind(fs []sigverify.SigFailure, kind sigverify.SigFailureKind) bool {
	for _, f := range fs {
		if f.Kind == kind {
			return true
		}
	}
	return false
}

func TestMultiSignatureCountsValid(t *testing.T) {
	r := newRing(t)
	n, failures, err := r.keyring.VerifySignatures(digest, "sha256", []sigverify.Signature{
		imageSig(r.k1), imageSig(r.k2), imageSig(r.krev),
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 valid signatures (active+rotated), got %d", n)
	}
	if !hasKind(failures, sigverify.SigFailureKeyRevoked) {
		t.Fatalf("revoked key failure expected, got %+v", failures)
	}
	t.Logf("valid=%d failures=%v (revoked does not count)", n, failures)
}

func TestTamperedSignature(t *testing.T) {
	r := newRing(t)
	s := imageSig(r.k1)
	s.Value[0] ^= 0xFF
	n, fs, err := r.keyring.VerifySignatures(digest, "sha256", []sigverify.Signature{s})
	if err != nil || n != 0 || !hasKind(fs, sigverify.SigFailureVerify) {
		t.Fatalf("n=%d fs=%v err=%v", n, fs, err)
	}
}

func TestUnknownKey(t *testing.T) {
	r := newRing(t)
	ku, _ := testdata.NewEd25519Key("unknown")
	n, fs, _ := r.keyring.VerifySignatures(digest, "sha256", []sigverify.Signature{imageSig(ku)})
	if n != 0 || !hasKind(fs, sigverify.SigFailureKeyUnknown) {
		t.Fatalf("n=%d fs=%v", n, fs)
	}
}

func TestDigestAlgorithmDifference(t *testing.T) {
	r := newRing(t)
	s := imageSig(r.k1)
	s.DigestAlg = "sha512"
	n, fs, _ := r.keyring.VerifySignatures(digest, "sha256", []sigverify.Signature{s})
	if n != 0 || !hasKind(fs, sigverify.SigFailureUnsupportedDigAlg) {
		t.Fatalf("algorithm difference should be reported distinctly: n=%d fs=%v", n, fs)
	}
}

func TestUnsupportedManifestDigestAlg(t *testing.T) {
	r := newRing(t)
	_, _, err := r.keyring.VerifySignatures("sha1:xx", "sha1", nil)
	if err == nil {
		t.Fatalf("sha1 must be rejected at verification entry")
	}
	sf, ok := err.(*sigverify.SigFailure)
	if !ok || sf.Kind != sigverify.SigFailureUnsupportedDigAlg {
		t.Fatalf("expected unsupported digest failure, got %v", err)
	}
}

func TestDigestMismatch(t *testing.T) {
	r := newRing(t)
	s := imageSig(r.k1)
	s.Digest = "sha256:different"
	n, fs, _ := r.keyring.VerifySignatures(digest, "sha256", []sigverify.Signature{s})
	if n != 0 || !hasKind(fs, sigverify.SigFailureDigestMismatch) {
		t.Fatalf("n=%d fs=%v", n, fs)
	}
}

func TestAttestationMissingVsVerifyFailed(t *testing.T) {
	r := newRing(t)
	// 仅要求两种类型，实际一种都不带 → 两个缺失失败。
	_, fs, err := r.keyring.VerifyAttestations(digest, "sha256", []string{"provenance", "sbom"}, nil)
	if err != nil || len(fs) != 2 || !hasKind(fs, sigverify.SigFailureMissing) {
		t.Fatalf("fs=%v err=%v", fs, err)
	}
	// 证明存在但签名被篡改 → verify_failed，而不是笼统 missing。
	payload := []byte(`{"a":1}`)
	bad := testdata.SignEd25519Attest(r.k1, "sha256", digest, "provenance", payload)
	bad[0] ^= 0xFF
	att := sigverify.Attestation{Type: "provenance", KeyID: "k1", Digest: digest, DigestAlg: "sha256",
		Payload: payload, Value: bad}
	n, fs2, err := r.keyring.VerifyAttestations(digest, "sha256", []string{"provenance"}, []sigverify.Attestation{att})
	if err != nil || n != 0 || !hasKind(fs2, sigverify.SigFailureVerify) || hasKind(fs2, sigverify.SigFailureMissing) {
		t.Fatalf("present-but-bad attestation must report verify_failed: n=%d fs=%v err=%v", n, fs2, err)
	}
	t.Logf("missing failures distinct from verify failures")
}

func TestUnsignedAttestationPresence(t *testing.T) {
	r := newRing(t)
	att := sigverify.Attestation{Type: "sbom", Digest: digest, DigestAlg: "sha256", Payload: []byte("{}")}
	n, fs, err := r.keyring.VerifyAttestations(digest, "sha256", []string{"sbom"}, []sigverify.Attestation{att})
	if err != nil || n != 1 || len(fs) != 0 {
		t.Fatalf("unsigned attestation bound to digest should count: n=%d fs=%v err=%v", n, fs, err)
	}
}
