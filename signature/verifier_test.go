package signature

import (
	"context"
	"strings"
	"testing"

	"github.com/h3yow/container-policy-guard-go/manifest"
)

const D256 = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

var D512 = "sha512:" + strings.Repeat("c", 128)

func testKeyring() *Keyring {
	kr := NewKeyring()
	kr.Add(PublicKey{ID: "k-new", State: KeyActive, Alg: "ed25519"})
	kr.Add(PublicKey{ID: "k-old", State: KeyRotated, Alg: "ed25519", RotatedBy: "k-new"})
	kr.Add(PublicKey{ID: "k-dead", State: KeyRevoked, Alg: "ed25519"})
	return kr
}

func mkManifest(sigs ...manifest.Signature) *manifest.Manifest {
	return &manifest.Manifest{
		APIVersion: "v1", ImageID: "repo/img:v1", Repository: "repo/img", Tag: "v1",
		Digest: D256, DigestAlg: "sha256", Signatures: sigs,
	}
}

func sigOf(keyID, alg, digestAlg, digest string) manifest.Signature {
	return manifest.Signature{KeyID: keyID, Alg: alg, DigestAlg: digestAlg,
		Value: ComposeSignatureValue(keyID, alg, digestAlg, digest)}
}

func expectReason(t *testing.T, err error, want FailureReason) {
	t.Helper()
	if want == FailNone {
		if err != nil {
			t.Fatalf("want success, got %v", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("want failure %s, got nil", want)
	}
	f, ok := err.(*Failure)
	if !ok {
		t.Fatalf("want *Failure, got %T", err)
	}
	t.Logf("verifier input returned reason=%s detail=%q", f.Reason, f.Detail)
	if f.Reason != want {
		t.Fatalf("want reason %s, got %s (%s)", want, f.Reason, f.Detail)
	}
}

func TestVerifyCases(t *testing.T) {
	v := NewVerifier(testKeyring())
	ctx := context.Background()

	t.Run("valid current key", func(t *testing.T) {
		m := mkManifest(sigOf("k-new", "ed25519", "sha256", D256))
		t.Logf("input: single signature by active key k-new over %s", D256)
		expectReason(t, v.Verify(ctx, m), FailNone)
	})

	t.Run("rotated key still verifies", func(t *testing.T) {
		m := mkManifest(sigOf("k-old", "ed25519", "sha256", D256))
		t.Logf("input: signature by rotated key k-old (rotation chain -> k-new)")
		expectReason(t, v.Verify(ctx, m), FailNone)
	})

	t.Run("multi-sig one bad one good", func(t *testing.T) {
		bad := sigOf("k-dead", "ed25519", "sha256", D256)
		good := sigOf("k-new", "ed25519", "sha256", D256)
		m := mkManifest(bad, good)
		t.Logf("input: two signatures, k-dead(revoked) + k-new(active)")
		expectReason(t, v.Verify(ctx, m), FailNone)
	})

	t.Run("revoked only -> revoked", func(t *testing.T) {
		m := mkManifest(sigOf("k-dead", "ed25519", "sha256", D256))
		expectReason(t, v.Verify(ctx, m), FailKeyRevoked)
	})

	t.Run("unknown key -> unknown", func(t *testing.T) {
		m := mkManifest(sigOf("k-stranger", "ed25519", "sha256", D256))
		expectReason(t, v.Verify(ctx, m), FailKeyUnknown)
	})

	t.Run("tampered value -> verification failed", func(t *testing.T) {
		s := sigOf("k-new", "ed25519", "sha256", D256)
		s.Value = "sig|TAMPERED"
		m := mkManifest(s)
		expectReason(t, v.Verify(ctx, m), FailVerification)
	})

	t.Run("digest alg mismatch vs manifest", func(t *testing.T) {
		m := mkManifest(sigOf("k-new", "ed25519", "sha512", D512))
		expectReason(t, v.Verify(ctx, m), FailDigestAlgMismatch)
	})

	t.Run("unsupported digest alg", func(t *testing.T) {
		s := manifest.Signature{KeyID: "k-new", Alg: "ed25519", DigestAlg: "md5",
			Value: ComposeSignatureValue("k-new", "ed25519", "md5", D256)}
		m := mkManifest(s)
		expectReason(t, v.Verify(ctx, m), FailDigestAlgUnsupported)
	})

	t.Run("no signature -> missing", func(t *testing.T) {
		m := mkManifest()
		expectReason(t, v.Verify(ctx, m), FailNoSignature)
	})
}

func TestAttestationReasons(t *testing.T) {
	v := NewVerifier(testKeyring())
	ctx := context.Background()

	t.Run("missing attestation", func(t *testing.T) {
		m := mkManifest()
		expectReason(t, v.VerifyAttestation(ctx, m, "sbom"), FailAttestationMissing)
	})

	t.Run("valid attestation", func(t *testing.T) {
		m := mkManifest()
		m.Attestations = []manifest.Attestation{{Type: "sbom", KeyID: "k-new",
			Value: ComposeAttestationValue("sbom", "k-new", "sha256", D256)}}
		expectReason(t, v.VerifyAttestation(ctx, m, "sbom"), FailNone)
	})

	t.Run("invalid attestation value", func(t *testing.T) {
		m := mkManifest()
		m.Attestations = []manifest.Attestation{{Type: "sbom", KeyID: "k-new", Value: "att|bogus"}}
		expectReason(t, v.VerifyAttestation(ctx, m, "sbom"), FailAttestationInvalid)
	})

	t.Run("attestation by revoked key", func(t *testing.T) {
		m := mkManifest()
		m.Attestations = []manifest.Attestation{{Type: "sbom", KeyID: "k-dead",
			Value: ComposeAttestationValue("sbom", "k-dead", "sha256", D256)}}
		expectReason(t, v.VerifyAttestation(ctx, m, "sbom"), FailAttestationInvalid)
	})
}
