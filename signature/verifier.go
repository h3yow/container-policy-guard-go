package signature

import (
	"context"
	"fmt"

	"github.com/h3yow/container-policy-guard-go/manifest"
)

// FailureReason 用于区分不同的验签/证明失败原因，不做笼统报错。
type FailureReason string

const (
	FailNone                 FailureReason = ""
	FailNoSignature          FailureReason = "signature_missing"
	FailVerification         FailureReason = "signature_verification_failed"
	FailKeyRevoked           FailureReason = "signing_key_revoked"
	FailKeyUnknown           FailureReason = "signing_key_unknown"
	FailDigestAlgMismatch    FailureReason = "digest_algorithm_mismatch"
	FailDigestAlgUnsupported FailureReason = "digest_algorithm_unsupported"
	FailAttestationMissing   FailureReason = "attestation_missing"
	FailAttestationInvalid   FailureReason = "attestation_invalid"
)

// supportedDigestAlgs 是本实现接受的摘要算法。
var supportedDigestAlgs = map[string]bool{
	"sha256": true,
	"sha512": true,
}

// Failure 描述一次校验失败的细节。
type Failure struct {
	Reason FailureReason
	Detail string
}

func (f *Failure) Error() string { return string(f.Reason) + ": " + f.Detail }

// Verifier 对本地清单做签名与证明校验。
//
// 说明：本地模拟环境没有真实密码学运算，签名/证明值采用确定性的
// 组合格式（见 ComposeSignatureValue / ComposeAttestationValue），
// 校验时重算期望值进行比对，从而能真实区分“值不对”“键不可信”等场景。
type Verifier struct {
	keyring *Keyring
}

// NewVerifier 创建校验器。
func NewVerifier(keyring *Keyring) *Verifier { return &Verifier{keyring: keyring} }

// Verify 校验镜像签名。
//
// 多签语义：多个签名中任一通过即可放行（兼容公钥轮换过渡期）；
// 全部失败时按“最严重原因”拒绝，优先级为
// revoked > unsupported digest alg > digest alg mismatch > unknown key > verify failed。
func (v *Verifier) Verify(_ context.Context, m *manifest.Manifest) error {
	if len(m.Signatures) == 0 {
		return &Failure{Reason: FailNoSignature, Detail: "image " + m.Identity() + " carries no signature"}
	}
	worst := &Failure{Reason: FailVerification, Detail: "no signature verified"}
	rank := func(r FailureReason) int {
		switch r {
		case FailKeyRevoked:
			return 6
		case FailDigestAlgUnsupported:
			return 5
		case FailDigestAlgMismatch:
			return 4
		case FailKeyUnknown:
			return 3
		default:
			return 2 // FailVerification
		}
	}

	for i, sig := range m.Signatures {
		if reason, detail := v.verifyOne(m, sig); reason != FailNone {
			if rank(reason) > rank(worst.Reason) {
				worst = &Failure{Reason: reason, Detail: detail}
			}
		} else {
			return nil // 多签中任一合法即通过
		}
		_ = i
	}
	return worst
}

func (v *Verifier) verifyOne(m *manifest.Manifest, sig manifest.Signature) (FailureReason, string) {
	// 1) 摘要算法：先判支持性，再判与清单是否一致。
	if !supportedDigestAlgs[sig.DigestAlg] {
		return FailDigestAlgUnsupported, fmt.Sprintf("signature by key %s uses unsupported digest algorithm %q", sig.KeyID, sig.DigestAlg)
	}
	if !supportedDigestAlgs[m.DigestAlg] {
		return FailDigestAlgUnsupported, fmt.Sprintf("manifest digest algorithm %q is unsupported", m.DigestAlg)
	}
	if sig.DigestAlg != m.DigestAlg {
		return FailDigestAlgMismatch, fmt.Sprintf("signature by key %s digested with %s but manifest declares %s", sig.KeyID, sig.DigestAlg, m.DigestAlg)
	}

	// 2) 公钥：沿轮换链查找，吊销/未知分别处理。
	chain, err := v.keyring.ActiveChain(sig.KeyID)
	if err != nil {
		if _, ok := err.(*KeyRevokedError); ok {
			return FailKeyRevoked, "signing key revoked: " + sig.KeyID
		}
		return FailVerification, err.Error()
	}
	var key *PublicKey
	for _, k := range chain {
		if k.Alg == sig.Alg {
			key = k
			break
		}
	}
	if key == nil {
		if _, known := v.keyring.Lookup(sig.KeyID); !known {
			return FailKeyUnknown, "no public key registered for keyID: " + sig.KeyID
		}
		return FailVerification, fmt.Sprintf("signature alg %q does not match registered key %q", sig.Alg, sig.KeyID)
	}

	// 3) 签名值：重算期望组合值比对。
	want := ComposeSignatureValue(sig.KeyID, sig.Alg, sig.DigestAlg, m.Digest)
	if sig.Value != want {
		return FailVerification, fmt.Sprintf("signature value mismatch for key %s", sig.KeyID)
	}
	return FailNone, ""
}

// VerifyAttestation 校验指定类型的证明；缺失与无效分别报错。
func (v *Verifier) VerifyAttestation(_ context.Context, m *manifest.Manifest, attType string) error {
	var found *manifest.Attestation
	for i := range m.Attestations {
		if m.Attestations[i].Type == attType {
			found = &m.Attestations[i]
			break
		}
	}
	if found == nil {
		return &Failure{Reason: FailAttestationMissing, Detail: fmt.Sprintf("image %s lacks attestation of type %q", m.Identity(), attType)}
	}

	chain, err := v.keyring.ActiveChain(found.KeyID)
	if err != nil {
		return &Failure{Reason: FailAttestationInvalid, Detail: "attestation signed by revoked key: " + found.KeyID}
	}
	var key *PublicKey
	for _, k := range chain {
		key = k
		break
	}
	if key == nil {
		if _, known := v.keyring.Lookup(found.KeyID); !known {
			return &Failure{Reason: FailAttestationInvalid, Detail: "attestation signed by unknown key: " + found.KeyID}
		}
	}
	want := ComposeAttestationValue(found.Type, found.KeyID, m.DigestAlg, m.Digest)
	if found.Value != want {
		return &Failure{Reason: FailAttestationInvalid, Detail: fmt.Sprintf("attestation %q value mismatch", attType)}
	}
	return nil
}

// ComposeSignatureValue 生成模拟签名值（确定性，便于本地重算校验）。
func ComposeSignatureValue(keyID, sigAlg, digestAlg, digest string) string {
	return fmt.Sprintf("sig|%s|%s|%s|%s", keyID, sigAlg, digestAlg, digest)
}

// ComposeAttestationValue 生成模拟证明值。
func ComposeAttestationValue(attType, keyID, digestAlg, digest string) string {
	return fmt.Sprintf("att|%s|%s|%s|%s", attType, keyID, digestAlg, digest)
}
