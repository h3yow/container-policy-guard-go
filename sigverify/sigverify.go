// Package sigverify 在本地完成镜像签名与证明（attestation）的校验，
// 覆盖多签、公钥轮换/吊销与摘要算法差异等场景。
package sigverify

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"hash"
	"os"
	"strings"

	"github.com/h3yow/container-policy-guard-go/internal/yamlish"
)

// KeyState 表示信任公钥的生命周期状态。
type KeyState string

const (
	KeyActive     KeyState = "active"
	KeyRotatedOut KeyState = "rotated" // 轮换下线：仅可验证旧镜像，不能签新镜像
	KeyRevoked    KeyState = "revoked" // 吊销：任何签名一律无效
)

// TrustedKey 是公钥库中的一个信任公钥条目。
type TrustedKey struct {
	ID        string   `json:"id" yaml:"id"`
	Algorithm string   `json:"algorithm" yaml:"algorithm"` // RSA / ECDSA / Ed25519
	PEM       string   `json:"publicKey" yaml:"publicKey"` // PEM 编码文本
	State     KeyState `json:"state" yaml:"state"`
	NotBefore string   `json:"notBefore,omitempty" yaml:"notBefore,omitempty"`
	NotAfter  string   `json:"notAfter,omitempty" yaml:"notAfter,omitempty"`

	pub crypto.PublicKey
}

// Keyring 是信任公钥库。
type Keyring struct {
	keys []TrustedKey
}

type rawKeyring struct {
	Keys []TrustedKey `json:"keys" yaml:"keys"`
}

// LoadKeyring 从 YAML 或 JSON 文件加载公钥库并解析 PEM 公钥。
func LoadKeyring(ctx context.Context, path string) (*Keyring, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sigverify: cannot read keyring: %w", err)
	}
	var raw rawKeyring
	if err := yamlish.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("sigverify: keyring syntax error: %w", err)
	}
	if len(raw.Keys) == 0 {
		return nil, fmt.Errorf("sigverify: keyring contains no keys")
	}
	seen := map[string]bool{}
	for i := range raw.Keys {
		k := &raw.Keys[i]
		if strings.TrimSpace(k.ID) == "" {
			return nil, fmt.Errorf("sigverify: keys[%d].id is required", i)
		}
		if seen[k.ID] {
			return nil, fmt.Errorf("sigverify: duplicate key id %q", k.ID)
		}
		seen[k.ID] = true
		switch k.State {
		case KeyActive, KeyRotatedOut, KeyRevoked:
		case "":
			k.State = KeyActive
		default:
			return nil, fmt.Errorf("sigverify: key %s has unknown state %q", k.ID, k.State)
		}
		pub, err := parsePublicKey([]byte(k.PEM))
		if err != nil {
			return nil, fmt.Errorf("sigverify: key %s: %w", k.ID, err)
		}
		k.pub = pub
	}
	return &Keyring{keys: raw.Keys}, nil
}

func parsePublicKey(pemBytes []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM block")
	}
	switch block.Type {
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKIX public key: %w", err)
		}
		return pub, nil
	case "RSA PUBLIC KEY":
		pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS1 public key: %w", err)
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}

// Signature 是镜像的一个本地签名。
type Signature struct {
	KeyID     string `json:"keyId" yaml:"keyId"`
	Algorithm string `json:"algorithm" yaml:"algorithm"`             // 签名算法，如 RSA-SHA256 / ECDSA-SHA256 / Ed25519
	Digest    string `json:"digest" yaml:"digest"`                   // 被签名的镜像摘要（algorithm:hex）
	DigestAlg string `json:"digestAlgorithm" yaml:"digestAlgorithm"` // 摘要算法
	Value     []byte `json:"value" yaml:"value"`                     // 裸签名值
	SignedAt  string `json:"signedAt,omitempty" yaml:"signedAt,omitempty"`
}

// Attestation 是镜像的一个本地证明。
type Attestation struct {
	Type      string `json:"type" yaml:"type"` // provenance / sbom ...
	KeyID     string `json:"keyId,omitempty" yaml:"keyId,omitempty"`
	Digest    string `json:"digest" yaml:"digest"`
	DigestAlg string `json:"digestAlgorithm" yaml:"digestAlgorithm"`
	Payload   []byte `json:"payload" yaml:"payload"` // JSON 证明负载
	Value     []byte `json:"value,omitempty" yaml:"value,omitempty"`
}

// SigFailureKind 区分签名/证明校验失败的具体类别。
type SigFailureKind string

const (
	SigFailureNone              SigFailureKind = ""
	SigFailureVerify            SigFailureKind = "verify_failed"
	SigFailureMissing           SigFailureKind = "missing"
	SigFailureKeyRevoked        SigFailureKind = "key_revoked"
	SigFailureKeyUnknown        SigFailureKind = "key_unknown"
	SigFailureDigestMismatch    SigFailureKind = "digest_mismatch"
	SigFailureUnsupportedDigAlg SigFailureKind = "unsupported_digest_algorithm"
)

// SigFailure 携带可区分的失败类别与说明。
type SigFailure struct {
	Kind   SigFailureKind
	Detail string
}

func (f *SigFailure) Error() string {
	if f == nil {
		return ""
	}
	return string(f.Kind) + ": " + f.Detail
}

// VerifySignatures 在本地验证镜像的多个签名。
// 每个签名独立判定，多签按“通过校验的签名数”统计，调用方据此对照
// 规则要求的 requiredSignatures。吊销/未知密钥、摘要不匹配、算法不支持、
// 密码学验签失败分别产生不同类别的失败记录，绝不含糊地合并。
func (k *Keyring) VerifySignatures(digest string, digestAlg string, sigs []Signature) (int, []SigFailure, error) {
	if err := checkDigestAlg(digestAlg); err != nil {
		return 0, nil, err
	}
	failures := []SigFailure{}
	valid := 0
	for i, s := range sigs {
		tk, ok := k.FindKey(s.KeyID)
		if !ok {
			failures = append(failures, SigFailure{Kind: SigFailureKeyUnknown,
				Detail: fmt.Sprintf("signature[%d] keyId=%q is not in the trusted keyring", i, s.KeyID)})
			continue
		}
		if tk.State == KeyRevoked {
			failures = append(failures, SigFailure{Kind: SigFailureKeyRevoked,
				Detail: fmt.Sprintf("signature[%d] signed by revoked key %q", i, s.KeyID)})
			continue
		}
		if s.DigestAlg != "" && s.DigestAlg != digestAlg {
			failures = append(failures, SigFailure{Kind: SigFailureUnsupportedDigAlg,
				Detail: fmt.Sprintf("signature[%d] digestAlgorithm=%q differs from manifest %q", i, s.DigestAlg, digestAlg)})
			continue
		}
		if s.Digest != "" && s.Digest != digest {
			failures = append(failures, SigFailure{Kind: SigFailureDigestMismatch,
				Detail: fmt.Sprintf("signature[%d] covers digest %s but image digest is %s", i, s.Digest, digest)})
			continue
		}
		signed := digestPayload(digestAlg, digest)
		if err := cryptoVerify(tk, s.Algorithm, digestAlg, signed, s.Value); err != nil {
			failures = append(failures, SigFailure{Kind: SigFailureVerify,
				Detail: fmt.Sprintf("signature[%d] keyId=%q: %v", i, s.KeyID, err)})
			continue
		}
		valid++
	}
	return valid, failures, nil
}

// VerifyAttestations 校验所要求类型的证明：每类证明必须存在（区分“缺失”），
// 若带签名则必须通过同一公钥库验证（区分“验签失败”）。
func (k *Keyring) VerifyAttestations(digest string, digestAlg string, required []string, atts []Attestation) (int, []SigFailure, error) {
	if err := checkDigestAlg(digestAlg); err != nil {
		return 0, nil, err
	}
	byType := map[string][]Attestation{}
	for _, a := range atts {
		byType[a.Type] = append(byType[a.Type], a)
	}
	failures := []SigFailure{}
	presentValid := 0
	for _, typ := range required {
		lst := byType[typ]
		if len(lst) == 0 {
			failures = append(failures, SigFailure{Kind: SigFailureMissing,
				Detail: "required attestation type not present: " + typ})
			continue
		}
		ok := false
		for j, a := range lst {
			if a.DigestAlg != "" && a.DigestAlg != digestAlg {
				failures = append(failures, SigFailure{Kind: SigFailureUnsupportedDigAlg,
					Detail: fmt.Sprintf("attestation %s[%d] digestAlgorithm mismatch", typ, j)})
				continue
			}
			if a.Digest != "" && a.Digest != digest {
				failures = append(failures, SigFailure{Kind: SigFailureDigestMismatch,
					Detail: fmt.Sprintf("attestation %s[%d] covers a different digest", typ, j)})
				continue
			}
			// 无签名值的证明只要求内容存在并绑定本摘要；带签名则必须验签通过。
			if len(a.Value) == 0 {
				ok = true
				continue
			}
			tk, found := k.FindKey(a.KeyID)
			if !found {
				failures = append(failures, SigFailure{Kind: SigFailureKeyUnknown,
					Detail: fmt.Sprintf("attestation %s[%d] keyId=%q unknown", typ, j, a.KeyID)})
				continue
			}
			if tk.State == KeyRevoked {
				failures = append(failures, SigFailure{Kind: SigFailureKeyRevoked,
					Detail: fmt.Sprintf("attestation %s[%d] signed by revoked key %q", typ, j, a.KeyID)})
				continue
			}
			signed := attestationPayload(digestAlg, digest, typ, a.Payload)
			if err := cryptoVerify(tk, guessSigAlg(tk), digestAlg, signed, a.Value); err != nil {
				failures = append(failures, SigFailure{Kind: SigFailureVerify,
					Detail: fmt.Sprintf("attestation %s[%d]: %v", typ, j, err)})
				continue
			}
			ok = true
		}
		if ok {
			presentValid++
		} else if !hasFailureType(failures, typ) {
			failures = append(failures, SigFailure{Kind: SigFailureVerify,
				Detail: "attestation type present but no valid copy: " + typ})
		}
	}
	return presentValid, failures, nil
}

func hasFailureType(failures []SigFailure, typ string) bool {
	for _, f := range failures {
		if strings.Contains(f.Detail, typ) {
			return true
		}
	}
	return false
}

// FindKey 按键 ID 查找信任公钥。
func (k *Keyring) FindKey(id string) (TrustedKey, bool) {
	if k == nil {
		return TrustedKey{}, false
	}
	for _, key := range k.keys {
		if key.ID == id {
			return key, true
		}
	}
	return TrustedKey{}, false
}

func checkDigestAlg(alg string) error {
	switch alg {
	case "sha256", "sha384", "sha512":
		return nil
	case "":
		return &SigFailure{Kind: SigFailureUnsupportedDigAlg, Detail: "empty digest algorithm"}
	default:
		return &SigFailure{Kind: SigFailureUnsupportedDigAlg, Detail: "unsupported digest algorithm: " + alg}
	}
}

func digestPayload(alg, digest string) []byte {
	return []byte("image|" + alg + "|" + digest)
}

func attestationPayload(alg, digest, typ string, payload []byte) []byte {
	return []byte("attest|" + alg + "|" + digest + "|" + typ + "|" + string(payload))
}

func hashFor(alg string) (crypto.Hash, func() hash.Hash, error) {
	switch alg {
	case "sha256":
		return crypto.SHA256, sha256.New, nil
	case "sha384":
		return crypto.SHA384, sha512.New384, nil
	case "sha512":
		return crypto.SHA512, sha512.New, nil
	default:
		return 0, nil, fmt.Errorf("unsupported digest algorithm %q", alg)
	}
}

func guessSigAlg(k TrustedKey) string {
	switch k.pub.(type) {
	case *rsa.PublicKey:
		return "RSA-SHA256"
	case *ecdsa.PublicKey:
		return "ECDSA-SHA256"
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return ""
	}
}

func cryptoVerify(k TrustedKey, sigAlg, digestAlg string, signed, sig []byte) error {
	chash, hf, err := hashFor(digestAlg)
	if err != nil {
		return err
	}
	h := hf()
	h.Write(signed)
	digest := h.Sum(nil)
	switch pub := k.pub.(type) {
	case *rsa.PublicKey:
		switch sigAlg {
		case "RSA-SHA256", "RSA-SHA384", "RSA-SHA512", "":
			if err := rsa.VerifyPKCS1v15(pub, chash, digest, sig); err != nil {
				return fmt.Errorf("rsa verify failed: %w", err)
			}
			return nil
		case "RSA-PSS":
			if err := rsa.VerifyPSS(pub, chash, digest, sig, nil); err != nil {
				return fmt.Errorf("rsa-pss verify failed: %w", err)
			}
			return nil
		default:
			return fmt.Errorf("unsupported rsa signature algorithm %q", sigAlg)
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest, sig) {
			return fmt.Errorf("ecdsa verify failed")
		}
		return nil
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, signed, sig) {
			return fmt.Errorf("ed25519 verify failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type %T", k.pub)
	}
}

// DecodeSignatureValue 是测试与加载辅助：把 base64 签名值写入 Signature.Value。
func DecodeSignatureValue(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
