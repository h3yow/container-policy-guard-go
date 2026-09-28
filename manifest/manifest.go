package manifest

import (
	"fmt"
	"strings"
)

// SupportedAPIVersions 是本实现理解的清单元数据版本。
var SupportedAPIVersions = map[string]bool{
	"v1": true,
}

// Manifest 是本地模拟的容器镜像元数据。
type Manifest struct {
	APIVersion   string            `json:"apiVersion"`
	ImageID      string            `json:"imageID"`
	Repository   string            `json:"repository"`
	Tag          string            `json:"tag"`
	Digest       string            `json:"digest"`
	DigestAlg    string            `json:"digestAlg"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	Signatures   []Signature       `json:"signatures,omitempty"`
	Attestations []Attestation     `json:"attestations,omitempty"`
}

// Signature 是本地模拟的镜像签名。
type Signature struct {
	KeyID     string `json:"keyID"`
	Alg       string `json:"alg"`       // 签名算法，如 ed25519
	DigestAlg string `json:"digestAlg"` // 被签名摘要所用算法，如 sha256
	Value     string `json:"value"`     // 模拟签名值
}

// Attestation 是本地模拟的证明。
type Attestation struct {
	Type  string `json:"type"`
	KeyID string `json:"keyID"`
	Value string `json:"value"`
}

// Identity 返回镜像标识 repository:tag，作为缓存键的一部分。
func (m *Manifest) Identity() string {
	if m.Repository == "" || m.Tag == "" {
		return m.ImageID
	}
	return m.Repository + ":" + m.Tag
}

// Validate 检查清单关键字段与元数据版本；失败原因可区分。
func (m *Manifest) Validate() error {
	if strings.TrimSpace(m.APIVersion) == "" {
		return &LoadError{Type: ManifestErrMissingField, Detail: "manifest.apiVersion is required"}
	}
	if !SupportedAPIVersions[m.APIVersion] {
		return &LoadError{
			Type:   ManifestErrVersionIncompat,
			Detail: fmt.Sprintf("manifest apiVersion %q is not supported (supported: v1)", m.APIVersion),
		}
	}
	if strings.TrimSpace(m.Repository) == "" {
		return &LoadError{Type: ManifestErrMissingField, Detail: "manifest.repository is required"}
	}
	if strings.TrimSpace(m.Tag) == "" {
		return &LoadError{Type: ManifestErrMissingField, Detail: "manifest.tag is required"}
	}
	if strings.TrimSpace(m.Digest) == "" {
		return &LoadError{Type: ManifestErrMissingField, Detail: "manifest.digest is required"}
	}
	if strings.TrimSpace(m.DigestAlg) == "" {
		return &LoadError{Type: ManifestErrMissingField, Detail: "manifest.digestAlg is required"}
	}
	return nil
}
