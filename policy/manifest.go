package policy

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/h3yow/container-policy-guard-go/internal/yamlish"
)

// ImageMeta 是本地清单中的镜像元数据。
type ImageMeta struct {
	APIVersion  string   `json:"apiVersion" yaml:"apiVersion"`
	Reference   string   `json:"reference" yaml:"reference"`
	Repository  string   `json:"repository" yaml:"repository"`
	ImageName   string   `json:"imageName" yaml:"imageName"`
	Tag         string   `json:"tag" yaml:"tag"`
	Digest      string   `json:"digest" yaml:"digest"`
	DigestAlg   string   `json:"digestAlgorithm" yaml:"digestAlgorithm"`
	SignerNames []string `json:"signerNames,omitempty" yaml:"signerNames,omitempty"`
	AttestTypes []string `json:"attestationTypes,omitempty" yaml:"attestationTypes,omitempty"`
}

// Manifest 是本地镜像清单文件：引用 -> 元数据。
type Manifest struct {
	APIVersion string               `json:"apiVersion" yaml:"apiVersion"`
	Images     map[string]ImageMeta `json:"images" yaml:"images"`
}

// SupportedMetaAPIVersions 列出支持的清单/元数据 API 版本。
var SupportedMetaAPIVersions = []string{"guard.image/v1"}

// LoadManifest 从 YAML 或 JSON 文件加载本地镜像清单并校验关键字段。
func LoadManifest(ctx context.Context, path string) (*Manifest, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &LoadError{Kind: LoadKindSyntax, File: path, Msg: "cannot read manifest file: " + err.Error()}
	}
	var m Manifest
	if err := yamlish.Unmarshal(data, &m); err != nil {
		return nil, &LoadError{Kind: LoadKindSyntax, File: path, Msg: err.Error()}
	}
	if strings.TrimSpace(m.APIVersion) == "" {
		return nil, &LoadError{Kind: LoadKindMissingField, File: path, Msg: "manifest.apiVersion is required"}
	}
	if !contains(SupportedMetaAPIVersions, m.APIVersion) {
		return nil, &LoadError{Kind: LoadKindSyntax, File: path,
			Msg: "unsupported manifest apiVersion " + m.APIVersion + ", supported: " + strings.Join(SupportedMetaAPIVersions, ",")}
	}
	if len(m.Images) == 0 {
		return nil, &LoadError{Kind: LoadKindMissingField, File: path, Msg: "manifest.images must contain at least one image"}
	}
	for ref, meta := range m.Images {
		if strings.TrimSpace(meta.Reference) == "" {
			meta.Reference = ref
		}
		// 单条镜像的版本兼容、关键字段、摘要算法问题不在加载阶段整单拒绝，
		// 保留原样由评估器按不同原因区分拒绝。
		m.Images[ref] = meta
	}
	return &m, nil
}

// Lookup 按镜像引用查找元数据。
func (m *Manifest) Lookup(ref string) (ImageMeta, bool) {
	if m == nil {
		return ImageMeta{}, false
	}
	if meta, ok := m.Images[ref]; ok {
		return meta, true
	}
	// 兼容引用与条目键大小写/空白差异，以及按 digest 反查。
	want := strings.TrimSpace(ref)
	for k, meta := range m.Images {
		if strings.EqualFold(strings.TrimSpace(k), want) ||
			strings.EqualFold(strings.TrimSpace(meta.Reference), want) ||
			(meta.Digest != "" && strings.HasSuffix(want, meta.Digest)) {
			return meta, true
		}
	}
	return ImageMeta{}, false
}

// Validate 校验单条镜像元数据的关键字段与 API 版本。
func Validate(meta ImageMeta) error {
	if strings.TrimSpace(meta.APIVersion) == "" {
		return fmt.Errorf("apiVersion is required")
	}
	if !contains(SupportedMetaAPIVersions, meta.APIVersion) {
		return fmt.Errorf("unsupported meta apiVersion %q", meta.APIVersion)
	}
	if strings.TrimSpace(meta.Repository) == "" {
		return fmt.Errorf("repository is required")
	}
	if strings.TrimSpace(meta.Digest) == "" {
		return fmt.Errorf("digest is required")
	}
	if strings.TrimSpace(meta.DigestAlg) == "" {
		return fmt.Errorf("digestAlgorithm is required")
	}
	// 摘要必须与声明算法前缀一致（algorithm:hex）。
	prefix := meta.DigestAlg + ":"
	if !strings.HasPrefix(meta.Digest, prefix) {
		return fmt.Errorf("digest %q does not match declared algorithm %q", meta.Digest, meta.DigestAlg)
	}
	return nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// KnownDigestAlg 报告摘要算法是否受支持（sha256/sha384/sha512）。
func KnownDigestAlg(alg string) bool { return knownDigestAlg(alg) }
