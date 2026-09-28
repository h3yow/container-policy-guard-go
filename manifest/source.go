package manifest

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// Source 是镜像清单来源。
type Source interface {
	Get(ctx context.Context, imageID string) (*Manifest, error)
}

// LoadErrorType 区分清单加载失败原因。
type LoadErrorType string

const (
	// ManifestErrNotFound 找不到镜像标识对应的本地清单。
	ManifestErrNotFound LoadErrorType = "manifest_not_found"
	// ManifestErrMissingField 清单缺少关键字段。
	ManifestErrMissingField LoadErrorType = "manifest_missing_field"
	// ManifestErrVersionIncompat 清单元数据版本不被支持。
	ManifestErrVersionIncompat LoadErrorType = "manifest_version_incompatible"
	// ManifestErrSyntax 清单 JSON 非法。
	ManifestErrSyntax LoadErrorType = "manifest_syntax_error"
)

// LoadError 携带可区分的失败原因。
type LoadError struct {
	Type   LoadErrorType
	Detail string
}

func (e *LoadError) Error() string { return string(e.Type) + ": " + e.Detail }

// DirSource 从本地目录读取清单：镜像标识 repo/app:v1 -> repo_app__v1.json。
// 这里不做真实路径穿透防护之外的假设；imageID 仅允许有限字符。
type DirSource struct {
	Dir string
}

// NewDirSource 创建目录来源。
func NewDirSource(dir string) *DirSource { return &DirSource{Dir: dir} }

func (s *DirSource) Get(ctx context.Context, imageID string) (*Manifest, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	if !safeImageID(imageID) {
		return nil, &LoadError{Type: ManifestErrNotFound, Detail: "unsafe or empty image id: " + imageID}
	}
	name := strings.NewReplacer("/", "_", ":", "__").Replace(imageID) + ".json"
	raw, err := os.ReadFile(filepath.Join(s.Dir, name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &LoadError{Type: ManifestErrNotFound, Detail: "no local manifest for image: " + imageID}
		}
		return nil, &LoadError{Type: ManifestErrSyntax, Detail: err.Error()}
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, &LoadError{Type: ManifestErrSyntax, Detail: "invalid manifest json for " + imageID + ": " + err.Error()}
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if m.ImageID == "" {
		m.ImageID = imageID
	} else if m.ImageID != imageID {
		return nil, &LoadError{Type: ManifestErrMissingField, Detail: "manifest.imageID does not match requested id"}
	}
	return &m, nil
}

// StaticSource 是内存清单来源，主要用于测试。
type StaticSource struct {
	Items map[string]*Manifest
}

func (s *StaticSource) Get(_ context.Context, imageID string) (*Manifest, error) {
	m, ok := s.Items[imageID]
	if !ok {
		return nil, &LoadError{Type: ManifestErrNotFound, Detail: "no in-memory manifest for image: " + imageID}
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return m, nil
}

func safeImageID(id string) bool {
	if id == "" || len(id) > 512 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_', r == '/', r == ':', r == '/':
		default:
			return false
		}
	}
	return !strings.Contains(id, "//")
}
