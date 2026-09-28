package manifest

import (
	"context"
	"testing"
)

func TestValidateReasons(t *testing.T) {
	cases := []struct {
		name string
		m    Manifest
		want LoadErrorType
	}{
		{"missing apiVersion", Manifest{Repository: "r", Tag: "t", Digest: "d", DigestAlg: "sha256"}, ManifestErrMissingField},
		{"incompatible version", Manifest{APIVersion: "v0", Repository: "r", Tag: "t", Digest: "d", DigestAlg: "sha256"}, ManifestErrVersionIncompat},
		{"missing repository", Manifest{APIVersion: "v1", Tag: "t", Digest: "d", DigestAlg: "sha256"}, ManifestErrMissingField},
		{"missing digest", Manifest{APIVersion: "v1", Repository: "r", Tag: "t", DigestAlg: "sha256"}, ManifestErrMissingField},
		{"missing digestAlg", Manifest{APIVersion: "v1", Repository: "r", Tag: "t", Digest: "d"}, ManifestErrMissingField},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.m.Validate()
			t.Logf("input case=%s err=%v", tc.name, err)
			if err == nil {
				t.Fatalf("want %s, got nil", tc.want)
			}
			le := err.(*LoadError)
			if le.Type != tc.want {
				t.Fatalf("want %s, got %s", tc.want, le.Type)
			}
		})
	}
}

func TestDirSource(t *testing.T) {
	ctx := context.Background()
	src := NewDirSource("../testdata/manifests")

	t.Run("known image loads", func(t *testing.T) {
		m, err := src.Get(ctx, "registry.local/app/web:v1")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("loaded image=%s digestAlg=%s sigs=%d atts=%d", m.Identity(), m.DigestAlg, len(m.Signatures), len(m.Attestations))
	})

	t.Run("unknown image -> not found", func(t *testing.T) {
		_, err := src.Get(ctx, "registry.local/app/nope:v9")
		le := err.(*LoadError)
		if le.Type != ManifestErrNotFound {
			t.Fatalf("want not_found, got %v", err)
		}
	})

	t.Run("missing digest field -> missing", func(t *testing.T) {
		_, err := src.Get(ctx, "registry.local/app/missing:v1")
		le, ok := err.(*LoadError)
		if !ok {
			t.Fatalf("want LoadError, got %T %v", err, err)
		}
		t.Logf("basis: %v", le)
		if le.Type != ManifestErrMissingField {
			t.Fatalf("want missing_field, got %s", le.Type)
		}
	})

	t.Run("old apiVersion -> incompatible", func(t *testing.T) {
		_, err := src.Get(ctx, "registry.local/app/oldmeta:v1")
		le := err.(*LoadError)
		if le.Type != ManifestErrVersionIncompat {
			t.Fatalf("want version_incompatible, got %s", le.Type)
		}
	})
}
