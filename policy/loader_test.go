package policy

import (
	"context"
	"strings"
	"testing"
)

func TestLoadErrorTypes(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		file string
		want LoadErrorType
	}{
		{"syntax error", "../testdata/policies/syntax-error.json", LoadErrSyntax},
		{"missing field", "../testdata/policies/missing-field.json", LoadErrMissing},
		{"conflict", "../testdata/policies/conflict.json", LoadErrConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadAll(ctx, []Source{&FileSource{Path: tc.file}})
			t.Logf("input=%s err=%v", tc.file, err)
			if err == nil {
				t.Fatalf("expected %s error, got nil", tc.want)
			}
			le, ok := err.(*LoadError)
			if !ok {
				t.Fatalf("expected *LoadError, got %T: %v", err, err)
			}
			if le.Type != tc.want {
				t.Fatalf("want error type %s, got %s", tc.want, le.Type)
			}
		})
	}
}

func TestLoadAllMergesBuiltinAndFile(t *testing.T) {
	builtin := &Policy{Version: 1, Rules: []Rule{
		{Name: "b-deny", Source: "builtin", Priority: 0, Action: ActionDeny},
	}}
	bundle, err := LoadAll(context.Background(), []Source{
		&BuiltinSource{Ver: 1, Pol: builtin},
		&FileSource{Path: "../testdata/policies/extra.json"},
	})
	if err != nil {
		t.Fatalf("merge load failed: %v", err)
	}
	t.Logf("merged version=%d revision=%s sources=%v rules=%d",
		bundle.Version, bundle.Revision[:8], bundle.Sources, len(bundle.Policy.Rules))
	if bundle.Version != 2 {
		t.Fatalf("want merged version 2, got %d", bundle.Version)
	}
	if len(bundle.Policy.Rules) != 2 {
		t.Fatalf("want 2 merged rules, got %d", len(bundle.Policy.Rules))
	}
	// 优先级降序：external-deny-legacy(200) 应排在 b-deny(0) 前。
	if bundle.Policy.Rules[0].Name != "external-deny-legacy" {
		t.Fatalf("priority order wrong: %s", bundle.Policy.Rules[0].Name)
	}
}

func TestContentRevisionChangesWithFile(t *testing.T) {
	load := func(path string) string {
		b, err := LoadAll(context.Background(), []Source{&FileSource{Path: path}})
		if err != nil {
			t.Fatalf("load %s: %v", path, err)
		}
		return b.Revision
	}
	r1 := load("../testdata/policies/extra.json")
	r2 := load("../testdata/policies/extra-v2.json")
	t.Logf("rev1=%s rev2=%s", r1[:8], r2[:8])
	if r1 == r2 {
		t.Fatal("revision must change when policy content changes")
	}
}

func TestNoSourcesIsFailClosed(t *testing.T) {
	_, err := LoadAll(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), string(LoadErrMissing)) {
		t.Fatalf("want missing-field error for empty sources, got %v", err)
	}
}
