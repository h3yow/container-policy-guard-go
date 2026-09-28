package yamlish

import "testing"

func TestParsePolicyShape(t *testing.T) {
	src := `
# 注释行
version: v1
rules:
  - id: r1
    effect: allow
    priority: 10
    requireAttestations: [provenance, sbom]
  - id: r2
    effect: deny
nested:
  a: "x:y"
  b: true
empty:
`
	var v struct {
		Version string `json:"version"`
		Rules   []struct {
			ID     string `json:"id"`
			Effect string `json:"effect"`
		} `json:"rules"`
		Nested map[string]any `json:"nested"`
	}
	if err := Unmarshal([]byte(src), &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if v.Version != "v1" || len(v.Rules) != 2 || v.Rules[0].ID != "r1" || v.Rules[1].Effect != "deny" {
		t.Fatalf("bad parse: %+v", v)
	}
	if v.Nested["a"] != "x:y" || v.Nested["b"] != true {
		t.Fatalf("bad nested: %+v", v.Nested)
	}
}

func TestParseJSONPassthrough(t *testing.T) {
	if err := Unmarshal([]byte(`{"a": 1}`), &struct{ A int }{}); err != nil {
		t.Fatal(err)
	}
}

func TestRejectBadSequenceIndentation(t *testing.T) {
	// 与 testdata/policy-bad-syntax.yaml 同形：未闭合的行内流序列。
	src := "version: pol-bad\nrules:\n  - id: x\n    repository: [a, b\n"
	var v map[string]any
	if err := Unmarshal([]byte(src), &v); err == nil {
		t.Fatalf("expected syntax error for mis-indented sequence item, got %#v", v)
	}
}
