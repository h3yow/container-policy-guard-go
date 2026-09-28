package policy_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/h3yow/container-policy-guard-go/policy"
)

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestLoadJSONPolicy(t *testing.T) {
	dir := t.TempDir()
	body := `{"version":"json-v1","rules":[
		{"id":"r1","repository":"example.com/*","effect":"allow","requiredSignatures":1}]}`
	p := writeFile(t, dir, "policy.json", body)
	pol, err := policy.LoadFile(context.Background(), p)
	if err != nil {
		t.Fatalf("load json: %v", err)
	}
	if pol.Version != "json-v1" || len(pol.Rules) != 1 || pol.Rules[0].Source != policy.SourceFile {
		t.Fatalf("bad parsed policy: %+v", pol)
	}
}

func TestConflictSamePrioritySameTarget(t *testing.T) {
	dir := t.TempDir()
	body := "version: c1\nrules:\n" +
		"  - id: a\n    repository: example.com/x\n    effect: allow\n    priority: 5\n" +
		"  - id: b\n    repository: example.com/x\n    effect: deny\n    priority: 5\n"
	p := writeFile(t, dir, "c.yaml", body)
	pol, err := policy.LoadFile(context.Background(), p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	merged, err := policy.Merge(policy.BuiltinPolicy(), pol)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	ev := policy.NewEvaluator(merged)
	meta := policy.ImageMeta{
		APIVersion: "guard.image/v1", Repository: "example.com/x",
		Digest: "sha256:aa", DigestAlg: "sha256",
	}
	res := ev.Evaluate(meta)
	if res.Winner != nil {
		t.Fatalf("same-priority allow/deny conflict must not pick a winner, got %+v", res.Winner)
	}
	if len(res.Matches) != 2 {
		t.Fatalf("both conflicting rules should be recorded as matches, got %d", len(res.Matches))
	}
	t.Logf("conflict matches: %+v -> guard maps to RULES_DISAGREE (default deny)", res.Matches)
}

func TestBuiltinDefaultsDenyUnmatched(t *testing.T) {
	ev := policy.NewEvaluator(policy.BuiltinPolicy())
	meta := policy.ImageMeta{APIVersion: "guard.image/v1", Repository: "gcr.io/x", Digest: "sha256:bb", DigestAlg: "sha256"}
	res := ev.Evaluate(meta)
	if res.Winner != nil || res.Allow {
		t.Fatalf("unmatched image must not be allowed by builtin policy")
	}
}

func TestValidateDigestPrefix(t *testing.T) {
	err := policy.Validate(policy.ImageMeta{
		APIVersion: "guard.image/v1", Repository: "r", Digest: "sha256:abc", DigestAlg: "sha512",
	})
	if err == nil {
		t.Fatalf("digest prefix mismatch must fail validation")
	}
}
