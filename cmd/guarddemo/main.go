package main

import (
	"context"
	"flag"
	"fmt"
	"sync"

	"github.com/h3yow/container-policy-guard-go/guard"
	"github.com/h3yow/container-policy-guard-go/manifest"
	"github.com/h3yow/container-policy-guard-go/policy"
	"github.com/h3yow/container-policy-guard-go/signature"
)

func main() {
	manifestDir := flag.String("manifests", "testdata/manifests", "directory of local manifests")
	policyFile := flag.String("policy", "testdata/policies/extra.json", "external policy file")
	keyFile := flag.String("keys", "testdata/keys.json", "keyring file")
	flag.Parse()

	ctx := context.Background()

	kr, err := signature.LoadKeyringFile(*keyFile)
	if err != nil {
		fmt.Println("load keyring failed:", err)
		return
	}

	images := []string{
		"registry.local/app/web:v1",
		"registry.local/app/web:bad",
		"registry.local/app/api:v1",
		"registry.local/app/legacy:v1",
	}

	// 第一次加载：内置规则 + 外部文件。
	bundle, err := loadPolicy(ctx, *policyFile)
	if err != nil {
		fmt.Println("load policy failed (fail-closed):", err)
		return
	}

	ev := guard.NewEvaluator(bundle, manifest.NewDirSource(*manifestDir), signature.NewVerifier(kr))

	run := func(tag string) {
		var wg sync.WaitGroup
		for _, img := range images {
			// 每个镜像并发评估两次，验证结论一致与缓存行为。
			for r := 0; r < 2; r++ {
				wg.Add(1)
				go func(id string) {
					defer wg.Done()
					d := ev.Evaluate(ctx, id)
					word := "ALLOW"
					if !d.Allowed {
						word = "DENY"
					}
					fmt.Printf("[%s] %-32s %-5s reason=%s rule=%s detail=%s\n",
						tag, id, word, d.Reason, d.MatchedRule, d.Detail)
				}(img)
			}
		}
		wg.Wait()
	}

	fmt.Println("==== before policy update ====")
	run("v1")

	// 模拟策略更新：换一个外部文件（版本号更高）。
	bundle2, err := loadPolicy(ctx, "testdata/policies/extra-v2.json")
	if err != nil {
		fmt.Println("reload policy failed:", err)
		return
	}
	ev.UpdatePolicy(bundle2)

	fmt.Println("==== after policy update ====")
	run("v2")
}

func loadPolicy(ctx context.Context, file string) (*policy.Bundle, error) {
	builtin := &policy.Policy{
		Version: 1,
		Rules: []policy.Rule{
			{Name: "builtin-default-deny", Source: "builtin", Priority: 0, Action: policy.ActionDeny,
				Reason: "no explicit allow rule"},
			{Name: "builtin-signed-images", Source: "builtin", Priority: 100, Action: policy.ActionAllow,
				ImageRefs: []string{"registry.local/app/*"}, Requires: []string{"signature", "attestation:sbom"}},
		},
	}
	return policy.LoadAll(ctx, []policy.Source{
		&policy.BuiltinSource{Ver: 1, Pol: builtin},
		&policy.FileSource{Path: file},
	})
}
