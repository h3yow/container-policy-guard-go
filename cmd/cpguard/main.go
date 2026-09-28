// Command cpguard 用本地清单、策略文件与信任公钥库，对镜像引用执行一次
// 准入判定并打印可解释结论。它不访问网络，全部输入来自本地文件。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/h3yow/container-policy-guard-go"
)

func main() {
	var (
		policyPath   = flag.String("policy", "", "外部策略文件路径 (YAML/JSON)，为空则只用内置规则")
		manifestPath = flag.String("manifest", "testdata/manifest.yaml", "本地镜像清单文件路径")
		keyringPath  = flag.String("keyring", "testdata/keyring.yaml", "信任公钥库文件路径")
		ref          = flag.String("ref", "", "要判定的镜像引用，例如 registry.example.com/base:1.0")
		reload       = flag.Bool("reload", false, "仅演示：装配成功后重新加载一次策略")
	)
	flag.Parse()

	if *ref == "" {
		fmt.Fprintln(os.Stderr, "error: --ref is required")
		flag.Usage()
		os.Exit(2)
	}

	ctx := context.Background()
	g, err := guard.New(ctx, guard.Config{
		PolicyPath:   *policyPath,
		ManifestPath: *manifestPath,
		KeyringPath:  *keyringPath,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "装配失败（默认拒绝，不提供判定服务）: %v\n", err)
		os.Exit(3)
	}
	if *reload {
		if err := g.Reload(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "策略重载失败，保留旧版本 %s: %v\n", g.PolicyVersion(), err)
		}
	}
	// 本 CLI 不带密码学签名输入（签名需由分发侧随镜像提供），因此签名相关
	// 规则会给出 SIGNATURE_MISSING 的可解释拒绝。
	d, err := g.EvaluateRef(ctx, *ref, nil, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "评估内部错误: %v\n", err)
		os.Exit(4)
	}
	fmt.Println(d.Explain())
	if d.Allowed {
		os.Exit(0)
	}
	os.Exit(1)
}
