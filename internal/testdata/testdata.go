// Package testdata 提供单测共用的密钥、签名与策略/清单/公钥库文件生成工具。
package testdata

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// KeyPair 是一把测试用密钥（公钥 PEM + 私钥）。
type KeyPair struct {
	ID        string
	PEM       string
	Private   ed25519.PrivateKey
	Public    ed25519.PublicKey
	Algorithm string
}

// NewEd25519Key 生成一把 ed25519 测试密钥。
func NewEd25519Key(id string) (*KeyPair, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return &KeyPair{ID: id, PEM: pemStr, Private: priv, Public: pub, Algorithm: "Ed25519"}, nil
}

// MustRSAKey 生成一把 2048 位 RSA 测试密钥，供摘要算法差异测试使用。
func MustRSAKey() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}

// RSAPublicPEM 导出 RSA 公钥 PEM。
func RSAPublicPEM(k *rsa.PrivateKey) string {
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// SignEd25519 使用与 guard 相同的签名载荷格式生成签名。
func SignEd25519(kp *KeyPair, alg, digest string) []byte {
	msg := []byte("image|" + alg + "|" + digest)
	return ed25519.Sign(kp.Private, msg)
}

// SignEd25519Attest 生成证明签名。
func SignEd25519Attest(kp *KeyPair, alg, digest, typ string, payload []byte) []byte {
	msg := []byte("attest|" + alg + "|" + digest + "|" + typ + "|" + string(payload))
	return ed25519.Sign(kp.Private, msg)
}

// B64 返回 base64 编码。
func B64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// WriteFile 写入测试夹具文件并返回绝对路径。
func WriteFile(dir, name, content string) (string, error) {
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		return "", err
	}
	return p, nil
}

// Must 失败时 panic（仅用于测试夹具构造）。
func Must(p string, err error) string {
	if err != nil {
		panic(fmt.Sprintf("testdata: %v", err))
	}
	return p
}

// IsNotExist 判断文件不存在。
func IsNotExist(err error) bool { return errors.Is(err, os.ErrNotExist) }
