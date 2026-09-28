package signature

import (
	"bytes"
	"encoding/json"
	"os"
	"time"
)

type keyFileEntry struct {
	ID        string    `json:"id"`
	State     KeyState  `json:"state"`
	Alg       string    `json:"alg"`
	RotatedBy string    `json:"rotatedBy,omitempty"`
	NotBefore time.Time `json:"notBefore,omitempty"`
	NotAfter  time.Time `json:"notAfter,omitempty"`
}

// LoadKeyringFile 从 JSON 数组加载公钥环。
func LoadKeyringFile(path string) (*Keyring, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var entries []keyFileEntry
	if err := dec.Decode(&entries); err != nil {
		return nil, err
	}
	kr := NewKeyring()
	for _, e := range entries {
		kr.Add(PublicKey{
			ID:        e.ID,
			State:     e.State,
			Alg:       e.Alg,
			RotatedBy: e.RotatedBy,
			NotBefore: e.NotBefore,
			NotAfter:  e.NotAfter,
		})
	}
	return kr, nil
}
