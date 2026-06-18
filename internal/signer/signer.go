package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Identity is the BRR service KERI AID used to sign proofs and anchor records.
type Identity struct {
	AID        string
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

func LoadOrCreate(dataDir string) (*Identity, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(dataDir, "brr_identity.json")
	if b, err := os.ReadFile(path); err == nil {
		var raw struct {
			AID           string `json:"aid"`
			PublicKeyB64  string `json:"public_key_b64"`
			PrivateSeedB64 string `json:"private_seed_b64"`
		}
		if err := json.Unmarshal(b, &raw); err != nil {
			return nil, err
		}
		pub, _ := base64.StdEncoding.DecodeString(raw.PublicKeyB64)
		seed, _ := base64.StdEncoding.DecodeString(raw.PrivateSeedB64)
		if len(pub) == ed25519.PublicKeySize && len(seed) == ed25519.SeedSize {
			return &Identity{
				AID: raw.AID, PublicKey: ed25519.PublicKey(pub),
				PrivateKey: ed25519.NewKeyFromSeed(seed),
			}, nil
		}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	aid := "E" + base64.RawURLEncoding.EncodeToString(pub)[:43]
	id := &Identity{AID: aid, PublicKey: pub, PrivateKey: priv}
	out, _ := json.MarshalIndent(map[string]string{
		"aid": aid,
		"public_key_b64": base64.StdEncoding.EncodeToString(pub),
		"private_seed_b64": base64.StdEncoding.EncodeToString(priv.Seed()),
	}, "", "  ")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return nil, err
	}
	return id, nil
}

func (id *Identity) Sign(payload []byte) string {
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(id.PrivateKey, payload))
}

func Verify(pub ed25519.PublicKey, payload []byte, sigB64 string) error {
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, payload, sig) {
		return fmt.Errorf("invalid signature")
	}
	return nil
}