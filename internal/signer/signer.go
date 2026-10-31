package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"

	keri "github.com/grapeid/keri-go"
)

// Identity is the BRR service KERI AID used to sign proofs and anchor records.
//
// The AID is non-transferable (code B): it IS the verifying key, so a verifier
// holding a signed proof needs nothing else to check it. It is derived from
// the key on every load, never read from the file, so the file cannot name a
// key it does not hold. An identity file written before this kept a made-up
// identifier ("E" and the key's base64url, which claims to be a Blake3 digest
// and is not one); its key is unchanged and it now reports the identifier that
// key really has.
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
			PrivateSeedB64 string `json:"private_seed_b64"`
		}
		if err := json.Unmarshal(b, &raw); err != nil {
			return nil, err
		}
		seed, _ := base64.StdEncoding.DecodeString(raw.PrivateSeedB64)
		if len(seed) == ed25519.SeedSize {
			return fromKey(ed25519.NewKeyFromSeed(seed))
		}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	id, err := fromKey(priv)
	if err != nil {
		return nil, err
	}
	out, _ := json.MarshalIndent(map[string]string{
		"aid":              id.AID,
		"public_key_b64":   base64.StdEncoding.EncodeToString(id.PublicKey),
		"private_seed_b64": base64.StdEncoding.EncodeToString(priv.Seed()),
	}, "", "  ")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return nil, err
	}
	return id, nil
}

func fromKey(priv ed25519.PrivateKey) (*Identity, error) {
	pub := priv.Public().(ed25519.PublicKey)
	aid, err := keri.MatterQB64(keri.CodeEd25519N, pub)
	if err != nil {
		return nil, err
	}
	return &Identity{AID: aid, PublicKey: pub, PrivateKey: priv}, nil
}

func (id *Identity) Sign(payload []byte) string {
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(id.PrivateKey, payload))
}
