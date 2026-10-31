package signer

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/grapeid/sp-common/decode"
)

// The service's identifier is its verifying key as a non-transferable
// identifier. It used to be "E" and the key's base64url, which claims to be a
// Blake3 digest, is not one, and no KERI implementation reads as a key.
func TestTheIdentifierIsTheVerifyingKey(t *testing.T) {
	id, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pub, code, err := decode.Ed25519KeyQB64(id.AID)
	if err != nil || code != decode.CodeEd25519N {
		t.Fatalf("identifier %q is not a non-transferable Ed25519 identifier: %v", id.AID, err)
	}
	if !pub.Equal(id.PublicKey) {
		t.Fatal("the identifier names a different key from the one that signs")
	}
}

// An identity file holding the old made-up identifier keeps its key and
// reports the identifier that key really has. The file is never trusted to
// name the key.
func TestAnOldIdentityFileKeepsItsKeyAndReportsItsRealIdentifier(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(nil)
	old, _ := json.Marshal(map[string]string{
		"aid":              "E" + base64.RawURLEncoding.EncodeToString(pub)[:43],
		"public_key_b64":   base64.StdEncoding.EncodeToString(pub),
		"private_seed_b64": base64.StdEncoding.EncodeToString(priv.Seed()),
	})
	if err := os.WriteFile(filepath.Join(dir, "brr_identity.json"), old, 0o600); err != nil {
		t.Fatal(err)
	}
	id, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !id.PublicKey.Equal(pub) {
		t.Fatal("the stored key was not kept")
	}
	if got, _, err := decode.Ed25519KeyQB64(id.AID); err != nil || !got.Equal(pub) {
		t.Fatalf("reported %q, not the key's identifier", id.AID)
	}
}
