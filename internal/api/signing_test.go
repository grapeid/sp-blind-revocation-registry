package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"
	"github.com/grapeid/sp-blind-revocation-registry/internal/signer"
	"github.com/grapeid/sp-blind-revocation-registry/internal/store"
)

func signedRegistry(t *testing.T) http.Handler {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	id, err := signer.LoadOrCreate(filepath.Join(dir, "id"))
	if err != nil {
		t.Fatal(err)
	}
	return New(st, id).Router()
}

func send(t *testing.T, h http.Handler, path string, body any) int {
	t.Helper()
	raw, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw)))
	return w.Code
}

func signOneForm(t *testing.T, priv ed25519.PrivateKey, fields map[string]any) string {
	t.Helper()
	body, err := relayproto.CanonicalBody(fields)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, body))
}

// An issuer's requests are checked over the one signing form (the Identity
// Agent's ADR-049), with the sequence number a decimal string and the registry
// prefix from the path signed too.
func TestAnIssuerSignsInTheOneForm(t *testing.T) {
	h := signedRegistry(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	enrol := map[string]any{"registry_prefix": "EREG", "issuer_aid": "EISSUER", "issuer_public_key_b64": pubB64}
	enrol["signature"] = signOneForm(t, priv, enrol)
	if c := send(t, h, "/registry/enroll", enrol); c != http.StatusOK {
		t.Fatalf("a correctly signed enrolment gave %d", c)
	}
	event := map[string]any{"blinded_id": "b1", "event_type": "rev", "sequence_number": "3"}
	event["signature"] = signOneForm(t, priv, map[string]any{"registry_prefix": "EREG", "blinded_id": "b1", "event_type": "rev", "sequence_number": "3"})
	if c := send(t, h, "/registry/EREG/event", event); c != http.StatusOK {
		t.Fatalf("a correctly signed event gave %d", c)
	}
	// The same event signed for another registry is not accepted here.
	other := map[string]any{"blinded_id": "b2", "event_type": "rev", "sequence_number": "4"}
	other["signature"] = signOneForm(t, priv, map[string]any{"registry_prefix": "EOTHER", "blinded_id": "b2", "event_type": "rev", "sequence_number": "4"})
	if c := send(t, h, "/registry/EREG/event", other); c != http.StatusUnauthorized {
		t.Fatalf("an event signed for another registry gave %d", c)
	}
}

// A key of the wrong length is refused. It used to return no error from the
// signature check, which read as verified.
func TestAnIssuerKeyOfTheWrongLengthIsRefused(t *testing.T) {
	h := signedRegistry(t)
	short := base64.StdEncoding.EncodeToString(make([]byte, 31))
	enrol := map[string]any{"registry_prefix": "EREG", "issuer_aid": "EISSUER", "issuer_public_key_b64": short, "signature": "AAAA"}
	if c := send(t, h, "/registry/enroll", enrol); c != http.StatusUnauthorized {
		t.Fatalf("a 31-byte key with a junk signature enrolled: %d", c)
	}
}

// The form does not escape HTML characters, where Go's default JSON writer
// does, so a value containing them shows which form the registry checks.
func TestAnEnrolmentWithHTMLCharactersVerifies(t *testing.T) {
	h := signedRegistry(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	enrol := map[string]any{"registry_prefix": "a<b>&c", "issuer_aid": "EISSUER",
		"issuer_public_key_b64": base64.StdEncoding.EncodeToString(pub)}
	enrol["signature"] = signOneForm(t, priv, enrol)
	if c := send(t, h, "/registry/enroll", enrol); c != http.StatusOK {
		t.Fatalf("an enrolment signed in the one form gave %d", c)
	}
}
